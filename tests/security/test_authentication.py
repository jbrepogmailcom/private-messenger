from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.x509.oid import NameOID
from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode
from pyasn1.type import univ

from private_messenger.smp.authentication import (
    authorize,
    spki,
    validate_chain,
    verify_router_key,
)
from private_messenger.smp.framing import ProtocolError, Reader, large, pad, short
from private_messenger.smp.handshake import handshake


def certificates():
    now = datetime.now(UTC)
    root_key = ed25519.Ed25519PrivateKey.generate()
    leaf_key = ed25519.Ed25519PrivateKey.generate()
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])

    def cert(name, issuer, key, signing_key, ca):
        return (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
            .sign(signing_key, algorithm=None)
        )

    root = cert(root_name, root_name, root_key, root_key, True)
    leaf = cert(leaf_name, root_name, leaf_key, root_key, False)
    return [leaf, root], leaf_key


def signed_key(private, public):
    wrapper = univ.SequenceOf()
    wrapper.append(decode(spki(public))[0])
    algorithm = univ.SequenceOf()
    algorithm.append(univ.ObjectIdentifier("1.3.101.112"))
    outer = univ.Sequence()
    outer.setComponentByPosition(0, wrapper)
    outer.setComponentByPosition(1, algorithm)
    outer.setComponentByPosition(2, univ.BitString.fromOctetString(private.sign(encode(wrapper))))
    return encode(outer)


def test_certificate_pinning_and_chain():
    chain, _ = certificates()
    fingerprint = chain[1].fingerprint(hashes.SHA256())
    validate_chain(chain, fingerprint)
    for bad in ([], chain[:1], chain * 3):
        with pytest.raises(ProtocolError):
            validate_chain(bad, fingerprint)
    with pytest.raises(ProtocolError):
        validate_chain(chain, bytes(32))
    other_chain, _ = certificates()
    with pytest.raises(ProtocolError):
        validate_chain([other_chain[0], chain[1]], fingerprint)


def test_signed_router_key():
    chain, key = certificates()
    public = x25519.X25519PrivateKey.generate().public_key()
    signed = signed_key(key, public)
    assert spki(verify_router_key(signed, chain[0])) == spki(public)
    with pytest.raises(ProtocolError):
        verify_router_key(signed[:-1] + bytes([signed[-1] ^ 1]), chain[0])
    with pytest.raises(ProtocolError):
        verify_router_key(signed + b"x", chain[0])
    with pytest.raises(ProtocolError):
        verify_router_key(b"garbage", chain[0])


def test_command_signature_binds_session_entity_and_command():
    key = ed25519.Ed25519PrivateKey.generate()
    session, corr, entity = b"tls finished", bytes(24), b"recipient id"
    wire = Reader(authorize(key, session, corr, entity, b"GET", 20))
    signature = wire.short()
    assert wire.take(1) == b"0"
    body = wire.rest()
    key.public_key().verify(signature, short(session) + body)
    for modified in (short(b"other session") + body, short(session) + body[:-3] + b"SUB"):
        with pytest.raises(InvalidSignature):
            key.public_key().verify(signature, modified)


def test_handshake_channel_binding_and_signed_key():
    from cryptography.hazmat.primitives.serialization import Encoding

    chain, signing = certificates()
    public = x25519.X25519PrivateKey.generate().public_key()
    hello = (
        b"\0\x0b\0\x14"
        + short(b"TLS Finished")
        + b"\2"
        + b"".join(large(c.public_bytes(Encoding.DER)) for c in chain)
        + large(signed_key(signing, public))
    )

    class SyntheticTransport:
        session = b"TLS Finished"

        def __init__(self):
            self.chain = chain
            self.sent = []

        def read_block(self):
            return pad(hello)

        def write_block(self, block):
            self.sent.append(block)

    transport = SyntheticTransport()
    assert handshake(transport, chain[1].fingerprint(hashes.SHA256()))[0] == 20
    assert len(transport.sent[0]) == 16384
    transport.session = b"wrong TLS session"
    with pytest.raises(ProtocolError):
        handshake(transport, chain[1].fingerprint(hashes.SHA256()))
