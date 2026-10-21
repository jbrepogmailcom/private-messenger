"""SMP Ed25519 command signatures and pinned X.509 router authentication."""

import hmac
from datetime import UTC, datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed448, ed25519, x25519
from OpenSSL import crypto
from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode
from pyasn1.error import PyAsn1Error

from .framing import ProtocolError, short


def spki(key) -> bytes:
    return key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def validate_chain(chain: list[x509.Certificate], fingerprint: bytes) -> None:
    if len(chain) not in (2, 3, 4):
        raise ProtocolError("router must supply 2, 3 or 4 certificates")
    # Current reference wire implementation pins index 1 in leaf-first order.
    # It hashes the complete DER certificate, NOT its SPKI. See PROTOCOL_NOTES.md.
    if not hmac.compare_digest(chain[1].fingerprint(hashes.SHA256()), fingerprint):
        raise ProtocolError("router certificate identity mismatch")
    now = datetime.now(UTC)
    for cert in chain:
        if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
            raise ProtocolError("router certificate outside validity period")
        if not isinstance(cert.public_key(), (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            raise ProtocolError("only EdDSA router certificates supported")
    store = crypto.X509Store()
    store.add_cert(crypto.X509.from_cryptography(chain[-1]))
    try:
        crypto.X509StoreContext(
            store,
            crypto.X509.from_cryptography(chain[0]),
            [crypto.X509.from_cryptography(c) for c in chain[1:-1]],
        ).verify_certificate()
        # OpenSSL normally treats the explicitly trusted root as an anchor;
        # additionally verify its self-signature and exact supplied path.
        for child, parent in zip(chain, chain[1:] + [chain[-1]], strict=True):
            if child.issuer != parent.subject:
                raise ProtocolError("certificate issuer mismatch")
            parent.public_key().verify(child.signature, child.tbs_certificate_bytes)
    except (crypto.X509StoreContextError, InvalidSignature) as exc:
        raise ProtocolError("invalid router certificate chain") from exc


def verify_router_key(signed_der: bytes, leaf: x509.Certificate) -> x25519.X25519PublicKey:
    try:
        obj, trailing = decode(signed_der)
        if trailing or encode(obj) != signed_der or len(obj) != 3:
            raise ValueError("noncanonical signed key")
        # SignedExact SubjectPublicKeyInfo, AlgorithmIdentifier(Ed25519), BIT STRING.
        expected = (
            "1.3.101.112"
            if isinstance(leaf.public_key(), ed25519.Ed25519PublicKey)
            else "1.3.101.113"
        )
        if len(obj[1]) != 1 or str(obj[1][0]) != expected:
            raise ValueError("unsupported router signature")
        # Haskell SignedExact wraps the SPKI in its own signed SEQUENCE.
        signed_bytes = encode(obj[0])
        if len(obj[0]) != 1:
            raise ValueError("invalid signed SPKI wrapper")
        key_der = encode(obj[0][0])
        leaf.public_key().verify(obj[2].asOctets(), signed_bytes)
        key = serialization.load_der_public_key(key_der)
        if not isinstance(key, x25519.X25519PublicKey):
            raise ValueError("expected X25519 session key")
        return key
    except (ValueError, TypeError, IndexError, InvalidSignature, PyAsn1Error) as exc:
        raise ProtocolError("invalid signed router session key") from exc


def authorize(
    key: ed25519.Ed25519PrivateKey | None,
    session: bytes,
    correlation: bytes,
    entity: bytes,
    command: bytes,
    version: int,
) -> bytes:
    body = short(correlation) + short(entity) + command
    if key is None:
        return b"\0" + body
    signature = key.sign(short(session) + body)
    return short(signature) + (b"0" if version >= 16 else b"") + body
