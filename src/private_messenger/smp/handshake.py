"""SMP v11-v20 handshake and v11 transport forward-secret block chains."""

import hmac
import struct

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from private_messenger.crypto import smp_box

from .authentication import spki, validate_chain, verify_router_key
from .framing import BLOCK_SIZE, ProtocolError, Reader, pad, short, unpad


def hkdf(salt: bytes, secret: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA512(), length=length, salt=salt, info=info).derive(secret)


class BlockChain:
    def __init__(self, chain: bytes):
        self.chain = chain

    def step(self) -> tuple[bytes, bytes]:
        result = hkdf(b"", self.chain, b"SimpleXSbChain", 88)
        self.chain = result[:32]
        return result[32:64], result[64:]

    def encrypt(self, body: bytes) -> bytes:
        key, nonce = self.step()
        return smp_box.encrypt(key, nonce, pad(body, BLOCK_SIZE - 16))

    def decrypt(self, block: bytes) -> bytes:
        if len(block) != BLOCK_SIZE:
            raise ProtocolError("incorrect encrypted block size")
        key, nonce = self.step()
        return unpad(smp_box.decrypt(key, nonce, block))


def negotiate(low: int, high: int, minimum: int = 11, maximum: int = 20) -> int:
    if not 11 <= minimum <= maximum <= 20:
        raise ValueError("client supports only v11-v20; no encryption downgrade")
    if low > high or max(low, minimum) > min(high, maximum):
        raise ProtocolError("no compatible secure SMP version")
    return min(high, maximum)


def handshake(transport, fingerprint: bytes, minimum: int = 11, maximum: int = 20):
    r = Reader(unpad(transport.read_block()))
    low, high = r.word16(), r.word16()
    version = negotiate(low, high, minimum, maximum)
    session = r.short()
    if not hmac.compare_digest(session, transport.session):
        raise ProtocolError("SMP session does not match TLS Finished")
    count = r.byte()
    if count not in (2, 3, 4):
        raise ProtocolError("invalid handshake certificate count")
    chain = [x509.load_der_x509_certificate(r.large()) for _ in range(count)]
    validate_chain(chain, fingerprint)
    if chain != transport.chain:
        raise ProtocolError("handshake certificate chain differs from TLS chain")
    server_key = verify_router_key(r.large(), chain[0])
    # Future handshake extensions inside the padded length are explicitly ignored.
    private = x25519.X25519PrivateKey.generate()
    secret = private.exchange(server_key)
    hello = struct.pack("!H", version) + short(fingerprint) + short(spki(private.public_key()))
    if version >= 14:
        hello += b"F"
    if version >= 16:
        hello += b"0"
    transport.write_block(pad(hello))
    keys = hkdf(session, secret, b"SimpleXSbChainInit", 64)
    # Reference server uses first key for sending; client directions are reversed.
    return version, BlockChain(keys[32:]), BlockChain(keys[:32])
