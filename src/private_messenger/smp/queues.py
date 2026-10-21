"""Separate recipient and sender queue credentials. Never publish recipient secrets."""

from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

from private_messenger.config import b64, unb64

from .authentication import spki
from .framing import ProtocolError, Reader


@dataclass(repr=False)
class ReceiveQueue:
    recipient_id: bytes
    sender_id: bytes
    auth_private: ed25519.Ed25519PrivateKey = field(repr=False)
    dh_private: x25519.X25519PrivateKey = field(repr=False)
    server_dh: x25519.X25519PublicKey
    sender_can_secure: bool

    def export(self) -> dict:
        return {
            "recipient_id": b64(self.recipient_id),
            "sender_id": b64(self.sender_id),
            "auth_private": b64(self.auth_private.private_bytes_raw()),
            "dh_private": b64(self.dh_private.private_bytes_raw()),
            "server_dh": b64(spki(self.server_dh)),
            "sender_can_secure": self.sender_can_secure,
        }

    @classmethod
    def restore(cls, data: dict) -> "ReceiveQueue":
        from cryptography.hazmat.primitives.serialization import load_der_public_key

        server_dh = load_der_public_key(unb64(data["server_dh"]))
        if not isinstance(server_dh, x25519.X25519PublicKey):
            raise ProtocolError("invalid saved queue DH key")
        return cls(
            unb64(data["recipient_id"]),
            unb64(data["sender_id"]),
            ed25519.Ed25519PrivateKey.from_private_bytes(unb64(data["auth_private"])),
            x25519.X25519PrivateKey.from_private_bytes(unb64(data["dh_private"])),
            server_dh,
            bool(data["sender_can_secure"]),
        )


@dataclass(frozen=True)
class Delivery:
    message_id: bytes
    timestamp: int
    notification: bool
    ciphertext: bytes


def optional(r: Reader, parser):
    tag = r.take(1)
    if tag == b"0":
        return None
    if tag != b"1":
        raise ProtocolError("invalid optional field")
    return parser()


def parse_ids(body: bytes, version: int, auth, dh) -> ReceiveQueue:
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    if not body.startswith(b"IDS "):
        raise ProtocolError("expected queue IDs")
    r = Reader(body[4:])
    rid, sid = r.short(), r.short()
    if not 16 <= len(rid) <= 24 or not 16 <= len(sid) <= 24 or rid == sid:
        raise ProtocolError("invalid queue identifiers")
    server_dh = load_der_public_key(r.short())
    if not isinstance(server_dh, x25519.X25519PublicKey):
        raise ProtocolError("queue server key must be X25519")
    if version >= 15:
        mode = optional(r, lambda: r.take(1))
        if mode not in (None, b"M", b"C"):
            raise ProtocolError("invalid queue mode")
        secure = mode == b"M"
        optional(r, r.short)  # no link was requested
        if version >= 16:
            optional(r, r.short)  # no service was requested
        if version >= 17:
            optional(r, lambda: (r.short(), r.short()))
    else:
        flag = r.take(1)
        if flag not in (b"T", b"F"):
            raise ProtocolError("invalid sender security flag")
        secure = flag == b"T"
    r.end()
    return ReceiveQueue(rid, sid, auth, dh, server_dh, secure)
