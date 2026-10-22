"""Bounded application framing. No SMP command or field is changed."""

from private_messenger.config import b64, unb64

MAGIC = b"PM2\x01"
HEADER_SIZE = 37


def pack(sender: str, message_type: int, ciphertext: bytes) -> bytes:
    address = unb64(sender)
    if len(address) != 32 or message_type not in (2, 3):
        raise ValueError("invalid encrypted application header")
    result = MAGIC + bytes([message_type]) + address + ciphertext
    if not HEADER_SIZE < len(result) <= 16048:
        raise ValueError("encrypted message exceeds SMP payload limit")
    return result


def unpack(packet: bytes) -> tuple[str, int, bytes]:
    if not HEADER_SIZE < len(packet) <= 16048 or packet[:4] != MAGIC or packet[4] not in (2, 3):
        raise ValueError("invalid encrypted application packet")
    return b64(packet[5:HEADER_SIZE]), packet[4], packet[HEADER_SIZE:]
