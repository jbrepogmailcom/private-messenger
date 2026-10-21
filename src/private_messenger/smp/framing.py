"""SMP fixed-size blocks and length-prefixed binary values (network byte order)."""

import struct
from dataclasses import dataclass

BLOCK_SIZE = 16384


class ProtocolError(ValueError):
    """Malformed, unsupported or unauthenticated protocol data."""


def short(data: bytes) -> bytes:
    if len(data) > 255:
        raise ProtocolError("short string exceeds 255 bytes")
    return bytes([len(data)]) + data


def large(data: bytes) -> bytes:
    if len(data) > 65535:
        raise ProtocolError("large string exceeds 65535 bytes")
    return struct.pack("!H", len(data)) + data


def pad(data: bytes, size: int = BLOCK_SIZE) -> bytes:
    if len(data) > size - 2:
        raise ProtocolError("block too large")
    return large(data) + b"#" * (size - len(data) - 2)


def unpad(block: bytes) -> bytes:
    r = Reader(block)
    data = r.large()
    if r.rest() != b"#" * (len(block) - len(data) - 2):
        raise ProtocolError("invalid block padding")
    return data


@dataclass
class Reader:
    data: bytes
    offset: int = 0

    def take(self, count: int) -> bytes:
        if count < 0 or count > len(self.data) - self.offset:
            raise ProtocolError("truncated value")
        result = self.data[self.offset : self.offset + count]
        self.offset += count
        return result

    def byte(self) -> int:
        return self.take(1)[0]

    def word16(self) -> int:
        return struct.unpack("!H", self.take(2))[0]

    def short(self) -> bytes:
        return self.take(self.byte())

    def large(self) -> bytes:
        return self.take(self.word16())

    def rest(self) -> bytes:
        return self.take(len(self.data) - self.offset)

    def end(self) -> None:
        if self.offset != len(self.data):
            raise ProtocolError("unexpected trailing data")


def batch(transmissions: list[bytes]) -> bytes:
    if not 1 <= len(transmissions) <= 255:
        raise ProtocolError("invalid batch count")
    return bytes([len(transmissions)]) + b"".join(large(t) for t in transmissions)


def unbatch(data: bytes) -> list[bytes]:
    r = Reader(data)
    count = r.byte()
    if not count:
        raise ProtocolError("empty batch")
    result = [r.large() for _ in range(count)]
    r.end()
    return result
