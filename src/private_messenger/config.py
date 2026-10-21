"""Explicit pinned router configuration. There is no discovery or trust on first use."""

import base64
from dataclasses import dataclass
from urllib.parse import urlsplit


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def unb64(value: str) -> bytes:
    return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)


@dataclass(frozen=True)
class Server:
    host: str
    port: int
    fingerprint: bytes

    @classmethod
    def parse(cls, uri: str) -> "Server":
        p = urlsplit(uri)
        if p.scheme != "smp" or not p.username or not p.hostname or p.password:
            raise ValueError("expected smp://BASE64URL_CERT_SHA256@HOST[:PORT]")
        if p.path not in ("", "/") or p.query or p.fragment or "," in p.hostname:
            raise ValueError("configure one router hostname per entry")
        fp = unb64(p.username)
        if len(fp) != 32:
            raise ValueError("router identity must contain 32 bytes")
        port = p.port or 5223
        if not 1 <= port <= 65535:
            raise ValueError("invalid router port")
        return cls(p.hostname, port, fp)

    @property
    def uri(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"smp://{b64(self.fingerprint)}@{host}:{self.port}"
