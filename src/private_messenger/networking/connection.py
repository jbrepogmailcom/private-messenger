import ipaddress
import secrets
import socket
from dataclasses import dataclass

import socks

from private_messenger.config import Server


@dataclass(frozen=True)
class Network:
    mode: str = "DIRECT"
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 9050
    timeout: float = 20.0

    def __post_init__(self) -> None:
        if self.mode not in ("DIRECT", "TOR"):
            raise ValueError("MIXNET is BLOCKED: no verified compatible adapter")
        if self.timeout <= 0:
            raise ValueError("timeout must be positive")
        # A literal proxy address prevents even proxy-host DNS resolution in TOR mode.
        if self.mode == "TOR":
            ipaddress.ip_address(self.proxy_host)

    def connect(self, server: Server) -> socket.socket:
        if self.mode == "DIRECT":
            if server.host.endswith(".onion"):
                raise ValueError("onion routers require TOR mode")
            return socket.create_connection((server.host, server.port), self.timeout)
        family = (
            socket.AF_INET6
            if ipaddress.ip_address(self.proxy_host).version == 6
            else socket.AF_INET
        )
        sock = socks.socksocket(family)
        # Fresh credentials isolate every connection if Tor IsolateSOCKSAuth is enabled.
        sock.set_proxy(
            socks.SOCKS5,
            self.proxy_host,
            self.proxy_port,
            rdns=True,
            username=secrets.token_hex(16),
            password=secrets.token_hex(16),
        )
        sock.settimeout(self.timeout)
        try:
            sock.connect((server.host, server.port))
            return sock
        except BaseException:
            sock.close()
            raise
