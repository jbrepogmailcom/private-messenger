"""Extension boundary only. No fictional mixnet endpoints or anonymity claim."""

import socket
from typing import Protocol

from private_messenger.config import Server


class StreamAdapter(Protocol):
    """Adapters must provide ordered, reliable streams for SMP TLS handshakes.

    A future deployed mixnet adapter needs independently verified deployment,
    stream semantics, MTU/latency handling, failure policy and privacy analysis.
    No MIXNET implementation is registered until those requirements are met.
    """

    timeout: float

    def connect(self, server: Server) -> socket.socket: ...
