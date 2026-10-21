"""TLS 1.3 transport, strict application authentication before any SMP command."""

import select
import time

from OpenSSL import SSL

from private_messenger.config import Server
from private_messenger.networking.connection import Network

from .authentication import validate_chain
from .framing import BLOCK_SIZE, ProtocolError


class TLSTransport:
    def __init__(self, server: Server, network: Network):
        self.timeout = network.timeout
        ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
        ctx.set_min_proto_version(SSL.TLS1_3_VERSION)
        ctx.set_max_proto_version(SSL.TLS1_3_VERSION)
        ctx.set_tls13_ciphersuites(b"TLS_CHACHA20_POLY1305_SHA256")
        ctx.set_session_cache_mode(SSL.SESS_CACHE_OFF)
        ctx.set_options(SSL.OP_NO_TICKET)
        ctx.set_alpn_protos([b"smp/1"])
        # Public PKI does not authenticate SMP routers. Pin and validate the full
        # self-signed chain immediately after TLS, before reading/sending SMP data.
        ctx.set_verify(SSL.VERIFY_NONE, None)
        self.socket = network.connect(server)
        self.socket.setblocking(False)
        self.tls = SSL.Connection(ctx, self.socket)
        self.tls.set_connect_state()
        self.tls.set_tlsext_host_name(server.host.encode("idna"))
        try:
            self._retry(self.tls.do_handshake)
            if (
                self.tls.get_protocol_version_name() != "TLSv1.3"
                or self.tls.get_cipher_name() != "TLS_CHACHA20_POLY1305_SHA256"
                or self.tls.get_group_name() != "x25519"
            ):
                raise ProtocolError("TLS algorithm requirements not satisfied")
            if self.tls.get_alpn_proto_negotiated() != b"smp/1":
                raise ProtocolError("smp/1 ALPN required; legacy fallback forbidden")
            self.chain = self.tls.get_peer_cert_chain(as_cryptography=True) or []
            validate_chain(self.chain, server.fingerprint)
            self.session = self.tls.get_finished()
            if not self.session:
                raise ProtocolError("missing TLS Finished channel binding")
        except BaseException:
            self.close()
            raise

    def _retry(self, operation, deadline=None):
        if deadline is None:
            deadline = time.monotonic() + self.timeout
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError("SMP TLS operation timed out")
            try:
                return operation()
            except (SSL.WantReadError, SSL.WantWriteError) as exc:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("SMP TLS operation timed out") from exc
                read = isinstance(exc, SSL.WantReadError)
                ready = select.select(
                    [self.socket] if read else [], [] if read else [self.socket], [], remaining
                )
                if not ready[0] and not ready[1]:
                    raise TimeoutError("SMP TLS operation timed out") from exc

    def read_block(self) -> bytes:
        deadline = time.monotonic() + self.timeout
        result = bytearray()
        while len(result) < BLOCK_SIZE:
            data = self._retry(lambda: self.tls.recv(BLOCK_SIZE - len(result)), deadline)
            if not data:
                raise EOFError("router closed transport")
            result.extend(data)
        return bytes(result)

    def write_block(self, data: bytes) -> None:
        if len(data) != BLOCK_SIZE:
            raise ProtocolError("transport block must be exactly 16384 bytes")
        offset = 0
        deadline = time.monotonic() + self.timeout
        while offset < len(data):
            written = self._retry(lambda position=offset: self.tls.send(data[position:]), deadline)
            if written <= 0:
                raise EOFError("router closed transport")
            offset += written

    def close(self) -> None:
        self.socket.close()
