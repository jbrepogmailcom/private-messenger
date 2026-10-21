"""Synchronous SMP client. One outstanding command per connection.

Unknown SEND results are surfaced; never automatically resend a possibly accepted
message. Application retries need an authenticated application message identifier.
"""

import secrets
import struct
import time
from collections import deque

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from OpenSSL import SSL

from private_messenger.config import Server
from private_messenger.crypto import smp_box
from private_messenger.networking.connection import Network

from .authentication import authorize, spki
from .framing import ProtocolError, Reader, batch, short, unbatch, unpad
from .handshake import handshake
from .queues import Delivery, ReceiveQueue, parse_ids
from .transport import TLSTransport


class RouterError(ProtocolError):
    def __init__(self, response: bytes):
        self.response = response
        super().__init__(repr(response))  # escape untrusted router control characters


class AmbiguousSendError(ConnectionError):
    """Connection failed after SEND started; server acceptance is unknown."""


class Client:
    def __init__(
        self, server: Server, network: Network | None = None, minimum: int = 11, maximum: int = 20
    ):
        self.server = server
        self.network = network or Network()
        self.minimum, self.maximum = minimum, maximum
        self.transport = None
        self.events = deque()
        self.responses = deque()
        self.modes = {}

    def connect(self) -> "Client":
        self.close()
        transport = TLSTransport(self.server, self.network)
        try:
            self.version, self.sending, self.receiving = handshake(
                transport, self.server.fingerprint, self.minimum, self.maximum
            )
        except BaseException:
            transport.close()
            raise
        self.transport = transport
        return self

    def close(self) -> None:
        if self.transport is not None:
            self.transport.close()
            self.transport = None
        self.events.clear()
        self.responses.clear()
        self.modes.clear()

    def reconnect(self, attempts: int = 3) -> "Client":
        """Bounded backoff, same pinned server and network; no command replay."""
        if not 1 <= attempts <= 5:
            raise ValueError("reconnect attempts must be 1..5")
        for attempt in range(attempts):
            try:
                return self.connect()
            except (OSError, EOFError, SSL.SysCallError, SSL.ZeroReturnError):
                if attempt + 1 == attempts:
                    raise
                time.sleep(min(0.25 * 2**attempt, 2) + secrets.randbelow(100) / 1000)
        raise AssertionError("unreachable")

    def __enter__(self) -> "Client":
        return self.connect()

    def __exit__(self, *_):
        self.close()

    def _read(self) -> None:
        if self.transport is None:
            raise ConnectionError("not connected")
        for transmission in unbatch(self.receiving.decrypt(self.transport.read_block())):
            r = Reader(transmission)
            if r.short():
                raise ProtocolError("unexpected signed router response")
            corr, entity = r.short(), r.short()
            if len(corr) not in (0, 24):
                raise ProtocolError("invalid response correlation identifier")
            item = (corr, entity, r.rest())
            if corr:
                self.responses.append(item)
            else:
                self.events.append(item)
            if len(self.events) > 256 or len(self.responses) > 256:
                raise ProtocolError("excessive unsolicited router responses")

    def command(self, command: bytes, entity: bytes = b"", key=None) -> bytes:
        if self.transport is None:
            raise ConnectionError("not connected")
        correlation = secrets.token_bytes(24)
        packet = authorize(key, self.transport.session, correlation, entity, command, self.version)
        try:
            self.transport.write_block(self.sending.encrypt(batch([packet])))
            while True:
                while self.responses:
                    corr, response_entity, body = self.responses.popleft()
                    if corr != correlation or response_entity != entity:
                        raise ProtocolError("response does not match outstanding command")
                    if body.startswith(b"ERR "):
                        raise RouterError(body)
                    return body
                self._read()
        except RouterError:
            raise
        except BaseException:
            # A failed block consumes chain material: always discard this connection.
            self.close()
            raise

    def ping(self) -> None:
        if self.command(b"PING") != b"PONG":
            raise ProtocolError("expected PONG")

    def create_queue(
        self, *, sender_can_secure: bool = True, basic_auth: bytes | None = None
    ) -> ReceiveQueue:
        auth = ed25519.Ed25519PrivateKey.generate()
        dh = x25519.X25519PrivateKey.generate()
        command = b"NEW " + short(spki(auth.public_key())) + short(spki(dh.public_key()))
        command += b"0" if basic_auth is None else b"1" + short(basic_auth)
        command += b"C"  # create without subscription
        if self.version >= 15:
            command += b"1M0" if sender_can_secure else b"1C0"
            if self.version >= 17:
                command += b"0"  # no notification credentials
        else:
            command += b"T" if sender_can_secure else b"F"
        queue = parse_ids(self.command(command, key=auth), self.version, auth, dh)
        if queue.sender_can_secure != sender_can_secure:
            raise ProtocolError("router changed requested queue security mode")
        return queue

    def secure_sender(self, sender_id: bytes, key: ed25519.Ed25519PrivateKey) -> None:
        self._ok(self.command(b"SKEY " + short(spki(key.public_key())), sender_id, key))

    def secure_recipient(self, queue: ReceiveQueue, sender_public) -> None:
        self._ok(
            self.command(
                b"KEY " + short(spki(sender_public)), queue.recipient_id, queue.auth_private
            )
        )

    def send_ciphertext(self, sender_id: bytes, ciphertext: bytes, key=None) -> None:
        """Send an already encrypted opaque body. Success = server acceptance only."""
        if not 1 <= len(ciphertext) <= 16048:
            raise ProtocolError("ciphertext length must be 1..16048")
        try:
            self._ok(self.command(b"SEND F " + ciphertext, sender_id, key))
        except (ConnectionError, OSError, EOFError, SSL.Error) as exc:
            raise AmbiguousSendError("SEND result unknown; do not blindly retry") from exc

    def get(self, queue: ReceiveQueue) -> Delivery | None:
        self._mode(queue, "GET")
        body = self.command(b"GET", queue.recipient_id, queue.auth_private)
        return None if body == b"OK" else self._delivery(queue, body)

    def subscribe(self, queue: ReceiveQueue) -> Delivery | None:
        self._mode(queue, "SUB")
        body = self.command(b"SUB", queue.recipient_id, queue.auth_private)
        return None if body in (b"OK", b"SOK 0") else self._delivery(queue, body)

    def next_delivery(self, queue: ReceiveQueue) -> Delivery:
        try:
            while not self.events:
                self._read()
            _, entity, body = self.events.popleft()
            if entity != queue.recipient_id:
                raise ProtocolError("notification belongs to a different queue")
            return self._delivery(queue, body)
        except BaseException:
            self.close()
            raise

    def acknowledge(self, queue: ReceiveQueue, message_id: bytes) -> Delivery | None:
        if len(message_id) != 24:
            raise ProtocolError("message ID must contain 24 bytes")
        body = self.command(b"ACK " + short(message_id), queue.recipient_id, queue.auth_private)
        return None if body == b"OK" else self._delivery(queue, body)

    def delete_queue(self, queue: ReceiveQueue) -> None:
        self._ok(self.command(b"DEL", queue.recipient_id, queue.auth_private))

    @staticmethod
    def _ok(body: bytes) -> None:
        if body != b"OK":
            raise ProtocolError("expected OK response")

    def _mode(self, queue: ReceiveQueue, mode: str) -> None:
        previous = self.modes.setdefault(queue.recipient_id, mode)
        if previous != mode:
            raise ProtocolError("GET and SUB cannot share a queue connection")

    @staticmethod
    def _delivery(queue: ReceiveQueue, body: bytes) -> Delivery:
        if not body.startswith(b"MSG "):
            raise ProtocolError("expected MSG response")
        r = Reader(body[4:])
        mid = r.short()
        if len(mid) != 24:
            raise ProtocolError("invalid message ID")
        secret = queue.dh_private.exchange(queue.server_dh)
        plain = Reader(unpad(smp_box.decrypt(secret, mid, r.rest())))
        if plain.data.startswith(b"QUOTA "):
            raise ProtocolError("router reports queue quota exceeded")
        timestamp = struct.unpack("!Q", plain.take(8))[0]
        flag = plain.take(1)
        if flag not in (b"T", b"F") or plain.take(1) != b" ":
            raise ProtocolError("invalid delivered message flags")
        return Delivery(mid, timestamp, flag == b"T", plain.rest())
