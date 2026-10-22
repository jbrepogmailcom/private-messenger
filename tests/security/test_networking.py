"""SOCKS wire tests use a synthetic local proxy, NOT a real Tor network."""

import socket
import threading

import pytest

from private_messenger.config import Server
from private_messenger.networking.connection import Network


def exact(stream, size):
    data = bytearray()
    while len(data) < size:
        block = stream.recv(size - len(data))
        if not block:
            raise EOFError("SOCKS test peer closed")
        data.extend(block)
    return bytes(data)


def test_remote_dns_and_connection_isolation(monkeypatch):
    observed = []
    failures = []
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)
    listener.settimeout(5)

    def proxy():
        try:
            for _ in range(2):
                stream, _ = listener.accept()
                with stream:
                    stream.settimeout(5)
                    assert exact(stream, 1) == b"\5"
                    methods = exact(stream, exact(stream, 1)[0])
                    assert 2 in methods
                    stream.sendall(b"\5\2")
                    assert exact(stream, 1) == b"\1"
                    username = exact(stream, exact(stream, 1)[0])
                    password = exact(stream, exact(stream, 1)[0])
                    stream.sendall(b"\1\0")
                    assert exact(stream, 4) == b"\5\1\0\3"  # ATYP domain name
                    hostname = exact(stream, exact(stream, 1)[0])
                    port = int.from_bytes(exact(stream, 2), "big")
                    observed.append((username, password, hostname, port))
                    stream.sendall(b"\5\0\0\1\x7f\0\0\1\x14\x67")
        except BaseException as exc:
            failures.append(exc)
        finally:
            listener.close()

    thread = threading.Thread(target=proxy, daemon=True)
    thread.start()
    real_lookup = socket.getaddrinfo

    def lookup(host, *args, **kwargs):
        assert host != "never-resolve-locally.invalid"
        return real_lookup(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", lookup)
    net = Network("TOR", "127.0.0.1", listener.getsockname()[1], timeout=3)
    server = Server("never-resolve-locally.invalid", 5223, bytes(32))
    for _ in range(2):
        net.connect(server).close()
    thread.join(timeout=6)
    assert not thread.is_alive() and not failures
    assert len(observed) == 2
    assert observed[0][:2] != observed[1][:2]
    assert observed[0][2:] == (b"never-resolve-locally.invalid", 5223)


def test_tor_fails_closed_without_direct_fallback(monkeypatch):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    def forbidden(*args, **kwargs):
        raise AssertionError("DIRECT fallback attempted")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    with pytest.raises(OSError):
        Network("TOR", "127.0.0.1", port, 1).connect(Server("example.invalid", 5223, bytes(32)))
    with pytest.raises(ValueError):
        Network("TOR", "proxy.invalid")
    with pytest.raises(ValueError):
        Network("MIXNET")


def test_onion_does_not_resolve_directly():
    with pytest.raises(ValueError):
        Network().connect(Server("example.onion", 5223, bytes(32)))


def test_swiss_password_discovery_tor_failure_never_uses_direct_http(monkeypatch):
    from private_messenger.networking.swiss import download_public_password

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    def forbidden(*args, **kwargs):
        raise AssertionError("Tor website discovery attempted direct DNS/HTTP fallback")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr("urllib.request.build_opener", forbidden)
    with pytest.raises(OSError):
        download_public_password(Network("TOR", "127.0.0.1", port, 1))
