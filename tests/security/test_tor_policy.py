"""Policy/lifecycle fixtures. Stub children are NOT real Tor interoperability."""

import socket
import subprocess
import sys
from pathlib import Path

import pytest

from private_messenger.config import Server, b64, unb64
from private_messenger.networking import tor
from private_messenger.storage.vault import Vault


class Settings:
    def __init__(self, **values):
        self.values = values

    def get(self, key, default=None):
        return self.values.get(key, default)

    def put(self, key, value):
        self.values[key] = value


def test_default_is_tor_and_old_direct_chat_is_migrated_before_connections():
    vault = Settings()
    assert tor.configured_network(vault).mode == "TOR"
    vault.put("network", {"mode": "DIRECT", "proxy_host": "127.0.0.1", "proxy_port": 9050})
    tor.configure_chat(vault)
    assert vault.get("network") == {"mode": "TOR"}
    tor.configure_chat(vault, mode="DIRECT")  # Only an explicit opt-in to DIRECT.
    assert tor.configured_network(vault).mode == "DIRECT"


def test_custom_external_proxy_preserved_and_invalid_options_do_not_commit():
    vault = Settings(network={"mode": "TOR", "proxy_host": "::1", "proxy_port": 9150})
    tor.configure_chat(vault)
    assert tor.configured_network(vault).proxy_port == 9150
    before = dict(vault.get("network"))
    for port in (0, -1, 65536):
        with pytest.raises(ValueError):
            tor.configure_chat(vault, proxy_port=port)
        assert vault.get("network") == before
    with pytest.raises(ValueError):
        tor.configure_chat(vault, mode="DIRECT", proxy_port=9050)


def test_external_proxy_error_never_starts_owned_tor_or_direct_dns(monkeypatch):
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
    vault = Settings(network={"mode": "TOR", "proxy_port": port})

    def forbidden(*args, **kwargs):
        raise AssertionError("external proxy failure must never trigger a fallback")

    monkeypatch.setattr(tor.shutil, "which", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    with tor.messaging_network(vault) as network, pytest.raises(OSError):
        network.connect(Server("must-not-resolve.invalid", 5223, bytes(32)))


def test_missing_tor_fails_before_yield_or_any_destination_connection(monkeypatch):
    monkeypatch.setattr(tor.shutil, "which", lambda _: None)
    with (
        pytest.raises(tor.TorUnavailable, match="nainstalovaný"),
        tor.messaging_network(Settings()),
    ):
        raise AssertionError("unavailable Tor yielded a network")


def stub_tor(monkeypatch, script, children):
    original = subprocess.Popen
    monkeypatch.setattr(tor.shutil, "which", lambda _: "/test/tor-stub")

    def spawn(argv, **kwargs):
        assert "IsolateSOCKSAuth" in argv[argv.index("--SocksPort") + 1]
        assert kwargs.get("shell", False) is False
        data = argv[argv.index("--DataDirectory") + 1]
        child = original([sys.executable, "-u", "-c", script, data], **kwargs)  # noqa: S603
        children.append((child, Path(data)))
        return child

    monkeypatch.setattr(tor.subprocess, "Popen", spawn)


def test_early_exit_and_bootstrap_timeout_never_yield_and_stop_owned_child(monkeypatch):
    children = []
    stub_tor(monkeypatch, "print('bootstrap failed')", children)
    with pytest.raises(tor.TorUnavailable), tor.messaging_network(Settings()):
        raise AssertionError("incomplete bootstrap yielded a network")
    assert children[0][0].poll() is not None
    assert not children[0][1].exists()
    # New patch restores original Popen before installing the second stub factory.
    monkeypatch.undo()
    stub_tor(monkeypatch, "import time; time.sleep(20)", children)
    monkeypatch.setattr(tor, "BOOTSTRAP_SECONDS", 0.05)
    with pytest.raises(tor.TorUnavailable), tor.messaging_network(Settings()):
        raise AssertionError("bootstrap timeout yielded a network")
    assert children[-1][0].poll() is not None
    assert not children[-1][1].exists()


def test_owned_guard_state_is_encrypted_restored_and_own_process_stops(tmp_path, monkeypatch):
    children = []
    script = """
import os, pathlib, signal, sys, time
state = pathlib.Path(sys.argv[1]) / 'state'
initial = state.read_bytes() if state.exists() else b''
assert initial == b'previous guard state'
def stop(*_):
    state.write_bytes(b'guard metadata only in encrypted vault after exit')
    state.chmod(0o600)
    sys.exit(0)
signal.signal(signal.SIGTERM, stop)
print('Bootstrapped 100% (done): Done', flush=True)
while True: time.sleep(0.1)
"""
    stub_tor(monkeypatch, script, children)
    path = tmp_path / "private/test.vault"
    with Vault(path, "test secret", create=True) as vault:
        vault.put("tor_guard_state", b64(b"previous guard state"))
        with tor.messaging_network(vault) as network:
            assert network.mode == "TOR"
            assert network.proxy_host == "127.0.0.1"
            assert children[-1][0].poll() is None
        assert children[-1][0].poll() is not None
        assert not children[-1][1].exists()
        assert unb64(vault.get("tor_guard_state")) == (
            b"guard metadata only in encrypted vault after exit"
        )
    assert b"guard metadata only" not in path.read_bytes()
    with Vault(path, "test secret") as vault:
        assert unb64(vault.get("tor_guard_state")).startswith(b"guard metadata only")
