"""Candidate secure suite over unmodified public SMP, independent profile processes.

Explicit opt-in; all queue credentials are temporary and cleaned up. No mocks.
"""

import json
import os
import secrets
import select
import subprocess
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

pytest.importorskip("private_messenger._crypto_native", reason="build native crypto")

from private_messenger.config import Server, b64, unb64
from private_messenger.identity import register
from private_messenger.networking.connection import Network
from private_messenger.networking.swiss import SERVER
from private_messenger.smp.client import Client
from private_messenger.smp.queues import ReceiveQueue
from private_messenger.storage.vault import Vault, atomic_write, read_private


class Process:
    def __init__(self, name, directory, password_file, mode="TOR"):
        self.p = subprocess.Popen(  # noqa: S603 -- fixed Python, no shell
            [
                str(Path(__file__).parents[2] / "chat"),
                name,
                "--directory",
                str(directory),
                "--passphrase-file",
                str(password_file),
                *(["--network", "DIRECT"] if mode == "DIRECT" else []),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        self.buffer = b""
        self.rows = []
        self.partial = b""

    def send(self, line):
        self.p.stdin.write((line + "\n").encode())
        self.p.stdin.flush()

    def read(self, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([self.p.stdout], [], [], remaining)[0]:
            raise AssertionError("process output timeout: " + self.buffer.decode())
        chunk = os.read(self.p.stdout.fileno(), 16384)
        if not chunk:
            raise AssertionError("process exited: " + self.buffer.decode())
        self.buffer += chunk
        self.partial += chunk
        while b"\n" in self.partial:
            line, self.partial = self.partial.split(b"\n", 1)
            if line.startswith(b"{") or line.startswith(b"["):
                try:
                    self.rows.append(json.loads(line))
                except ValueError:
                    pass

    def text(self, text, timeout=120):
        deadline = time.monotonic() + timeout
        while text.encode() not in self.buffer:
            self.read(deadline)

    def result(self, predicate, timeout=120):
        deadline = time.monotonic() + timeout
        while True:
            for index, row in enumerate(self.rows):
                if isinstance(row, dict) and predicate(row):
                    return self.rows.pop(index)
            self.read(deadline)

    def stop(self):
        if self.p.poll() is None:
            self.send("quit")
            try:
                self.p.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.p.kill()
                self.p.wait(timeout=5)


@pytest.mark.public
@pytest.mark.parametrize("mode", ["DIRECT", "TOR", "MANAGED_TOR"])
def test_secure_remote_pairing_online_offline_restart_and_replay(tmp_path, mode):
    if os.environ.get("PM_PUBLIC_SECURE_MESSENGER") != "1":
        pytest.skip("set PM_PUBLIC_SECURE_MESSENGER=1 for the real Swiss SMP candidate test")
    proxy_port = os.environ.get("PM_SECURE_TOR_PORT")
    if mode in ("TOR", "MANAGED_TOR") and not proxy_port:
        pytest.skip("real running Tor SOCKS proxy required: PM_SECURE_TOR_PORT")
    network = Network(
        mode="TOR" if mode == "MANAGED_TOR" else mode,
        proxy_port=int(proxy_port or 9050),
        timeout=30,
    )
    passwords = {name: secrets.token_urlsafe(32) for name in ("Alice", "Bob")}
    directories = {name: tmp_path / name for name in passwords}
    files = {}
    clients = []
    for name, password in passwords.items():
        files[name] = tmp_path / f"{name}.password"
        atomic_write(files[name], password.encode(), overwrite=False)
        auth_file = os.environ.get("PM_ROUTER_AUTH_FILE")
        if mode in ("TOR", "MANAGED_TOR") or auth_file:
            with Vault(directories[name] / f"{name.lower()}.vault", password, create=True) as vault:
                register(vault, name)
                if auth_file:
                    password = read_private(Path(auth_file), 257).rstrip(b"\r\n")
                    assert 1 <= len(password) <= 255
                    vault.put("router-auth:" + Server.parse(SERVER).uri, b64(password))
                vault.put(
                    "network",
                    {"mode": "DIRECT"}
                    if mode == "MANAGED_TOR"
                    else {
                        "mode": mode,
                        "proxy_host": "127.0.0.1",
                        "proxy_port": int(proxy_port or 9050),
                        "timeout": 30,
                    },
                )

    def start(name):
        client = Process(name, directories[name], files[name], mode)
        clients.append(client)
        client.text("Přihlášen(a): " + name, timeout=240)
        client.text("síť: " + ("DIRECT" if mode == "DIRECT" else "TOR"))
        return client

    def profile(name):
        return directories[name] / f"{name.lower()}.vault"

    try:
        bob = start("Bob")
        bob.send("address")
        invitation = bob.result(lambda r: "invitation" in r)
        bid = invitation["id"]
        alice = start("Alice")
        alice.send("connect " + invitation["invitation"])
        requested = alice.result(lambda r: r.get("event") == "request_sent")
        aid = requested["id"]
        bob.result(lambda r: r.get("id") == bid and "fingerprint" in r)
        bob.send("accept " + bid)
        accepted = bob.result(lambda r: r.get("event") == "accepted")
        assert accepted["fingerprint"] == requested["fingerprint"]
        alice.text("přijal spojení")
        alice.send(f"verify {aid} --confirm {requested['fingerprint']}")
        assert alice.result(lambda r: r.get("verified") is True)["id"] == aid
        alice.send(f"send {aid} Ahoj Bobe, skutečný vzdáleně spárovaný chat 🐴")
        first = alice.result(lambda r: r.get("event") == "server_accepted")
        # The peer verifies later: no ACK/history insertion before that, then resume
        # the same queued ciphertext without losing a session or requiring restart.
        bob.text("unverified contact cannot deliver application text")
        bob.send(f"verify {bid} --confirm {requested['fingerprint']}")
        assert bob.result(lambda r: r.get("verified") is True)["id"] == bid
        bob.text("skutečný vzdáleně spárovaný chat 🐴")
        alice.text("Příjemce potvrdil zprávu " + first["id"])
        bob.stop()
        assert bob.p.returncode == 0
        alice.send(f"send {aid} Tohle počká na vypnutého Boba")
        offline = alice.result(lambda r: r.get("event") == "server_accepted")
        alice.send(f"send {aid} Druhá offline zpráva přes ratchet")
        alice.result(lambda r: r.get("event") == "server_accepted")
        alice.stop()
        assert alice.p.returncode == 0
        with Vault(profile("Alice"), passwords["Alice"]) as vault:
            contact = json.loads(
                vault.db.execute("SELECT value FROM contacts WHERE id=?", (aid,)).fetchone()[0]
            )
            wire = vault.db.execute(
                "SELECT wire FROM outbox WHERE contact=? AND id=?", (aid, offline["id"])
            ).fetchone()[0]
            with Client(Server.parse(contact["outgoing"]["server"]), network) as sender:
                sender.send_ciphertext(
                    unb64(contact["outgoing"]["sender_id"]),
                    wire,
                    ed25519.Ed25519PrivateKey.from_private_bytes(unb64(contact["sender_private"])),
                )
        bob = start("Bob")
        bob.text("Tohle počká na vypnutého Boba")
        bob.text("Druhá offline zpráva přes ratchet")
        alice = start("Alice")
        alice.text("Příjemce potvrdil zprávu " + offline["id"])
        bob.send(f"send {bid} Bob odpovídá po restartu obou klientů")
        alice.text("Bob odpovídá po restartu obou klientů")
        for client in clients:
            client.stop()
            assert client.p.returncode == 0
        with Vault(profile("Bob"), passwords["Bob"]) as vault:
            assert vault.db.execute(
                "SELECT count(*) FROM messages WHERE direction='in'"
            ).fetchone() == (3,)
            if mode == "MANAGED_TOR":
                assert vault.get("network") == {"mode": "TOR"}
                assert vault.get("tor_guard_state")
        with Vault(profile("Alice"), passwords["Alice"]) as vault:
            assert vault.db.execute(
                "SELECT count(*) FROM messages WHERE status='recipient_received'"
            ).fetchone() == (3,)
    finally:
        for client in clients:
            client.stop()
        for name in passwords:
            if profile(name).exists():
                with Vault(profile(name), passwords[name]) as vault:
                    if not vault.db.execute(
                        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='contacts'"
                    ).fetchone():
                        continue
                    contacts = [
                        json.loads(row[0]) for row in vault.db.execute("SELECT value FROM contacts")
                    ]
                for contact in contacts:
                    with Client(Server.parse(contact["incoming_server"]), network) as client:
                        client.delete_queue(ReceiveQueue.restore(contact["receive"]))
