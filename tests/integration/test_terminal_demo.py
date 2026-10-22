"""Opt-in real public Swiss SMP, independently running interactive Python clients."""

import os
import pty
import secrets
import select
import subprocess
import sys
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from private_messenger.config import Server, unb64
from private_messenger.messaging.local_demo import DemoMessages, profile_path, provision
from private_messenger.networking.swiss import SERVER, download_public_password
from private_messenger.smp.client import Client
from private_messenger.smp.queues import ReceiveQueue
from private_messenger.storage.vault import Vault, atomic_write


class PTYTerminal:
    """Real controlling terminal: exercise getpass in the retained legacy launcher."""

    def __init__(self, role, directory):
        launcher = Path(__file__).parents[2] / "chat-legacy"
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            # Fixed repository launcher; arguments are passed directly, never through a shell.
            os.execv(  # noqa: S606
                str(launcher), [str(launcher), role, "--directory", str(directory)]
            )
        self.output = b""
        self.finished = False

    def send(self, text):
        os.write(self.fd, (text + "\n").encode())

    def wait_for(self, text, timeout=40):
        expected = text.encode()
        deadline = time.monotonic() + timeout
        while expected not in self.output:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError(f"terminal did not show {text!r}: {self.output.decode()}")
            if select.select([self.fd], [], [], remaining)[0]:
                self.output += os.read(self.fd, 8192)

    def stop(self):
        if self.finished:
            return
        self.send("/quit")
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                self.finished = True
                os.close(self.fd)
                assert os.waitstatus_to_exitcode(status) == 0
                return
            time.sleep(0.1)
        os.kill(self.pid, 9)
        os.waitpid(self.pid, 0)
        os.close(self.fd)
        self.finished = True
        raise AssertionError("terminal did not quit")


class TerminalProcess:
    def __init__(self, role, directory, password_file):
        self.process = subprocess.Popen(  # noqa: S603 -- fixed Python, argument list, no shell
            [
                sys.executable,
                "-m",
                "private_messenger.messaging.terminal",
                role,
                "--directory",
                str(directory),
                "--passphrase-file",
                str(password_file),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        self.output = b""

    def send(self, text):
        self.process.stdin.write((text + "\n").encode())
        self.process.stdin.flush()

    def wait_for(self, text, timeout=30):
        expected = text.encode()
        deadline = time.monotonic() + timeout
        while expected not in self.output:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError(f"missing {text!r}; output: {self.output.decode()}")
            ready = select.select([self.process.stdout], [], [], remaining)[0]
            if ready:
                chunk = os.read(self.process.stdout.fileno(), 8192)
                if not chunk:
                    raise AssertionError(f"process exited: {self.output.decode()}")
                self.output += chunk

    def stop(self):
        if self.process.poll() is None:
            self.send("/quit")
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        assert self.process.returncode == 0


@pytest.mark.public
def test_real_two_terminal_text_online_offline_restart_and_replay(tmp_path):
    if os.environ.get("PM_PUBLIC_TERMINAL_DEMO") != "1":
        pytest.skip("set PM_PUBLIC_TERMINAL_DEMO=1 to opt in to real Swiss SMP queues")
    directory = tmp_path / "profiles"
    password = secrets.token_urlsafe(32)
    password_file = tmp_path / "password"
    atomic_write(password_file, password.encode(), overwrite=False)
    server = Server.parse(SERVER)
    provision(directory, password, server, download_public_password())
    profiles = {}
    for role in ("Alice", "Bob"):
        with Vault(profile_path(directory, role), password) as vault:
            profiles[role] = vault.get("terminal_demo")
            if role == "Alice":
                replay_id, replay_ciphertext = DemoMessages(vault, role).prepare("replay fixture")
    clients = []
    try:
        alice = TerminalProcess("Alice", directory, password_file)
        clients.append(alice)
        bob = TerminalProcess("Bob", directory, password_file)
        clients.append(bob)
        alice.wait_for("Ready to receive")
        bob.wait_for("Ready to receive")
        alice.send("Ahoj Bobe, vidíš mě? 🐴")
        bob.wait_for("Alice: Ahoj Bobe, vidíš mě? 🐴")
        bob.send("Ahoj Alice, zpráva dorazila!")
        alice.wait_for("Bob: Ahoj Alice, zpráva dorazila!")
        # SUB remains alive during ordinary silence, rather than timing out after 20s.
        time.sleep(21)
        alice.send("Zpráva po tichu")
        bob.wait_for("Alice: Zpráva po tichu")
        assert bob.output.count("Ready to receive".encode()) == 1
        bob.stop()
        alice.send("Čekám ve frontě, zatímco je Bob vypnutý")
        alice.send("Druhá zpráva pro offline Boba")
        # Restarting Bob restores the same encrypted profile and queue credentials.
        bob = TerminalProcess("Bob", directory, password_file)
        clients.append(bob)
        bob.wait_for("Alice: Čekám ve frontě, zatímco je Bob vypnutý")
        bob.wait_for("Alice: Druhá zpráva pro offline Boba")
        # Republish identical authenticated application ciphertext under distinct router IDs.
        with Client(server) as sender:
            key = ed25519.Ed25519PrivateKey.from_private_bytes(
                unb64(profiles["Alice"]["sender_private"])
            )
            sid = unb64(profiles["Alice"]["send_id"])
            sender.send_ciphertext(sid, replay_ciphertext, key)
            sender.send_ciphertext(sid, replay_ciphertext, key)
        bob.wait_for("Alice: replay fixture")
        alice.send("Konec testovací série")
        bob.wait_for("Alice: Konec testovací série")
        assert bob.output.count(b"Alice: replay fixture") == 1
        for terminal in clients:
            terminal.stop()
        with Vault(profile_path(directory, "Bob"), password) as vault:
            assert vault.db.execute(
                "SELECT count(*) FROM demo_messages WHERE id=?", (replay_id,)
            ).fetchone() == (1,)
            assert vault.db.execute(
                "SELECT count(*) FROM demo_messages WHERE direction='in'"
            ).fetchone() == (6,)
            with Client(server) as receiver:
                assert receiver.get(ReceiveQueue.restore(profiles["Bob"]["receive"])) is None
    finally:
        for terminal in clients:
            terminal.stop()
        for profile in profiles.values():
            with Client(server) as receiver:
                receiver.delete_queue(ReceiveQueue.restore(profile["receive"]))


@pytest.mark.public
def test_first_run_password_login_and_text_in_two_real_terminals(tmp_path):
    if os.environ.get("PM_PUBLIC_TERMINAL_DEMO") != "1":
        pytest.skip("requires opt-in real Swiss SMP and two controlling terminals")
    directory = tmp_path / "interactive-profiles"
    password = secrets.token_urlsafe(32)
    terminals = []
    try:
        alice = PTYTerminal("Alice", directory)
        terminals.append(alice)
        alice.wait_for("Password for both test profiles:")
        alice.send(password)
        alice.wait_for("Zopakuj heslo:")
        alice.send(password)
        alice.wait_for("Ready to receive")
        bob = PTYTerminal("Bob", directory)
        terminals.append(bob)
        bob.wait_for("Password for both test profiles:")
        bob.send(password)
        bob.wait_for("Ready to receive")
        alice.send("Ahoj Bobe z terminálu!")
        bob.wait_for("Alice: Ahoj Bobe z terminálu!")
        bob.send("Ahoj Alice, opravdu to funguje!")
        alice.wait_for("Bob: Ahoj Alice, opravdu to funguje!")
        assert password.encode() not in alice.output + bob.output
        assert "Zopakuj heslo:".encode() not in bob.output
    finally:
        for terminal in terminals:
            terminal.stop()
        for role in ("Alice", "Bob"):
            path = profile_path(directory, role)
            if path.exists():
                with Vault(path, password) as vault:
                    profile = vault.get("terminal_demo")
                if profile:
                    with Client(Server.parse(profile["server"])) as receiver:
                        receiver.delete_queue(ReceiveQueue.restore(profile["receive"]))
