"""Interactive two-terminal *local-pairing demo*, independently transported by SMP."""

import argparse
import getpass
import json
import queue
import sys
import threading
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519
from nacl.exceptions import CryptoError
from OpenSSL import SSL

from private_messenger.config import Server, unb64
from private_messenger.networking.connection import Network
from private_messenger.networking.swiss import SERVER, download_public_password
from private_messenger.smp.client import AmbiguousSendError, Client, RouterError
from private_messenger.smp.queues import ReceiveQueue
from private_messenger.storage.vault import Vault, read_private

from .local_demo import (
    MAX_TEXT_BYTES,
    ROLES,
    DemoMessages,
    is_ready,
    profile_path,
    provision,
    public_address,
    safe_terminal,
)


def post(events: queue.Queue, stop: threading.Event, item: tuple) -> bool:
    while not stop.is_set():
        try:
            events.put(item, timeout=0.2)
            return True
        except queue.Full:
            pass
    return False


def keyboard(events: queue.Queue, stop: threading.Event) -> None:
    while not stop.is_set():
        line = sys.stdin.readline(MAX_TEXT_BYTES + 2)
        if not line:
            post(events, stop, ("input", "/quit"))
            return
        if not line.endswith("\n") and len(line) > MAX_TEXT_BYTES:
            while line and not line.endswith("\n"):
                line = sys.stdin.readline(MAX_TEXT_BYTES + 2)
            post(events, stop, ("input_error", None))
        else:
            post(events, stop, ("input", line.rstrip("\r\n")))


def receiver(profile: dict, events: queue.Queue, stop: threading.Event) -> None:
    """Network thread owns its SMP connection; only the main thread owns SQLite."""
    incoming = ReceiveQueue.restore(profile["receive"])
    server = Server.parse(profile["server"])
    failures = 0
    while not stop.is_set():
        try:
            with Client(server, Network(timeout=8)) as client:
                delivery = client.subscribe(incoming)
                post(events, stop, ("connected", client.version))
                failures = 0
                last_ping = time.monotonic()
                while not stop.is_set():
                    if delivery is None:
                        delivery = client.wait_delivery(incoming, timeout=0.25)
                        if delivery is None and time.monotonic() - last_ping > 45:
                            client.ping()
                            last_ping = time.monotonic()
                        continue
                    decision = queue.Queue(maxsize=1)
                    if not post(events, stop, ("delivery", (delivery, decision))):
                        return
                    while not stop.is_set():
                        try:
                            durable = decision.get(timeout=0.2)
                            break
                        except queue.Empty:
                            pass
                    else:
                        return
                    if not durable:
                        return
                    mid = delivery.message_id
                    delivery = client.acknowledge(incoming, mid)
                    post(events, stop, ("acked", mid))
        except (ValueError, CryptoError):
            post(events, stop, ("fatal", None))
            return
        except (OSError, EOFError, SSL.Error):
            if not failures:
                post(events, stop, ("reconnecting", None))
            failures += 1
            stop.wait(min(0.5 * 2 ** min(failures, 5), 10))


def run_chat(vault: Vault, role: str) -> int:
    messages = DemoMessages(vault, role)
    profile = messages.profile
    peer = profile["peer"]
    server = Server.parse(profile["server"])
    # This convenience launcher has one explicit pinned DIRECT demo configuration.
    if server != Server.parse(SERVER):
        raise ValueError("unexpected demo router identity")
    events = queue.Queue(maxsize=32)
    stop = threading.Event()
    receiving = threading.Thread(target=receiver, args=(profile, events, stop), daemon=True)
    typing = threading.Thread(target=keyboard, args=(events, stop), daemon=True)
    sending = Client(server, Network(timeout=8))
    sender_key = ed25519.Ed25519PrivateKey.from_private_bytes(unb64(profile["sender_private"]))
    sender_id = unb64(profile["send_id"])
    interactive = sys.stdin.isatty()

    def say(text: str) -> None:
        print(("\r\033[K" if interactive else "") + text, flush=True)
        if interactive:
            print(f"{role}> ", end="", flush=True)

    def history() -> None:
        for direction, text, state in messages.history():
            who = role if direction == "out" else peer
            suffix = f" [{state}]" if direction == "out" else ""
            say(f"{who}: {safe_terminal(text)}{suffix}")

    print(f"Signed in: {role} · contact: {peer}", flush=True)
    print("Same-computer test · Swiss SMP · DIRECT (server sees your IP).", flush=True)
    print(
        "Locally exchanged NaCl Box keys. No ratchet, PFS/PCS or post-quantum protection.",
        flush=True,
    )
    print(
        "Type a message and press Enter. /address = invitation, /history = history, /quit = exit.",
        flush=True,
    )
    history()
    receiving.start()
    typing.start()
    if interactive:
        print(f"{role}> ", end="", flush=True)
    result = 0
    try:
        while True:
            try:
                kind, value = events.get(timeout=0.2)
            except queue.Empty:
                continue
            if kind == "input":
                if value in ("/quit", "/exit"):
                    break
                if value == "/history":
                    history()
                elif value == "/address":
                    say(json.dumps(public_address(profile), ensure_ascii=True))
                elif value.startswith("/"):
                    say("Commands: /address, /history, /quit. Otherwise, type a message directly.")
                elif value:
                    try:
                        mid, ciphertext = messages.prepare(value)
                    except ValueError:
                        say("A message can contain at most 8192 UTF-8 bytes.")
                        continue
                    try:
                        if sending.transport is None:
                            sending.connect()
                        messages.outgoing_state(mid, "acceptance_unknown")
                        sending.send_ciphertext(sender_id, ciphertext, sender_key)
                        messages.outgoing_state(mid, "server_accepted")
                        say("✓ Message accepted by the server. Recipient delivery is unconfirmed.")
                    except AmbiguousSendError:
                        say(
                            "The send result is unknown. "
                            "The message will not be retried automatically."
                        )
                    except RouterError:
                        messages.outgoing_state(mid, "rejected")
                        say("The server rejected the message. See /history for details.")
                    except (OSError, EOFError, SSL.Error):
                        say("Connection failed. Message status is saved in /history.")
                elif interactive:
                    print(f"{role}> ", end="", flush=True)
            elif kind == "delivery":
                delivery, decision = value
                try:
                    fresh, text = messages.receive(delivery)
                except (ValueError, CryptoError):
                    decision.put(False)
                    say(
                        "Message verification failed. Reception stopped; "
                        "the message was not acknowledged."
                    )
                    result = 1
                    break
                decision.put(True)
                if fresh:
                    say(f"{peer}: {safe_terminal(text)}")
            elif kind == "acked":
                vault.acknowledged("terminal-demo", value)
            elif kind == "connected":
                say(f"Ready to receive · SMP v{value}. You can start typing.")
            elif kind == "reconnecting":
                say("Disconnected; reconnecting to the same server.")
            elif kind == "input_error":
                say("Message is too long; it was not sent.")
            elif kind == "fatal":
                say("Server or queue authentication failed. Connection stopped.")
                result = 1
                break
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        sending.close()
        receiving.join(timeout=9)
        print("\nSigned out. History and keys remain in encrypted storage.", flush=True)
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Two-terminal, locally paired SMP test")
    parser.add_argument("role", type=str.capitalize, choices=ROLES)
    parser.add_argument(
        "--directory",
        type=Path,
        default=Path.home() / ".local/share/private-messenger/terminal-demo",
    )
    parser.add_argument("--passphrase-file", type=Path, help="0600 file for automated tests")
    parser.add_argument(
        "--address",
        action="store_true",
        help="show only the public address after unlocking; no network connection",
    )
    args = parser.parse_args(argv)
    try:
        new = not is_ready(args.directory)
        if new and args.address:
            print("Profiles do not exist yet. Start chat Alice first.", file=sys.stderr)
            return 1
        if new:
            print(
                "The first launch prepares local test profiles for both Alice and Bob.", flush=True
            )
        if args.passphrase_file:
            secret = read_private(args.passphrase_file, 4096).decode().rstrip("\n")
        else:
            secret = getpass.getpass("Password for both test profiles: ")
            if new and getpass.getpass("Repeat password: ") != secret:
                raise ValueError("passphrases do not match")
        if new:
            print("Preparing encrypted profiles and queues on the Swiss SMP server…", flush=True)
            provision(args.directory, secret, Server.parse(SERVER), download_public_password())
        with Vault(profile_path(args.directory, args.role), secret) as vault:
            secret = None
            if args.address:
                print(json.dumps(public_address(vault.get("terminal_demo")), indent=2), flush=True)
                return 0
            return run_chat(vault, args.role)
    except BlockingIOError:
        print(
            "The profile is already open. Use /address in the running chat; "
            "after an update, first exit the old process with /quit.",
            file=sys.stderr,
        )
        return 1
    except (ValueError, OSError, EOFError, CryptoError, SSL.Error):
        print(
            "Startup failed: check the password, connection and SMP server availability. "
            "On first launch, let setup finish in one terminal before opening the other.",
            file=sys.stderr,
        )
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
