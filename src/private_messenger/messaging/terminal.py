"""Interactive two-terminal *local-pairing demo*, independently transported by SMP."""

import argparse
import getpass
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

    print(f"Přihlášen(a): {role} · protějšek: {peer}", flush=True)
    print("Test na jednom počítači · švýcarský SMP · DIRECT (server vidí IP).", flush=True)
    print("Lokálně předané klíče, NaCl Box. Bez ratchetu, PFS/PCS a PQ ochrany.", flush=True)
    print("Piš zprávu a stiskni Enter. /history = historie, /quit = konec.", flush=True)
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
                elif value.startswith("/"):
                    say("Příkazy: /history, /quit. Jinak napiš přímo zprávu.")
                elif value:
                    try:
                        mid, ciphertext = messages.prepare(value)
                    except ValueError:
                        say("Zpráva může mít nejvýše 8192 bajtů v UTF-8.")
                        continue
                    try:
                        if sending.transport is None:
                            sending.connect()
                        messages.outgoing_state(mid, "acceptance_unknown")
                        sending.send_ciphertext(sender_id, ciphertext, sender_key)
                        messages.outgoing_state(mid, "server_accepted")
                        say("✓ Zprávu přijal server. Přijetí protějškem není potvrzené.")
                    except AmbiguousSendError:
                        say("Výsledek odeslání není znám. Zprávu automaticky neopakuji.")
                    except RouterError:
                        messages.outgoing_state(mid, "rejected")
                        say("Server zprávu odmítl. Podrobnosti jsou v /history.")
                    except (OSError, EOFError, SSL.Error):
                        say("Spojení selhalo. Stav zprávy je uložen v /history.")
                elif interactive:
                    print(f"{role}> ", end="", flush=True)
            elif kind == "delivery":
                delivery, decision = value
                try:
                    fresh, text = messages.receive(delivery)
                except (ValueError, CryptoError):
                    decision.put(False)
                    say("Ověření zprávy selhalo. Příjem zastaven, zpráva nebyla potvrzena.")
                    result = 1
                    break
                decision.put(True)
                if fresh:
                    say(f"{peer}: {safe_terminal(text)}")
            elif kind == "acked":
                vault.acknowledged("terminal-demo", value)
            elif kind == "connected":
                say(f"Příjem připraven · SMP v{value}. Můžeš psát.")
            elif kind == "reconnecting":
                say("Spojení přerušeno; obnovuji příjem přes stejný server.")
            elif kind == "input_error":
                say("Zpráva je příliš dlouhá; nebyla odeslána.")
            elif kind == "fatal":
                say("Ověření serveru nebo fronty selhalo. Spojení zastaveno.")
                result = 1
                break
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        sending.close()
        receiving.join(timeout=9)
        print("\nOdhlášeno. Historie a klíče zůstávají v šifrovaném úložišti.", flush=True)
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Dva terminály, lokálně spárovaný SMP test")
    parser.add_argument("role", type=str.capitalize, choices=ROLES)
    parser.add_argument(
        "--directory",
        type=Path,
        default=Path.home() / ".local/share/private-messenger/terminal-demo",
    )
    parser.add_argument("--passphrase-file", type=Path, help="0600 soubor, pro automatické testy")
    args = parser.parse_args(argv)
    try:
        new = not is_ready(args.directory)
        if new:
            print("První spuštění připraví místní testovací profily Alice i Bob.", flush=True)
        if args.passphrase_file:
            secret = read_private(args.passphrase_file, 4096).decode().rstrip("\n")
        else:
            secret = getpass.getpass("Heslo obou testovacích profilů: ")
            if new and getpass.getpass("Zopakuj heslo: ") != secret:
                raise ValueError("passphrases do not match")
        if new:
            print("Připravuji šifrované profily a fronty na švýcarském SMP…", flush=True)
            provision(args.directory, secret, Server.parse(SERVER), download_public_password())
        with Vault(profile_path(args.directory, args.role), secret) as vault:
            secret = None
            return run_chat(vault, args.role)
    except (ValueError, OSError, EOFError, CryptoError, SSL.Error):
        print(
            "Spuštění selhalo: zkontroluj heslo, připojení a dostupnost SMP. "
            "Při prvním spuštění nech nejprve dokončit přípravu v jednom okně.",
            file=sys.stderr,
        )
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
