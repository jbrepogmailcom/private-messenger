"""Independent profiles and remote invitations. No locally shared peer secrets."""

import argparse
import getpass
import json
import queue
import re
import sys
import threading
import time
from dataclasses import replace
from pathlib import Path

from nacl.exceptions import CryptoError
from OpenSSL import SSL
from tqdm import tqdm

from private_messenger.crypto.backend import SUITE, CryptoUnavailable, operation
from private_messenger.identity import register
from private_messenger.messaging.receiver import post, subscribe
from private_messenger.messaging.service import Messenger
from private_messenger.messaging.terminal_ui import ChatUI, safe
from private_messenger.messaging.terminal_ui import chat_words as chat_words
from private_messenger.networking.tor import configure_chat, messaging_network
from private_messenger.storage.vault import Vault, read_private


class TorProgress:
    """One terminal progress bar; readable event lines for redirected output."""

    def __init__(self):
        self.output = sys.stdout
        self.bar = None

    def __call__(self, text: str) -> None:
        if not self.output.isatty():
            print(text, file=self.output, flush=True)
            return
        if self.bar is None:
            self.bar = tqdm(
                total=100,
                file=self.output,
                dynamic_ncols=True,
                bar_format="Tor: {percentage:3.0f}% |{bar}|",
                mininterval=0,
                miniters=1,
                leave=True,
            )
        match = re.fullmatch(r"Tor: (\d{1,3}) %", text)
        if match and 0 <= int(match[1]) <= 100:
            self.bar.update(int(match[1]) - self.bar.n)

    def close(self) -> None:
        if self.bar is not None:
            self.bar.close()
            self.bar = None


def keyboard(events, stop) -> None:
    while not stop.is_set():
        line = sys.stdin.readline(16386)
        if not line:
            post(events, stop, ("input", "quit"))
            return
        if len(line) > 16384:
            while line and not line.endswith("\n"):
                line = sys.stdin.readline(16386)
            post(events, stop, ("input_error", None))
        else:
            post(events, stop, ("input", line.rstrip("\r\n")))


def run_shell(vault: Vault, interactive=True, network=None) -> int:
    if network is None:
        progress = TorProgress()
        try:
            with messaging_network(vault, progress=progress) as route:
                progress.close()
                return run_shell(vault, interactive, route)
        finally:
            progress.close()

    events = queue.Queue(maxsize=64)
    workers = {}
    resume = set()
    paused = set()
    stop = threading.Event()
    last_flush = 0
    is_tty = interactive and sys.stdin.isatty()
    name = vault.get("identity", {}).get("name", "private-messenger")

    def say(text):
        print(("\r\033[K" if is_tty else "") + text, flush=True)

    def verified(cid):
        if cid in paused:
            resume.add(cid)
            paused.remove(cid)

    def prompt():
        if is_tty:
            peer = " → " + ui.label(ui.selected) if ui.selected else ""
            print(f"{safe(name)}{peer}> ", end="", flush=True)

    with Messenger(vault, network=network) as messenger:
        ui = ChatUI(messenger, say, human=is_tty, on_verified=verified)
        if interactive:
            print(
                f"Přihlášen(a): {safe(name)} · experimentální verze bez nezávislého auditu.",
                flush=True,
            )
            print(
                f"SMP · síť: {messenger.network.mode}"
                if is_tty
                else f"Kryptografie: {SUITE} · síť: {messenger.network.mode}",
                flush=True,
            )
            ui.welcome()
            threading.Thread(target=keyboard, args=(events, stop), daemon=True).start()
            prompt()
        try:
            while not stop.is_set():
                for contact in messenger.all_contacts():
                    if contact["state"] not in ("invited", "waiting", "requested", "active"):
                        continue
                    cid = contact["id"]
                    if cid in resume and cid in workers and not workers[cid].is_alive():
                        del workers[cid]
                        resume.remove(cid)
                    if cid not in workers:
                        worker = threading.Thread(
                            target=subscribe,
                            args=(
                                contact,
                                replace(
                                    messenger.network,
                                    timeout=30 if messenger.network.mode == "TOR" else 8,
                                ),
                                events,
                                stop,
                            ),
                            daemon=True,
                        )
                        workers[contact["id"]] = worker
                        worker.start()
                try:
                    kind, value = events.get(timeout=0.2)
                except queue.Empty:
                    kind, value = "idle", None
                if kind == "input":
                    try:
                        if not ui.handle(value):
                            break
                    except (
                        ValueError,
                        OSError,
                        EOFError,
                        SSL.Error,
                        CryptoError,
                        CryptoUnavailable,
                    ) as exc:
                        say("Chyba: " + safe(str(exc)))
                elif kind == "delivery":
                    cid, delivery, decision = value
                    try:
                        event = messenger.receive(cid, delivery)
                    except (ValueError, CryptoError) as exc:
                        paused.add(cid)
                        decision.put(False)
                        contact = messenger.contact(cid)
                        if is_tty and contact["state"] == "active" and not contact["verified"]:
                            say(
                                f"{ui.label(cid)}: zpráva čeká na ověření. "
                                f"Napiš verify {cid} a porovnej otisk."
                            )
                        else:
                            say(
                                f"[{cid}] Ověření selhalo; fronta nebyla potvrzena: "
                                + safe(str(exc))
                            )
                        prompt()
                        continue
                    decision.put(True)
                    ui.received(cid, event)
                elif kind == "acked":
                    cid, mid = value
                    vault.acknowledged("pm2:" + cid, mid)
                elif kind == "connected":
                    cid, version = value
                    say(
                        f"{ui.label(cid)}: příjem zpráv je připraven."
                        if is_tty
                        else f"Příjem připraven [{cid}] · SMP v{version}."
                    )
                elif kind == "reconnecting":
                    say(
                        f"{ui.label(value)}: obnovuji spojení."
                        if is_tty
                        else f"[{value}] Obnovuji spojení přes stejný ověřený server."
                    )
                elif kind == "fatal":
                    say(f"[{value}] Ověření serveru nebo fronty selhalo; příjem zastaven.")
                elif kind == "input_error":
                    say("Příkaz je příliš dlouhý; nebyl proveden.")
                if kind not in ("idle", "acked"):
                    prompt()
                if time.monotonic() - last_flush > 0.5:
                    messenger.flush()
                    last_flush = time.monotonic()
        except KeyboardInterrupt:
            pass
        finally:
            stop.set()
            deadline = time.monotonic() + 9
            for worker in workers.values():
                worker.join(timeout=max(0, deadline - time.monotonic()))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Samostatný SMP messenger s ověřenými kontakty")
    parser.add_argument("name")
    parser.add_argument(
        "--directory",
        type=Path,
        default=Path.home() / ".local/share/private-messenger/secure-profiles",
    )
    parser.add_argument("--passphrase-file", type=Path)
    parser.add_argument(
        "--network",
        choices=["TOR", "DIRECT"],
        default="TOR",
        help="výchozí TOR; DIRECT je výslovný režim odhalující IP routeru",
    )
    parser.add_argument("--tor-proxy-host", help="IP vlastní Tor SOCKS proxy")
    parser.add_argument("--tor-proxy-port", type=int, help="port vlastní Tor SOCKS proxy")
    parser.add_argument(
        "--address", action="store_true", help="vytvoř jednorázovou pozvánku a skonči"
    )
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", args.name):
        parser.error("profil musí mít 1–32 znaků: písmena, číslice, _ nebo -")
    path = args.directory / (args.name.lower() + ".vault")
    new = not path.exists()
    try:
        operation("metadata")  # Refuse unavailable/unexpected crypto before creating a profile.
        if args.passphrase_file:
            secret = read_private(args.passphrase_file, 4096).decode().rstrip("\n")
        else:
            secret = getpass.getpass(f"Heslo profilu {args.name}: ")
            if new and getpass.getpass("Zopakuj heslo: ") != secret:
                raise ValueError("hesla se neshodují")
        with Vault(path, secret, create=new) as vault:
            secret = None
            if new:
                register(vault, args.name)
            configure_chat(vault, args.network, args.tor_proxy_host, args.tor_proxy_port)
            if args.address:
                with (
                    messaging_network(vault) as route,
                    Messenger(vault, network=route) as messenger,
                ):
                    print(json.dumps(messenger.address()), flush=True)
                return 0
            return run_shell(vault)
    except (ValueError, OSError, EOFError, SSL.Error, CryptoError, CryptoUnavailable) as exc:
        print("Chyba: " + safe(str(exc)), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
