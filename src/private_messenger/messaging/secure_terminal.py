"""Independent profiles and remote invitations. No locally shared peer secrets."""

import argparse
import getpass
import json
import queue
import re
import shlex
import sys
import threading
import time
import unicodedata
from dataclasses import replace
from pathlib import Path

from nacl.exceptions import CryptoError
from OpenSSL import SSL

from private_messenger.crypto.backend import SUITE, CryptoUnavailable, operation
from private_messenger.identity import register
from private_messenger.messaging.receiver import post, subscribe
from private_messenger.messaging.service import Messenger
from private_messenger.storage.vault import Vault, read_private


def safe(text: str) -> str:
    return "".join(
        f"\\u{ord(c):04x}" if unicodedata.category(c).startswith("C") else c for c in text
    )


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


def run_shell(vault: Vault, interactive=True) -> int:
    from private_messenger.cli import execute, parser

    events = queue.Queue(maxsize=64)
    workers = {}
    resume = set()
    paused = set()
    stop = threading.Event()
    selected = None
    last_flush = 0
    is_tty = interactive and sys.stdin.isatty()
    name = vault.get("identity", {}).get("name", "private-messenger")

    def say(text):
        print(("\r\033[K" if is_tty else "") + text, flush=True)
        if is_tty:
            print(f"{safe(name)}> ", end="", flush=True)

    with Messenger(vault) as messenger:
        if interactive:
            print(
                f"Přihlášen(a): {safe(name)} · experimentální verze bez nezávislého auditu.",
                flush=True,
            )
            print(f"Kryptografie: {SUITE} · síť: {messenger.network.mode}", flush=True)
            print(
                "address → pozvánka; connect POZVÁNKA; requests; accept ID; verify ID", flush=True
            )
            print(
                "Po porovnání: verify ID --confirm OTISK. Zpráva: send ID TEXT. quit = konec.",
                flush=True,
            )
            threading.Thread(target=keyboard, args=(events, stop), daemon=True).start()
            if is_tty:
                print(f"{safe(name)}> ", end="", flush=True)
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
                    line = value.lstrip("/")
                    if line in ("quit", "exit"):
                        break
                    if line.startswith("PMS2:"):
                        line = "connect " + line
                    try:
                        words = shlex.split(line)
                        if not words:
                            continue
                        known = {
                            "address",
                            "connect",
                            "requests",
                            "accept",
                            "verify",
                            "contacts",
                            "send",
                            "history",
                            "inbox",
                            "identity",
                            "status",
                            "servers",
                            "network",
                            "backup",
                            "rotate",
                            "help",
                        }
                        if words[0] not in known and selected:
                            words = ["send", selected, value]
                        if words[0] == "help":
                            say(
                                "address; connect POZVÁNKA; requests; accept ID; verify ID; "
                                "verify ID --confirm OTISK; send ID TEXT; "
                                "contacts; history ID; quit"
                            )
                            continue
                        args = parser().parse_args(words)
                        if args.command in ("unlock", "register", "restore", "listen", "smp"):
                            raise ValueError("command unavailable inside chat")
                        if args.command == "network" and args.mode:
                            raise ValueError(
                                "Nejprve ukonči chat. Síť změň samostatným příkazem network, "
                                "aby během změny nezůstalo aktivní staré spojení."
                            )
                        execute(args, vault, messenger)
                        if args.command == "connect":
                            selected = messenger.all_contacts()[-1]["id"]
                        elif args.command in ("accept", "verify", "send"):
                            selected = args.id
                        if args.command == "verify" and args.confirm and args.id in paused:
                            resume.add(args.id)
                            paused.remove(args.id)
                    except (
                        ValueError,
                        OSError,
                        EOFError,
                        SSL.Error,
                        CryptoError,
                        CryptoUnavailable,
                    ) as exc:
                        say("Chyba: " + safe(str(exc)))
                    except SystemExit:
                        pass
                    if is_tty:
                        print(f"{safe(name)}> ", end="", flush=True)
                elif kind == "delivery":
                    cid, delivery, decision = value
                    try:
                        event = messenger.receive(cid, delivery)
                    except (ValueError, CryptoError) as exc:
                        paused.add(cid)
                        decision.put(False)
                        say(f"[{cid}] Ověření selhalo; fronta nebyla potvrzena: {safe(str(exc))}")
                        continue
                    decision.put(True)
                    if event["event"] == "text":
                        peer = messenger.contact(cid)["name"] or cid
                        say(f"{safe(peer)} [{cid}]: {safe(event['body'])}")
                    elif event["event"] == "request":
                        say(
                            f"Požadavek [{cid}] od {safe(event['body']['name'])}. "
                            f"Přijmi: accept {cid}"
                        )
                        say(json.dumps(messenger.fingerprint(cid)))
                    elif event["event"] == "accept":
                        selected = cid
                        say(f"Kontakt [{cid}] přijal spojení. Porovnej otisk: verify {cid}")
                    elif event["event"] == "receipt":
                        say(f"[{cid}] Příjemce potvrdil zprávu {event['body']['message_id']}.")
                elif kind == "acked":
                    cid, mid = value
                    vault.acknowledged("pm2:" + cid, mid)
                elif kind == "connected":
                    cid, version = value
                    say(f"Příjem připraven [{cid}] · SMP v{version}.")
                elif kind == "reconnecting":
                    say(f"[{value}] Obnovuji spojení přes stejný ověřený server.")
                elif kind == "fatal":
                    say(f"[{value}] Ověření serveru nebo fronty selhalo; příjem zastaven.")
                elif kind == "input_error":
                    say("Příkaz je příliš dlouhý; nebyl proveden.")
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
            if args.address:
                with Messenger(vault) as messenger:
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
