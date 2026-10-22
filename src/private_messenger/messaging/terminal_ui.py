"""Guided chat commands. Peer authentication still requires explicit user verification."""

import argparse
import json
import re
import shlex
import unicodedata


def safe(text: str) -> str:
    return "".join(
        f"\\u{ord(c):04x}" if unicodedata.category(c).startswith("C") else c for c in text
    )


def chat_words(line: str) -> list[str]:
    """Preserve JSON quotes when a copied export is supplied to connect."""
    line = line.strip().lstrip("/")
    if len(line) > 16384:
        raise ValueError("Příkaz je příliš dlouhý.")
    if line.startswith("PMS2:"):
        return ["connect", line]
    command = re.match(r"connect\s+({.*)$", line, re.DOTALL)
    if command:
        return ["connect", command[1]]
    if line.startswith("{"):
        # A damaged pasted export must fail as an invitation, never become a chat message.
        if re.search(r'"invitation"\s*:', line):
            return ["connect", line]
        try:
            exported = json.loads(line)
        except (ValueError, RecursionError):
            exported = None
        if isinstance(exported, dict) and "invitation" in exported:
            return ["connect", line]
    return shlex.split(line)


class ChatParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError(message + ". Nápověda: help")


def state_text(contact):
    state = contact["state"]
    if state == "active":
        return "připraveno k psaní" if contact["verified"] else "zbývá ověřit otisk: verify"
    return {
        "invited": "pozvánka čeká na použití",
        "requested": "příchozí žádost: accept",
        "waiting": "čekám na přijetí protistranou",
        "recovery_required": "po obnově je nutné nové spárování",
    }.get(state, "navazování spojení není dokončeno")


class ChatUI:
    """The selected recipient and verification prompt are local UI state only."""

    def __init__(self, messenger, write, *, human=True, on_verified=None):
        self.messenger = messenger
        self.write = write
        self.human = human
        self.on_verified = on_verified or (lambda cid: None)
        self.selected = None
        self.pending_verification = None
        usable = [c for c in messenger.all_contacts() if c["state"] != "invited"]
        if len(usable) == 1:
            self.selected = usable[0]["id"]

    def label(self, cid):
        contact = self.messenger.contact(cid)
        return safe(contact["name"] or f"nový kontakt [{cid}]")

    def emit(self, value):
        self.write(json.dumps(value, sort_keys=True))

    def select(self, cid):
        if cid != self.selected:
            self.pending_verification = None
        self.selected = cid

    def resolve(self, token=None, *, requested=False):
        contacts = self.messenger.all_contacts()
        if token is not None:
            exact = [c for c in contacts if c["id"] == token]
            found = exact or [c for c in contacts if c["name"].casefold() == token.casefold()]
        else:
            candidates = (
                [c for c in contacts if c["state"] == "requested"] if requested else contacts
            )
            found = [c for c in candidates if c["id"] == self.selected]
            if not found:
                found = [c for c in candidates if c["state"] != "invited"]
            if not found and requested:
                found = [c for c in contacts if c["id"] == self.selected and c["state"] == "active"]
        if len(found) == 1:
            if requested and found[0]["state"] not in ("requested", "active"):
                raise ValueError("Tento kontakt nemá příchozí žádost. " + state_text(found[0]))
            return found[0]["id"]
        if len(found) > 1:
            choices = "; ".join(f"{safe(c['name']) or 'kontakt'} [{c['id']}]" for c in found)
            raise ValueError("Vyber konkrétní kontakt pomocí jeho ID: " + choices)
        if requested:
            raise ValueError("Zatím nepřišla odpovídající žádost. Nech druhé okno otevřené.")
        if token is not None:
            raise ValueError(
                f"Kontakt {safe(token)} nenalezen. Napiš contacts; "
                "u jediného kontaktu stačí verify bez jména nebo ID."
            )
        raise ValueError(
            "Zatím nemáš vybraný kontakt. Vlož pozvánku protistrany, "
            "nebo napiš contacts a pak chat JMÉNO. Vlastní pozvánka: address."
        )

    def guidance(self, cid):
        contact = self.messenger.contact(cid)
        self.write(f"{self.label(cid)} · {state_text(contact)}.")
        if contact["state"] == "requested":
            self.write("Pro přijetí napiš accept. Potom oba napište verify.")
        elif contact["state"] == "waiting":
            self.write("Protistrana musí napsat accept. Potom oba napište verify.")
        elif contact["state"] == "active":
            self.write(
                "Teď stačí napsat zprávu a stisknout Enter."
                if contact["verified"]
                else "Napiš verify a porovnej otisk s protistranou."
            )

    def welcome(self):
        if not self.human:
            return
        if self.selected:
            self.guidance(self.selected)
        else:
            self.write("Nový kontakt: napiš address nebo sem vlož přijatou pozvánku.")
        self.write("contacts = kontakty · chat JMÉNO = výběr · help = nápověda · quit = konec")

    def verified(self, cid, confirmation):
        result = self.messenger.fingerprint(cid, confirmation)
        self.pending_verification = None
        self.select(cid)
        self.on_verified(cid)
        if self.human:
            self.write(f"{self.label(cid)}: otisk ověřen.")
            self.guidance(cid)
        else:
            self.emit(result)

    def send(self, cid, text):
        self.select(cid)
        contact = self.messenger.contact(cid)
        if contact["state"] != "active":
            self.write("Zpráva nebyla odeslána.")
            self.guidance(cid)
            return
        if not contact["verified"]:
            self.write(
                f"Zpráva nebyla odeslána. Nejprve ověř kontakt {self.label(cid)}: napiš verify."
            )
            return
        mid = self.messenger.send(cid, text)
        status = next(item["status"] for item in self.messenger.history(cid) if item["id"] == mid)
        if self.human:
            description = {
                "server_accepted": "přijato SMP serverem; čekám na potvrzení příjemce.",
                "rejected": "server zprávu odmítl. Nebyla doručena.",
                "acceptance_unknown": "přijetí serverem zatím nepotvrzeno; opakuji doručení.",
            }.get(status, "uloženo k odeslání; čekám na spojení se serverem.")
            self.write(f"Pro {self.label(cid)}: {description}")
        else:
            self.emit({"event": status, "id": mid, "recipient_delivery": "unconfirmed"})

    def handle(self, value):
        """Handle one input line; return False only for explicit exit."""
        from private_messenger.cli import execute, parser

        line = value.strip()
        if not line:
            return True
        if len(line) > 16384:
            raise ValueError("Příkaz je příliš dlouhý.")
        if line.lstrip("/") in ("quit", "exit"):
            return False
        pending, self.pending_verification = self.pending_verification, None
        if pending is not None and line.casefold() in ("ano", "ne"):
            cid, expected = pending
            if line.casefold() == "ne":
                self.write(
                    "Kontakt zůstává neověřený. Zprávy jsou zablokované; ověř původ pozvánky."
                )
            elif self.messenger.fingerprint(cid)["fingerprint"] != expected:
                raise ValueError("Otisk se změnil. Napiš verify a znovu jej porovnej.")
            else:
                self.verified(cid, expected)
            return True

        command_line = line.lstrip("/")
        if not command_line:
            raise ValueError("Nápověda: help")
        command = command_line.split(maxsplit=1)[0]
        known = {
            "address",
            "connect",
            "requests",
            "accept",
            "verify",
            "contacts",
            "send",
            "chat",
            "use",
            "history",
            "inbox",
            "identity",
            "status",
            "servers",
            "network",
            "backup",
            "rotate",
            "help",
            "unlock",
            "register",
            "restore",
            "listen",
            "smp",
        }
        pasted = line.startswith(("PMS2:", "{"))
        if command not in known and not pasted:
            # Ordinary text is never shell-parsed: apostrophes and quotes are message content.
            self.send(self.resolve(), value)
            return True
        words = chat_words(line)
        if command in ("chat", "use"):
            if len(words) != 2:
                raise ValueError("Výběr kontaktu: chat JMÉNO (nebo jeho ID).")
            cid = self.resolve(words[1])
            self.select(cid)
            self.guidance(cid)
            return True
        if command == "help":
            self.write(
                "1. Bob: address. Alice: vlož celou pozvánku.\n"
                "2. Bob: accept.\n"
                "3. Oba: verify. Porovnejte otisk osobně nebo jinou důvěryhodnou cestou; "
                "pouze při shodě napište ano.\n"
                "4. Pište zprávy přímo, bez příkazu.\n"
                "Další: contacts; chat JMÉNO; send JMÉNO TEXT; history; requests; quit.\n"
                "Příkazy lze uvozovat lomítkem, například /verify."
            )
            return True
        if words[0] in ("accept", "verify", "history", "rotate"):
            # Resolve names and the implicit recipient before the strict one-shot CLI parser.
            token = words[1] if len(words) > 1 and not words[1].startswith("--") else None
            cid = self.resolve(token, requested=words[0] == "accept")
            if token is None:
                words.insert(1, cid)
            else:
                words[1] = cid
        elif words[0] == "send" and len(words) > 1:
            words[1] = self.resolve(words[1])
        args = parser(ChatParser).parse_args(words)
        if args.command in ("unlock", "register", "restore", "listen", "smp"):
            raise ValueError("Tento příkaz není dostupný uvnitř chatu. Nápověda: help")
        if args.command == "network" and args.mode:
            raise ValueError("Změna sítě vyžaduje ukončení chatu a nové přihlášení.")
        if args.command == "connect":
            cid = self.messenger.connect(args.invitation, args.name)
            self.select(cid)
            if self.human:
                self.write("Žádost o spojení byla odeslána.")
                self.guidance(cid)
            else:
                self.emit({"event": "request_sent", **self.messenger.fingerprint(cid)})
        elif args.command == "accept":
            already_active = self.messenger.contact(args.id)["state"] == "active"
            if not already_active:
                self.messenger.accept(args.id)
            self.select(args.id)
            if self.human:
                self.write("Kontakt už je přijatý." if already_active else "Žádost přijata.")
                self.guidance(args.id)
            else:
                self.emit({"event": "accepted", **self.messenger.fingerprint(args.id)})
        elif args.command == "verify":
            self.select(args.id)
            if self.messenger.contact(args.id)["state"] == "invited":
                raise ValueError("Pozvánka ještě nebyla použita; zatím není koho ověřit.")
            if args.confirm:
                self.verified(args.id, args.confirm)
            else:
                result = self.messenger.fingerprint(args.id)
                if self.human:
                    fingerprint = result["fingerprint"]
                    grouped = " ".join(
                        fingerprint[i : i + 5] for i in range(0, len(fingerprint), 5)
                    )
                    self.write(f"Otisk spojení s {self.label(args.id)}:\n{grouped}")
                    if result["verified"]:
                        self.write("Tento otisk už máš ověřený.")
                    else:
                        self.pending_verification = (args.id, fingerprint)
                        self.write(
                            "Porovnejte celý otisk v obou oknech osobně nebo jinou "
                            "důvěryhodnou cestou. Shoduje se? Napiš ano / ne."
                        )
                else:
                    self.emit(result)
        elif args.command == "send":
            self.send(args.id, " ".join(args.message))
        elif args.command == "address" and self.human:
            invitation = self.messenger.address(args.server)
            self.write("Jednorázová pozvánka. Zkopíruj celý následující řádek do druhého chatu:")
            self.write(invitation["invitation"])
        elif args.command in ("contacts", "requests") and self.human:
            contacts = self.messenger.all_contacts()
            if args.command == "requests":
                contacts = [c for c in contacts if c["state"] == "requested"]
            if not contacts:
                self.write(
                    "Žádné kontakty." if args.command == "contacts" else "Žádné nové žádosti."
                )
            for contact in contacts:
                mark = "→ " if contact["id"] == self.selected else "  "
                self.write(
                    f"{mark}{self.label(contact['id'])} [{contact['id']}] · {state_text(contact)}"
                )
        elif args.command == "history" and self.human:
            self.select(args.id)
            history = self.messenger.history(args.id)
            if not history:
                self.write("Zatím žádné zprávy.")
            for item in history:
                sender = "Já" if item["direction"] == "out" else self.label(args.id)
                self.write(f"{sender}: {safe(item['body'])}")
        elif args.command == "status" and self.human:
            self.write(f"Síť: {self.messenger.network.mode} · experimentální, bez auditu.")
            if self.selected:
                self.guidance(self.selected)
            else:
                self.write("Nový kontakt: address nebo vlož přijatou pozvánku.")
        else:
            execute(args, self.messenger.vault, self.messenger)
        return True

    def received(self, cid, event):
        kind = event["event"]
        if kind == "text":
            sender = self.label(cid) if self.human else f"{self.label(cid)} [{cid}]"
            self.write(f"{sender}: {safe(event['body'])}")
        elif kind == "request":
            if self.selected is None:
                self.select(cid)
            target = "" if self.selected == cid else " " + cid
            self.write(f"{self.label(cid)} žádá o spojení. Pro přijetí napiš accept{target}.")
            if not self.human:
                self.emit(self.messenger.fingerprint(cid))
        elif kind == "accept":
            if self.selected is None:
                self.select(cid)
            self.write(f"{self.label(cid)} přijal spojení.")
            if self.human:
                if self.selected == cid:
                    self.guidance(cid)
                else:
                    self.write(f"Vyber konverzaci: chat {cid}")
        elif kind == "receipt":
            self.write(
                f"{self.label(cid)}: doručení zprávy potvrzeno."
                if self.human
                else f"[{cid}] Příjemce potvrdil zprávu {event['body']['message_id']}."
            )
