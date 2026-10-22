"""Guided chat commands. Peer authentication still requires explicit user verification."""

import argparse
import json
import re
import shlex
import unicodedata

from OpenSSL import SSL


def safe(text: str) -> str:
    return "".join(
        f"\\u{ord(c):04x}" if unicodedata.category(c).startswith("C") else c for c in text
    )


def chat_words(line: str) -> list[str]:
    """Preserve JSON quotes when a copied export is supplied to connect."""
    line = line.strip().lstrip("/")
    if len(line) > 16384:
        raise ValueError("Příkaz je příliš dlouhý.")
    if re.match(r"add(?:\s|$)", line):
        line = "connect" + line[3:]
    if line.startswith("PMS2:"):
        return ["connect", line]
    command = re.match(r"connect\s+({.*)$", line, re.DOTALL)
    if command:
        try:
            _, end = json.JSONDecoder().raw_decode(command[1])
        except (ValueError, RecursionError):
            return ["connect", command[1]]
        return ["connect", command[1][:end], *shlex.split(command[1][end:])]
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
    words = shlex.split(line)
    # Friendly named form: /add Charlie PMS2:... (the name is only a local label).
    if (
        len(words) == 3
        and words[0] == "connect"
        and not words[1].startswith("--")
        and words[2].startswith("PMS2:")
    ):
        return ["connect", words[2], "--name", words[1]]
    return words


def check_message(text):
    """Keep accidental invitation pastes out of the currently selected conversation."""
    if (
        "pms2:" in text.casefold()
        or re.search(r'"invitation"\s*:', text)
        or re.search(r"[A-Z2-7]{512,}", text, re.IGNORECASE)
    ):
        raise ValueError(
            "Pozvánka nebyla odeslána jako zpráva. "
            "Nový kontakt přidej příkazem /add KÓD nebo /add Charlie KÓD."
        )


class ChatParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError(message + ". Nápověda: /help")


def state_text(contact):
    state = contact["state"]
    if state == "active":
        return "připraveno k psaní" if contact["verified"] else "zbývá ověřit otisk: /verify"
    return {
        "invited": "pozvánka čeká na použití",
        "requested": "příchozí žádost: /accept",
        "waiting": "čekám na přijetí protistranou",
        "recovery_required": "po obnově je nutné nové spárování",
        "deleting": "čeká na dokončení smazání fronty: /del",
    }.get(state, "navazování spojení není dokončeno")


class ChatUI:
    """The selected recipient and verification prompt are local UI state only."""

    def __init__(self, messenger, write, *, human=True, on_verified=None, on_deleting=None):
        self.messenger = messenger
        self.write = write
        self.human = human
        self.on_verified = on_verified or (lambda cid: None)
        self.on_deleting = on_deleting or (lambda cid: None)
        self.selected = None
        self.require_selection = False
        self.pending_verification = None
        self.pending_deletion = None
        self.contact_choices = ()
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
            self.pending_deletion = None
        self.selected = cid
        self.require_selection = cid is None

    def resolve(self, token=None, *, requested=False):
        if token is None and not requested and self.selected is None and self.require_selection:
            raise ValueError("Vyber protistranu ze seznamu /chat nebo příkazem /chat JMÉNO.")
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
            raise ValueError(
                "Vyber konkrétní kontakt ze seznamu /chat, pak /chat ČÍSLO: " + choices
            )
        if requested:
            raise ValueError("Zatím nepřišla odpovídající žádost. Nech druhé okno otevřené.")
        if token is not None:
            raise ValueError(
                f"Kontakt {safe(token)} nenalezen. Napiš /chat; "
                "u jediného kontaktu stačí /verify bez jména nebo ID."
            )
        raise ValueError(
            "Zatím nemáš vybraný kontakt. Napiš /chat a vyber protistranu; "
            "nový kontakt: /add KÓD. Vlastní pozvánka: /address."
        )

    def list_contacts(self, *, requested=False, include_invitations=False):
        contacts = sorted(
            (
                c
                for c in self.messenger.all_contacts()
                if (
                    c["state"] == "requested"
                    if requested
                    else include_invitations or c["state"] not in ("new", "invited")
                )
            ),
            key=lambda c: (c["name"].casefold(), c["id"]),
        )
        # Freeze exactly the displayed ID order. Incoming requests cannot renumber this menu.
        self.contact_choices = tuple(c["id"] for c in contacts)
        if not self.human:
            self.emit(
                [
                    {"number": i, **{key: c[key] for key in ("id", "name", "state", "verified")}}
                    for i, c in enumerate(contacts, 1)
                ]
            )
            return
        if not contacts:
            self.write("Žádné nové žádosti." if requested else "Zatím nemáš uložené kontakty.")
            self.write("Nový kontakt: /add KÓD. Vlastní pozvánka: /address.")
            return
        for number, contact in enumerate(contacts, 1):
            mark = "→ " if contact["id"] == self.selected else "  "
            self.write(f"{mark}{number}. {self.label(contact['id'])} · {state_text(contact)}")
        self.write("Vyber protistranu: /chat ČÍSLO (například /chat 1) nebo /chat JMÉNO.")

    def choose(self, token):
        if token.isascii() and token.isdecimal() and len(token) < 16:
            if not self.contact_choices:
                raise ValueError("Nejdřív zobraz seznam: /chat. Potom vyber /chat ČÍSLO.")
            number = int(token)
            if not 1 <= number <= len(self.contact_choices):
                raise ValueError(f"Vyber číslo 1–{len(self.contact_choices)} ze seznamu /chat.")
            return self.resolve(self.contact_choices[number - 1])
        return self.resolve(token)

    def guidance(self, cid):
        contact = self.messenger.contact(cid)
        self.write(f"{self.label(cid)} · {state_text(contact)}.")
        if contact["state"] == "requested":
            self.write("Pro přijetí napiš /accept. Potom oba napište /verify.")
        elif contact["state"] == "waiting":
            self.write("Protistrana musí napsat /accept. Potom oba napište /verify.")
        elif contact["state"] == "active":
            self.write(
                "Teď stačí napsat zprávu a stisknout Enter."
                if contact["verified"]
                else "Napiš /verify a porovnej otisk s protistranou."
            )

    def welcome(self):
        if not self.human:
            return
        if self.selected:
            self.guidance(self.selected)
        else:
            self.list_contacts()
        self.write("/add KÓD = nový kontakt · /chat = výběr · /del = smazání · /help · /quit")

    def delete(self, cid, local_only=False):
        peer = self.label(cid)
        self.messenger.begin_contact_deletion(cid)
        self.on_deleting(cid)
        if self.selected == cid:
            # Never silently start sending ordinary text to another remaining contact.
            self.select(None)
        self.contact_choices = ()
        try:
            result = self.messenger.delete_contact(cid, local_only=local_only)
        except (ValueError, OSError, EOFError, SSL.Error) as exc:
            if local_only:
                self.write(
                    f"{peer}: historie a konverzační klíče jsou odstraněné, "
                    "ale dokončení místního smazání zbývajících přístupových údajů selhalo."
                )
            else:
                self.write(
                    f"{peer}: místní historie a konverzační klíče jsou odstraněné. "
                    "Smazání SMP fronty se nepodařilo potvrdit; "
                    "zbývají jen přístupové údaje k frontě pro dokončení smazání."
                )
            self.write("Důvod: " + safe(str(exc)))
            suffix = " --local" if local_only else ""
            self.write(f"Dokončení: /del {cid}{suffix} (lze i po restartu).")
            if not local_only:
                self.write(
                    f"Úplně místně bez serveru: /del {cid} --local. "
                    "Tím se vzdáš možnosti smazat tuto frontu na serveru."
                )
            return
        if self.human:
            self.write(f"Kontakt {peer} odstraněn včetně místní historie a klíčů.")
            description = {
                "server_deleted": "SMP server potvrdil smazání příchozí fronty.",
                "local_only": "Smazáno pouze místně; fronta na serveru nebyla odstraněna.",
                "server_unconfirmed": (
                    "Server vrátil AUTH; fronta není dostupná, její smazání nelze potvrdit."
                ),
            }
            self.write(description[result])
            self.write(
                "Pro test od začátku smaž kontakt i v druhém okně a vytvoř novou pozvánku /address."
            )
        else:
            self.emit({"event": "contact_deleted", "id": cid, "queue": result})

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
        check_message(text)
        self.select(cid)
        contact = self.messenger.contact(cid)
        if contact["state"] != "active":
            self.write("Zpráva nebyla odeslána.")
            self.guidance(cid)
            return
        if not contact["verified"]:
            self.write(
                f"Zpráva nebyla odeslána. Nejprve ověř kontakt {self.label(cid)}: napiš /verify."
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
        if line in ("/quit", "/exit"):
            return False
        pending, self.pending_verification = self.pending_verification, None
        deletion, self.pending_deletion = self.pending_deletion, None
        if line.casefold() in ("/ano", "/ne", "/yes", "/no"):
            if deletion is not None:
                if line.casefold() in ("/ne", "/no"):
                    self.write("Smazání zrušeno.")
                else:
                    self.delete(*deletion)
                return True
            if pending is None:
                raise ValueError("Nejprve zobraz otisk příkazem /verify a porovnej jej.")
            cid, expected = pending
            if line.casefold() in ("/ne", "/no"):
                self.write(
                    "Kontakt zůstává neověřený. Zprávy jsou zablokované; ověř původ pozvánky."
                )
            elif self.messenger.fingerprint(cid)["fingerprint"] != expected:
                raise ValueError("Otisk se změnil. Napiš /verify a znovu jej porovnej.")
            else:
                self.verified(cid, expected)
            return True

        if not line.startswith("/"):
            # Ordinary text is never shell-parsed: apostrophes and quotes are message content.
            check_message(value)
            self.send(self.resolve(), value)
            return True
        if line == "/" or line.startswith("//"):
            raise ValueError("Neznámý příkaz. Nápověda: /help")
        command = line[1:].split(maxsplit=1)[0]
        words = chat_words(line)
        if command == "del":
            local_only = words[-1] == "--local"
            if local_only:
                words.pop()
            if len(words) > 2:
                raise ValueError("Smazání: /del JMÉNO, /del ČÍSLO nebo /del pro vybraný kontakt.")
            if len(words) == 2:
                cid = self.choose(words[1])
            elif self.selected:
                cid = self.selected
            else:
                contacts = self.messenger.all_contacts()
                if len(contacts) != 1:
                    self.list_contacts(include_invitations=True)
                    self.write("Smazání: /del ČÍSLO nebo /del JMÉNO.")
                    return True
                cid = contacts[0]["id"]
            if self.messenger.contact(cid)["state"] == "deleting" and not local_only:
                self.delete(cid)  # The persisted deletion was already explicitly confirmed.
            else:
                self.pending_deletion = (cid, local_only)
                self.write(
                    f"Smazat kontakt {self.label(cid)} [{cid}], jeho místní historii a klíče "
                    + (
                        "pouze místně? Fronta na serveru zůstane; její přístupové klíče se zahodí. "
                        if local_only
                        else "a vlastní příchozí SMP frontu? "
                    )
                    + "Potvrď /ano, zruš /ne."
                )
            return True
        if words == ["contacts", "--all"]:
            self.list_contacts(include_invitations=True)
            return True
        if command in ("chat", "use"):
            if len(words) == 1:
                self.list_contacts()
                return True
            if len(words) != 2:
                raise ValueError("Výběr kontaktu: /chat ČÍSLO nebo /chat JMÉNO.")
            cid = self.choose(words[1])
            self.select(cid)
            self.guidance(cid)
            return True
        if command == "help":
            self.write(
                "Příkazy začínají /; ostatní text je zpráva vybrané protistraně.\n"
                "1. Charlie: /address. Alice: /add Charlie KÓD.\n"
                "2. Charlie: /accept.\n"
                "3. Oba: /verify. Porovnejte otisk osobně nebo jinou důvěryhodnou cestou; "
                "pouze při shodě napište /ano. Při neshodě /ne.\n"
                "4. Pište zprávy přímo, bez příkazu.\n"
                "Výběr: /chat nebo /contacts vypíše seznam; /chat 2 vybere druhý kontakt.\n"
                "Smazání: /del JMÉNO nebo /del ČÍSLO, potom /ano. /ne smazání zruší.\n"
                "Nepoužité pozvánky: /contacts --all; pak je lze také odstranit přes /del ČÍSLO.\n"
                "Bez kontaktování serveru: /del JMÉNO --local; ponechá frontu na serveru.\n"
                "Další: /chat Bob; /send Bob TEXT; /history; /requests; /status; /quit."
            )
            return True
        if command in ("add", "connect") and len(words) == 1:
            self.write("Nový kontakt: /add KÓD nebo /add Charlie KÓD.")
            self.write("KÓD získáš od protistrany příkazem /address v jejím okně.")
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
            raise ValueError("Tento příkaz není dostupný uvnitř chatu. Nápověda: /help")
        if args.command == "network" and args.mode:
            raise ValueError("Změna sítě vyžaduje ukončení chatu a nové přihlášení.")
        if args.command == "connect":
            try:
                cid = self.messenger.connect(args.invitation, args.name)
            except ValueError as exc:
                if str(exc) == "invitation already used by this profile":
                    raise ValueError(
                        "Tuto pozvánku už máš uloženou. Vyber kontakt ze seznamu /chat."
                    ) from exc
                raise
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
                if not result["verified"]:
                    self.pending_verification = (args.id, result["fingerprint"])
                if self.human:
                    fingerprint = result["fingerprint"]
                    grouped = " ".join(
                        fingerprint[i : i + 5] for i in range(0, len(fingerprint), 5)
                    )
                    self.write(f"Otisk spojení s {self.label(args.id)}:\n{grouped}")
                    if result["verified"]:
                        self.write("Tento otisk už máš ověřený.")
                    else:
                        self.write(
                            "Porovnejte celý otisk v obou oknech osobně nebo jinou "
                            "důvěryhodnou cestou. Shoduje se? Napiš /ano nebo /ne."
                        )
                else:
                    self.emit(result)
        elif args.command == "send":
            self.send(args.id, " ".join(args.message))
        elif args.command == "address" and self.human:
            invitation = self.messenger.address(args.server)
            name = self.messenger.vault.get("identity", {}).get("name", "")
            label = shlex.quote(name) + " " if name else ""
            self.write(
                "Zkopíruj celý následující příkaz do okna protistrany (jednorázová pozvánka):"
            )
            self.write(f"/add {safe(label)}{invitation['invitation']}")
        elif args.command in ("contacts", "requests"):
            self.list_contacts(requested=args.command == "requests")
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
                self.write("Výběr kontaktu: /chat. Nový kontakt: /add KÓD.")
        else:
            execute(args, self.messenger.vault, self.messenger)
        return True

    def received(self, cid, event):
        kind = event["event"]
        if kind == "text":
            sender = self.label(cid) if self.human else f"{self.label(cid)} [{cid}]"
            self.write(f"{sender}: {safe(event['body'])}")
        elif kind == "request":
            if self.selected is None and not self.require_selection:
                self.select(cid)
            target = "" if self.selected == cid else " " + cid
            self.write(f"{self.label(cid)} žádá o spojení. Pro přijetí napiš /accept{target}.")
            if not self.human:
                self.emit(self.messenger.fingerprint(cid))
        elif kind == "accept":
            if self.selected is None and not self.require_selection:
                self.select(cid)
            self.write(f"{self.label(cid)} přijal spojení.")
            if self.human:
                if self.selected == cid:
                    self.guidance(cid)
                else:
                    self.write(f"Vyber konverzaci: /chat {cid} (nebo vyber ze seznamu /chat).")
        elif kind == "receipt":
            self.write(
                f"{self.label(cid)}: doručení zprávy potvrzeno."
                if self.human
                else f"[{cid}] Příjemce potvrdil zprávu {event['body']['message_id']}."
            )
