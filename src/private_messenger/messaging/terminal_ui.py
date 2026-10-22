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
        raise ValueError("Command is too long.")
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
            "The invitation was not sent as a message. "
            "Add a contact with /add INVITATION or /add Charlie INVITATION."
        )


class ChatParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError(message + ". Help: /help")


def state_text(contact):
    state = contact["state"]
    if state == "active":
        return (
            "ready to chat" if contact["verified"] else "fingerprint verification required: /verify"
        )
    return {
        "invited": "invitation waiting to be used",
        "requested": "incoming request: /accept",
        "waiting": "waiting for the contact to accept",
        "recovery_required": "new pairing required after restore",
        "deleting": "queue deletion pending: /del",
    }.get(state, "connection setup is incomplete")


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
        return safe(contact["name"] or f"new contact [{cid}]")

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
            raise ValueError("Choose a contact from /chat or use /chat NAME.")
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
                raise ValueError("This contact has no incoming request. " + state_text(found[0]))
            return found[0]["id"]
        if len(found) > 1:
            choices = "; ".join(f"{safe(c['name']) or 'contact'} [{c['id']}]" for c in found)
            raise ValueError(
                "Choose a specific contact from /chat, then use /chat NUMBER: " + choices
            )
        if requested:
            raise ValueError("No matching request has arrived yet. Keep the other terminal open.")
        if token is not None:
            raise ValueError(
                f"Contact {safe(token)} not found. Use /chat; "
                "with one contact, /verify needs no name or ID."
            )
        raise ValueError(
            "No contact is selected. Use /chat to choose a recipient; "
            "add a contact: /add INVITATION. Create your invitation: /address."
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
            self.write("No new requests." if requested else "No saved contacts yet.")
            self.write("Add a contact: /add INVITATION. Create your invitation: /address.")
            return
        for number, contact in enumerate(contacts, 1):
            mark = "→ " if contact["id"] == self.selected else "  "
            self.write(f"{mark}{number}. {self.label(contact['id'])} · {state_text(contact)}")
        self.write("Choose a contact: /chat NUMBER (for example /chat 1) or /chat NAME.")

    def choose(self, token):
        if token.isascii() and token.isdecimal() and len(token) < 16:
            if not self.contact_choices:
                raise ValueError("First display the list with /chat, then choose /chat NUMBER.")
            number = int(token)
            if not 1 <= number <= len(self.contact_choices):
                raise ValueError(
                    f"Choose a number from 1–{len(self.contact_choices)} in the /chat list."
                )
            return self.resolve(self.contact_choices[number - 1])
        return self.resolve(token)

    def guidance(self, cid):
        contact = self.messenger.contact(cid)
        self.write(f"{self.label(cid)} · {state_text(contact)}.")
        if contact["state"] == "requested":
            self.write("Use /accept to accept. Then both contacts use /verify.")
        elif contact["state"] == "waiting":
            self.write("The other contact must use /accept. Then both contacts use /verify.")
        elif contact["state"] == "active":
            self.write(
                "Type a message and press Enter."
                if contact["verified"]
                else "Use /verify and compare the fingerprint with your contact."
            )

    def welcome(self):
        if not self.human:
            return
        if self.selected:
            self.guidance(self.selected)
        else:
            self.list_contacts()
        self.write(
            "/add INVITATION = add contact · /chat = choose contact · /del = delete · /help · /quit"
        )

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
                    f"{peer}: history and conversation keys have been removed, "
                    "but local removal of the remaining queue credentials failed."
                )
            else:
                self.write(
                    f"{peer}: local history and conversation keys have been removed. "
                    "SMP queue deletion could not be confirmed; "
                    "only queue credentials remain to finish deletion."
                )
            self.write("Reason: " + safe(str(exc)))
            suffix = " --local" if local_only else ""
            self.write(f"To finish: /del {cid}{suffix} (also works after restart).")
            if not local_only:
                self.write(
                    f"Local removal without contacting the server: /del {cid} --local. "
                    "This gives up the ability to delete this queue on the server."
                )
            return
        if self.human:
            self.write(f"Contact {peer} deleted, including local history and keys.")
            description = {
                "server_deleted": "The SMP server confirmed deletion of the incoming queue.",
                "local_only": "Deleted locally only; the server queue was not removed.",
                "server_unconfirmed": (
                    "The server returned AUTH; the queue is inaccessible, "
                    "but deletion is unconfirmed."
                ),
            }
            self.write(description[result])
            self.write(
                "To start over, delete the contact on both sides "
                "and create a new /address invitation."
            )
        else:
            self.emit({"event": "contact_deleted", "id": cid, "queue": result})

    def verified(self, cid, confirmation):
        result = self.messenger.fingerprint(cid, confirmation)
        self.pending_verification = None
        self.select(cid)
        self.on_verified(cid)
        if self.human:
            self.write(f"{self.label(cid)}: fingerprint verified.")
            self.guidance(cid)
        else:
            self.emit(result)

    def send(self, cid, text):
        check_message(text)
        self.select(cid)
        contact = self.messenger.contact(cid)
        if contact["state"] != "active":
            self.write("Message was not sent.")
            self.guidance(cid)
            return
        if not contact["verified"]:
            self.write(f"Message was not sent. First verify {self.label(cid)} with /verify.")
            return
        mid = self.messenger.send(cid, text)
        status = next(item["status"] for item in self.messenger.history(cid) if item["id"] == mid)
        if self.human:
            description = {
                "server_accepted": (
                    "accepted by the SMP server; waiting for recipient confirmation."
                ),
                "rejected": "the server rejected the message. It was not delivered.",
                "acceptance_unknown": "server acceptance is unconfirmed; retrying delivery.",
            }.get(status, "saved for sending; waiting for a server connection.")
            self.write(f"To {self.label(cid)}: {description}")
        else:
            self.emit({"event": status, "id": mid, "recipient_delivery": "unconfirmed"})

    def handle(self, value):
        """Handle one input line; return False only for explicit exit."""
        from private_messenger.cli import execute, parser

        line = value.strip()
        if not line:
            return True
        if len(line) > 16384:
            raise ValueError("Command is too long.")
        if line in ("/quit", "/exit"):
            return False
        pending, self.pending_verification = self.pending_verification, None
        deletion, self.pending_deletion = self.pending_deletion, None
        if line.casefold() in ("/yes", "/no"):
            if deletion is not None:
                if line.casefold() == "/no":
                    self.write("Deletion cancelled.")
                else:
                    self.delete(*deletion)
                return True
            if pending is None:
                raise ValueError("First display the fingerprint with /verify and compare it.")
            cid, expected = pending
            if line.casefold() == "/no":
                self.write(
                    "The contact remains unverified. Messages are blocked; "
                    "check the invitation source."
                )
            elif self.messenger.fingerprint(cid)["fingerprint"] != expected:
                raise ValueError("The fingerprint changed. Use /verify and compare it again.")
            else:
                self.verified(cid, expected)
            return True

        if not line.startswith("/"):
            # Ordinary text is never shell-parsed: apostrophes and quotes are message content.
            check_message(value)
            self.send(self.resolve(), value)
            return True
        if line == "/" or line.startswith("//"):
            raise ValueError("Unknown command. Help: /help")
        command = line[1:].split(maxsplit=1)[0]
        words = chat_words(line)
        if command == "del":
            local_only = words[-1] == "--local"
            if local_only:
                words.pop()
            if len(words) > 2:
                raise ValueError(
                    "Delete: /del NAME, /del NUMBER, or /del for the selected contact."
                )
            if len(words) == 2:
                cid = self.choose(words[1])
            elif self.selected:
                cid = self.selected
            else:
                contacts = self.messenger.all_contacts()
                if len(contacts) != 1:
                    self.list_contacts(include_invitations=True)
                    self.write("Delete: /del NUMBER or /del NAME.")
                    return True
                cid = contacts[0]["id"]
            if self.messenger.contact(cid)["state"] == "deleting" and not local_only:
                self.delete(cid)  # The persisted deletion was already explicitly confirmed.
            else:
                self.pending_deletion = (cid, local_only)
                self.write(
                    f"Delete contact {self.label(cid)} [{cid}], its local history and keys "
                    + (
                        "locally only? The server queue will remain; "
                        "its access keys will be discarded. "
                        if local_only
                        else "and your own incoming SMP queue? "
                    )
                    + "Confirm with /yes, or cancel with /no."
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
                raise ValueError("Choose a contact: /chat NUMBER or /chat NAME.")
            cid = self.choose(words[1])
            self.select(cid)
            self.guidance(cid)
            return True
        if command == "help":
            self.write(
                "Commands start with /; other text is a message to the selected contact.\n"
                "1. Charlie: /address. Alice: /add Charlie INVITATION.\n"
                "2. Charlie: /accept.\n"
                "3. Both: /verify. Compare the fingerprint in person or through a trusted channel; "
                "use /yes only if it matches. Use /no if it differs.\n"
                "4. Type messages directly, without a command.\n"
                "Choose: /chat or /contacts lists contacts; /chat 2 selects the second contact.\n"
                "Delete: /del NAME or /del NUMBER, then /yes. Use /no to cancel.\n"
                "Unused invitations: /contacts --all; remove one with /del NUMBER.\n"
                "Without server contact: /del NAME --local; leaves the server queue in place.\n"
                "More: /chat Bob; /send Bob TEXT; /history; /requests; /status; /quit."
            )
            return True
        if command in ("add", "connect") and len(words) == 1:
            self.write("Add a contact: /add INVITATION or /add Charlie INVITATION.")
            self.write(
                "Ask the other contact to create an invitation with /address in their terminal."
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
            raise ValueError("This command is not available inside chat. Help: /help")
        if args.command == "network" and args.mode:
            raise ValueError("To change networks, quit chat and sign in again.")
        if args.command == "connect":
            try:
                cid = self.messenger.connect(args.invitation, args.name)
            except ValueError as exc:
                if str(exc) == "invitation already used by this profile":
                    raise ValueError(
                        "This invitation is already saved. Choose the contact from /chat."
                    ) from exc
                raise
            self.select(cid)
            if self.human:
                self.write("Connection request sent.")
                self.guidance(cid)
            else:
                self.emit({"event": "request_sent", **self.messenger.fingerprint(cid)})
        elif args.command == "accept":
            already_active = self.messenger.contact(args.id)["state"] == "active"
            if not already_active:
                self.messenger.accept(args.id)
            self.select(args.id)
            if self.human:
                self.write("Contact already accepted." if already_active else "Request accepted.")
                self.guidance(args.id)
            else:
                self.emit({"event": "accepted", **self.messenger.fingerprint(args.id)})
        elif args.command == "verify":
            self.select(args.id)
            if self.messenger.contact(args.id)["state"] == "invited":
                raise ValueError(
                    "The invitation has not been used; there is no contact to verify yet."
                )
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
                    self.write(f"Connection fingerprint with {self.label(args.id)}:\n{grouped}")
                    if result["verified"]:
                        self.write("This fingerprint is already verified.")
                    else:
                        self.write(
                            "Compare the entire fingerprint in both terminals in person "
                            "or through another trusted channel. Does it match? Use /yes or /no."
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
                "Copy the entire command below into your contact's terminal (one-time invitation):"
            )
            self.write(f"/add {safe(label)}{invitation['invitation']}")
        elif args.command in ("contacts", "requests"):
            self.list_contacts(requested=args.command == "requests")
        elif args.command == "history" and self.human:
            self.select(args.id)
            history = self.messenger.history(args.id)
            if not history:
                self.write("No messages yet.")
            for item in history:
                sender = "Me" if item["direction"] == "out" else self.label(args.id)
                self.write(f"{sender}: {safe(item['body'])}")
        elif args.command == "status" and self.human:
            self.write(f"Network: {self.messenger.network.mode} · experimental, unaudited.")
            if self.selected:
                self.guidance(self.selected)
            else:
                self.write("Choose a contact: /chat. Add a contact: /add INVITATION.")
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
            self.write(f"{self.label(cid)} requests a connection. To accept, use /accept{target}.")
            if not self.human:
                self.emit(self.messenger.fingerprint(cid))
        elif kind == "accept":
            if self.selected is None and not self.require_selection:
                self.select(cid)
            self.write(f"{self.label(cid)} accepted the connection.")
            if self.human:
                if self.selected == cid:
                    self.guidance(cid)
                else:
                    self.write(
                        f"Choose the conversation: /chat {cid} (or choose from the /chat list)."
                    )
        elif kind == "receipt":
            self.write(
                f"{self.label(cid)}: message delivery confirmed."
                if self.human
                else f"[{cid}] Recipient confirmed message {event['body']['message_id']}."
            )
