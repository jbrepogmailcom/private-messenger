"""Independent application protocol over native SMP and upstream crypto.

The vault owner thread alone mutates state. Native calls return candidate states;
only a successful encrypted transaction commits them. Opaque retries reuse the
identical authenticated packet, never a message key for new plaintext.
"""

import hashlib
import json
import secrets
import time

from cryptography.hazmat.primitives.asymmetric import ed25519
from OpenSSL import SSL

from private_messenger.config import Server, b64, unb64
from private_messenger.crypto.backend import SUITE, operation
from private_messenger.networking.swiss import PUBLIC_NEW_AUTH, SERVER
from private_messenger.networking.tor import configured_network
from private_messenger.sessions import invitations, packets
from private_messenger.smp.client import AmbiguousSendError, Client, RouterError
from private_messenger.smp.queues import ReceiveQueue
from private_messenger.storage.vault import Vault, VaultError

SCHEMA = (
    "CREATE TABLE IF NOT EXISTS contacts (id TEXT PRIMARY KEY, value TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS messages (contact TEXT NOT NULL,id TEXT NOT NULL,"
    " direction TEXT NOT NULL,body TEXT NOT NULL,status TEXT NOT NULL,created INTEGER NOT NULL,"
    " PRIMARY KEY(contact,id))",
    "CREATE TABLE IF NOT EXISTS outbox (contact TEXT NOT NULL,id TEXT NOT NULL,kind TEXT NOT NULL,"
    " wire BLOB NOT NULL,state TEXT NOT NULL,attempts INTEGER NOT NULL,next_attempt REAL NOT NULL,"
    " PRIMARY KEY(contact,id))",
    "CREATE TABLE IF NOT EXISTS received_packets (contact TEXT NOT NULL,digest BLOB NOT NULL,"
    " app_id TEXT NOT NULL,kind TEXT NOT NULL, PRIMARY KEY(contact,digest),"
    " UNIQUE(contact,app_id))",
)
MAX_CONTACTS = 64
MAX_TEXT = 8192
MAX_ATTEMPTS = 3


def put_contact(db, contact: dict) -> None:
    db.execute("INSERT OR REPLACE INTO contacts VALUES (?,?)", (contact["id"], json.dumps(contact)))


def route(server: str, sender_id: str) -> dict:
    if not isinstance(server, str) or not isinstance(sender_id, str) or len(server) > 512:
        raise ValueError("invalid peer route")
    server = Server.parse(server)
    sid = unb64(sender_id)
    if len(sid) != 24:
        raise ValueError("invalid sender queue ID")
    return {"server": server.uri, "sender_id": b64(sid)}


class Messenger:
    def __init__(self, vault: Vault, network=None):
        self.vault = vault
        self.clients = {}
        self.network = network if network is not None else configured_network(vault)
        with vault.transaction() as db:
            for statement in SCHEMA:
                db.execute(statement)
            if vault.get("restore_requires_repair", False):
                for contact in self.all_contacts():
                    contact.update(
                        state="recovery_required",
                        verified=False,
                        native=None,
                        sender_private=None,
                        outgoing=None,
                    )
                    put_contact(db, contact)
                db.execute("UPDATE outbox SET state='recovery_blocked'")
                db.execute(
                    "UPDATE messages SET status='recovery_blocked' WHERE direction='out' "
                    "AND status IN ('queued','acceptance_unknown')"
                )
                db.execute("UPDATE state SET value='false' WHERE key='restore_requires_repair'")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self) -> None:
        for client in self.clients.values():
            client.close()
        self.clients.clear()

    def all_contacts(self) -> list[dict]:
        return [json.loads(row[0]) for row in self.vault.db.execute("SELECT value FROM contacts")]

    def contact(self, cid: str) -> dict:
        row = self.vault.db.execute("SELECT value FROM contacts WHERE id=?", (cid,)).fetchone()
        if row is None:
            raise ValueError("unknown contact ID")
        return json.loads(row[0])

    def begin_contact_deletion(self, cid: str) -> None:
        """Durably retire a contact before network I/O; retain only DEL credentials.

        A failed remote deletion leaves a visible, non-messaging tombstone so it
        can be retried after a crash. No old ratchet/outbox can resume meanwhile.
        This is logical deletion, not guaranteed erasure of Python/SSD copies.
        """
        contact = self.contact(cid)
        if contact["state"] == "deleting":
            return
        retired = {
            key: contact[key]
            for key in ("id", "name", "conversation", "incoming_server", "receive")
        }
        retired.update(
            state="deleting", verified=False, native=None, outgoing=None, sender_private=None
        )
        with self.vault.transaction() as db:
            db.execute("DELETE FROM messages WHERE contact=?", (cid,))
            db.execute("DELETE FROM outbox WHERE contact=?", (cid,))
            db.execute("DELETE FROM received_packets WHERE contact=?", (cid,))
            db.execute("DELETE FROM deliveries WHERE queue=?", ("pm2:" + cid,))
            put_contact(db, retired)
        client = self.clients.pop(cid, None)
        if client is not None:
            client.close()

    def delete_contact(self, cid: str, *, local_only: bool = False) -> str:
        """Delete our recipient queue, then discard its last local credentials.

        AUTH is intentionally not evidence of erasure: it may mean absent queue
        or rejected credentials. Allow local cleanup, but report it as unavailable.
        Other failures retain the tombstone for an explicit retry.
        """
        self.begin_contact_deletion(cid)
        contact = self.contact(cid)
        result = "local_only" if local_only else "server_deleted"
        if not local_only:
            try:
                with Client(Server.parse(contact["incoming_server"]), self.network) as client:
                    client.delete_queue(ReceiveQueue.restore(contact["receive"]))
            except RouterError as exc:
                if exc.response != b"ERR AUTH":
                    raise
                result = "server_unconfirmed"
        with self.vault.transaction() as db:
            db.execute("DELETE FROM contacts WHERE id=?", (cid,))
        return result

    def _create(self, server: Server) -> dict:
        if len(self.all_contacts()) >= MAX_CONTACTS:
            raise ValueError("contact/unused invitation limit reached")
        native = operation("generate", local_address=b64(secrets.token_bytes(32)))
        auth = self.vault.get("router-auth:" + server.uri)
        if auth is None and server == Server.parse(SERVER):
            auth = b64(PUBLIC_NEW_AUTH)
            self.vault.put("router-auth:" + server.uri, auth)
        with Client(server, self.network) as client:
            incoming = client.create_queue(basic_auth=None if auth is None else unb64(auth))
            contact = {
                "id": secrets.token_hex(8),
                "conversation": b64(secrets.token_bytes(32)),
                "native": native["state"],
                "bundle": invitations.compact_bundle(native["bundle"]),
                "state": "new",
                "verified": False,
                "name": "",
                "incoming_server": server.uri,
                "receive": incoming.export(),
                "outgoing": None,
                "sender_private": b64(ed25519.Ed25519PrivateKey.generate().private_bytes_raw()),
                "expires": int(time.time()) + 7 * 86400,
            }
            try:
                with self.vault.transaction() as db:
                    put_contact(db, contact)
            except BaseException:
                client.delete_queue(incoming)
                raise
        return contact

    def address(self, server_uri: str | None = None) -> dict:
        configured = self.vault.get("servers", [SERVER])
        server = Server.parse(server_uri or (configured[0] if configured else SERVER))
        contact = self._create(server)
        data = {
            "v": 2,
            "suite": SUITE,
            "id": contact["conversation"],
            "expires": contact["expires"],
            "address": contact["native"]["local_address"],
            "server": server.uri,
            "sender_id": contact["receive"]["sender_id"],
            "bundle": contact["bundle"],
        }
        invitation = invitations.encode(data, contact["native"])
        contact.update(state="invited", invitation=invitation)
        with self.vault.transaction() as db:
            put_contact(db, contact)
        return {"id": contact["id"], "invitation": invitation, "expires": contact["expires"]}

    def _secure_outgoing(self, contact: dict) -> None:
        if contact["outgoing"] is None:
            raise ValueError("peer return route unavailable")
        key = ed25519.Ed25519PrivateKey.from_private_bytes(unb64(contact["sender_private"]))
        remote = contact["outgoing"]
        with Client(Server.parse(remote["server"]), self.network) as client:
            client.secure_sender(unb64(remote["sender_id"]), key)

    def connect(self, invitation: str, name: str = "") -> str:
        if len(name.encode()) > 256:
            raise ValueError("contact name exceeds 256 UTF-8 bytes")
        # Export metadata is ignored; verify the signed inner invitation before network access.
        data = invitations.decode(invitations.unwrap(invitation))
        if any(c["conversation"] == data["id"] for c in self.all_contacts()):
            raise ValueError("invitation already used by this profile")
        configured = self.vault.get("servers", [SERVER])
        server = Server.parse(configured[0] if configured else SERVER)
        contact = self._create(server)
        contact.update(
            conversation=data["id"],
            outgoing=route(data["server"], data["sender_id"]),
            state="securing",
            name=name,
        )
        contact["native"] = operation(
            "initiate",
            state=contact["native"],
            peer_address=data["address"],
            bundle=invitations.expand_bundle(data["bundle"]),
        )["state"]
        with self.vault.transaction() as db:
            put_contact(db, contact)
        self._secure_outgoing(contact)
        contact["state"] = "waiting"
        profile = self.vault.get("identity", {})
        body = {
            "name": profile.get("name", ""),
            "route": route(server.uri, contact["receive"]["sender_id"]),
        }
        with self.vault.transaction() as db:
            mid = self._prepare(db, contact, "request", body)
            contact["request_id"] = mid
            put_contact(db, contact)
        self.flush(contact["id"])
        return contact["id"]

    def _prepare(self, db, contact: dict, kind: str, body) -> str:
        mid = b64(secrets.token_bytes(32))
        state = contact["native"]
        envelope = {
            "v": 2,
            "suite": SUITE,
            "conversation": contact["conversation"],
            "id": mid,
            "from": state["local_address"],
            "to": state["peer_address"],
            "kind": kind,
            "body": body,
        }
        result = operation("encrypt", state=state, plaintext=list(invitations.canonical(envelope)))
        wire = packets.pack(
            state["local_address"], result["message_type"], bytes(result["ciphertext"])
        )
        contact["native"] = result["state"]
        put_contact(db, contact)
        db.execute(
            "INSERT INTO outbox VALUES (?,?,?,?, 'queued',0,0)", (contact["id"], mid, kind, wire)
        )
        return mid

    def accept(self, cid: str) -> None:
        contact = self.contact(cid)
        if contact["state"] != "requested":
            raise ValueError("contact is not an incoming request")
        self._secure_outgoing(contact)
        contact["state"] = "active"
        with self.vault.transaction() as db:
            mid = self._prepare(
                db,
                contact,
                "accept",
                {
                    "request_id": contact["request_id"],
                    "name": self.vault.get("identity", {}).get("name", ""),
                },
            )
            contact["accept_id"] = mid
            put_contact(db, contact)
        self.flush(cid)

    def fingerprint(self, cid: str, confirm: str | None = None) -> dict:
        contact = self.contact(cid)
        if contact["native"] is None:
            raise ValueError(
                "restored contact requires a fresh invitation and fingerprint verification"
            )
        fingerprint = operation("fingerprint", state=contact["native"])["fingerprint"]
        if confirm is not None:
            if confirm.replace(" ", "") != fingerprint:
                raise ValueError("fingerprint does not match; identity remains unverified")
            contact["verified"] = True
            with self.vault.transaction() as db:
                put_contact(db, contact)
        return {"id": cid, "fingerprint": fingerprint, "verified": contact["verified"]}

    def send(self, cid: str, text: str) -> str:
        if not isinstance(text, str) or not 1 <= len(text.encode()) <= MAX_TEXT:
            raise ValueError("message must contain 1..8192 UTF-8 bytes")
        contact = self.contact(cid)
        if contact["state"] != "active" or not contact["verified"]:
            raise ValueError("accept contact and verify its fingerprint out of band before sending")
        with self.vault.transaction() as db:
            mid = self._prepare(db, contact, "text", text)
            db.execute(
                "INSERT INTO messages VALUES (?,?, 'out',?, 'queued',?)",
                (cid, mid, text, int(time.time())),
            )
        self.flush(cid)
        return mid

    def flush(self, cid: str | None = None) -> None:
        rows = self.vault.db.execute(
            "SELECT contact,id,wire,attempts FROM outbox "
            "WHERE state IN ('queued','acceptance_unknown') "
            "AND attempts<? AND next_attempt<=? AND (? IS NULL OR contact=?) LIMIT 8",
            (MAX_ATTEMPTS, time.time(), cid, cid),
        ).fetchall()
        for target, mid, wire, attempts in rows:
            contact = self.contact(target)
            remote = contact["outgoing"]
            if remote is None:
                continue
            client = self.clients.setdefault(
                target, Client(Server.parse(remote["server"]), self.network)
            )
            state = "queued"
            try:
                if client.transport is None:
                    client.connect()
                with self.vault.transaction() as db:
                    db.execute(
                        "UPDATE outbox SET state='acceptance_unknown',attempts=attempts+1,"
                        "next_attempt=? WHERE contact=? AND id=?",
                        (time.time() + 2 ** (attempts + 1), target, mid),
                    )
                    db.execute(
                        "UPDATE messages SET status='acceptance_unknown' WHERE contact=? AND id=?",
                        (target, mid),
                    )
                state = "acceptance_unknown"
                client.send_ciphertext(
                    unb64(remote["sender_id"]),
                    wire,
                    ed25519.Ed25519PrivateKey.from_private_bytes(unb64(contact["sender_private"])),
                )
                state = "server_accepted"
            except RouterError:
                state = "rejected"
            except AmbiguousSendError:
                pass
            except (OSError, EOFError, SSL.Error):
                client.close()
                if state == "queued":
                    with self.vault.transaction() as db:
                        db.execute(
                            "UPDATE outbox SET attempts=attempts+1,next_attempt=? "
                            "WHERE contact=? AND id=?",
                            (time.time() + 2 ** (attempts + 1), target, mid),
                        )
            with self.vault.transaction() as db:
                db.execute(
                    "UPDATE outbox SET state=? WHERE contact=? AND id=?", (state, target, mid)
                )
                db.execute(
                    "UPDATE messages SET status=? WHERE contact=? AND id=?", (state, target, mid)
                )

    def receive(self, cid: str, delivery) -> dict:
        contact = self.contact(cid)
        if contact["state"] == "deleting":
            raise ValueError("contact pending deletion cannot receive messages")
        digest = hashlib.sha256(delivery.ciphertext).digest()
        stored = self.vault.db.execute(
            "SELECT app_id,kind FROM received_packets WHERE contact=? AND digest=?", (cid, digest)
        ).fetchone()
        if stored:
            self.vault.record_delivery("pm2:" + cid, delivery)
            return {"id": cid, "event": "duplicate", "message_id": stored[0]}
        sender, message_type, ciphertext = packets.unpack(delivery.ciphertext)
        old = contact["native"]
        result = operation(
            "decrypt",
            state=old,
            peer_address=sender,
            message_type=message_type,
            ciphertext=list(ciphertext),
        )
        try:
            envelope = json.loads(bytes(result["plaintext"]))
        except (ValueError, RecursionError) as exc:
            raise ValueError("invalid encrypted application envelope") from exc
        if (
            not isinstance(envelope, dict)
            or set(envelope) != {"v", "suite", "conversation", "id", "from", "to", "kind", "body"}
            or envelope["v"] != 2
            or envelope["suite"] != SUITE
            or (
                envelope["conversation"] != contact["conversation"]
                or envelope["from"] != sender
                or envelope["to"] != old["local_address"]
            )
        ):
            raise ValueError("authenticated conversation/header context mismatch")
        mid, kind, body = envelope["id"], envelope["kind"], envelope["body"]
        if not isinstance(mid, str) or len(unb64(mid)) != 32:
            raise ValueError("invalid authenticated message identifier")
        if self.vault.db.execute(
            "SELECT 1 FROM received_packets WHERE contact=? AND app_id=?", (cid, mid)
        ).fetchone():
            raise ValueError("conflicting authenticated application ID")
        contact["native"] = result["state"]
        with self.vault.transaction() as db:
            previous = db.execute(
                "SELECT timestamp,ciphertext FROM deliveries WHERE queue=? AND message_id=?",
                ("pm2:" + cid, delivery.message_id),
            ).fetchone()
            if previous is not None and previous != (delivery.timestamp, delivery.ciphertext):
                raise VaultError("router reused delivery ID with changed contents")
            if kind == "request":
                if contact["state"] != "invited" or contact["expires"] <= time.time():
                    raise ValueError("invitation expired or already consumed")
                if (
                    not isinstance(body, dict)
                    or set(body) != {"name", "route"}
                    or (not isinstance(body["name"], str) or len(body["name"].encode()) > 256)
                ):
                    raise ValueError("invalid request")
                remote = body["route"]
                if not isinstance(remote, dict) or set(remote) != {"server", "sender_id"}:
                    raise ValueError("invalid peer return route")
                contact.update(
                    outgoing=route(remote["server"], remote["sender_id"]),
                    name=body["name"],
                    state="requested",
                    request_id=mid,
                )
            elif kind == "accept":
                if (
                    contact["state"] != "waiting"
                    or not isinstance(body, dict)
                    or set(body) != {"request_id", "name"}
                    or body["request_id"] != contact["request_id"]
                    or not isinstance(body["name"], str)
                    or len(body["name"].encode()) > 256
                ):
                    raise ValueError("unexpected contact acceptance")
                contact["state"] = "active"
                contact["name"] = contact["name"] or body["name"]
                db.execute(
                    "UPDATE outbox SET state='recipient_received' WHERE contact=? AND id=?",
                    (cid, contact["request_id"]),
                )
                self._prepare(db, contact, "receipt", {"message_id": mid})
            elif kind == "text":
                if contact["state"] != "active" or not contact["verified"]:
                    raise ValueError("unverified contact cannot deliver application text")
                if not isinstance(body, str) or not 1 <= len(body.encode()) <= MAX_TEXT:
                    raise ValueError("invalid message text")
                db.execute(
                    "INSERT INTO messages VALUES (?,?, 'in',?, 'received',?)",
                    (cid, mid, body, int(time.time())),
                )
                self._prepare(db, contact, "receipt", {"message_id": mid})
            elif kind == "receipt":
                if not isinstance(body, dict) or set(body) != {"message_id"}:
                    raise ValueError("invalid delivery receipt")
                referenced = body["message_id"]
                if not isinstance(referenced, str) or len(unb64(referenced)) != 32:
                    raise ValueError("invalid receipt message identifier")
                if (
                    db.execute(
                        "UPDATE outbox SET state='recipient_received' WHERE contact=? AND id=?",
                        (cid, referenced),
                    ).rowcount
                    != 1
                ):
                    raise ValueError("receipt for an unknown outgoing message")
                db.execute(
                    "UPDATE messages SET status='recipient_received' WHERE contact=? AND id=?",
                    (cid, referenced),
                )
            else:
                raise ValueError("unknown authenticated application message type")
            put_contact(db, contact)
            db.execute("INSERT INTO received_packets VALUES (?,?,?,?)", (cid, digest, mid, kind))
            db.execute(
                "INSERT OR IGNORE INTO deliveries VALUES (?,?,?,?, 'stored')",
                ("pm2:" + cid, delivery.message_id, delivery.timestamp, delivery.ciphertext),
            )
        return {"id": cid, "event": kind, "message_id": mid, "body": body}

    def history(self, cid: str) -> list[dict]:
        self.contact(cid)
        return [
            dict(zip(("id", "direction", "body", "status", "created"), row, strict=True))
            for row in self.vault.db.execute(
                "SELECT id,direction,body,status,created FROM messages "
                "WHERE contact=? ORDER BY rowid",
                (cid,),
            )
        ]
