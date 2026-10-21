"""Same-computer, locally paired text demo. NOT a replacement session protocol.

Keys are provisioned out of band by the local setup, never established over SMP.
Payloads use PyNaCl Box directly (Curve25519/XSalsa20-Poly1305), with its random
24-byte nonces. There is no ratchet, hybrid KEX, remote invitation, PFS or PCS.
"""

import fcntl
import json
import os
import secrets
import time
import unicodedata
from contextlib import ExitStack
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519
from nacl.public import Box, PrivateKey, PublicKey
from OpenSSL import SSL

from private_messenger.config import Server, b64, unb64
from private_messenger.identity import register
from private_messenger.smp.client import Client
from private_messenger.storage.vault import (
    Vault,
    VaultError,
    atomic_write,
    private_dir,
    read_private,
)

ROLES = ("Alice", "Bob")
MAX_TEXT_BYTES = 8192
FORMAT = "private-messenger-local-terminal-demo-v1"
READY = b"private-messenger-local-pair-v1\n"
SCHEMA = """
CREATE TABLE IF NOT EXISTS demo_messages (
 id TEXT PRIMARY KEY, direction TEXT NOT NULL CHECK(direction IN ('in','out')),
 text TEXT NOT NULL, ciphertext BLOB NOT NULL, state TEXT NOT NULL,
 created INTEGER NOT NULL
);
"""


def profile_path(directory: Path, role: str) -> Path:
    if role not in ROLES:
        raise ValueError("choose Alice or Bob")
    return directory / f"{role.lower()}.vault"


def is_ready(directory: Path) -> bool:
    marker = directory / "pair.ready"
    if not marker.exists():
        return False
    if read_private(marker, 128) != READY:
        raise VaultError("invalid local pairing marker")
    if not all(profile_path(directory, role).is_file() for role in ROLES):
        raise VaultError("local pairing is incomplete")
    return True


def provision(directory: Path, secret: str, server: Server, basic_auth: bytes | None) -> None:
    """Prepare both demo profiles locally; secure queues before either can chat.

    No remote identity-authentication protocol is simulated. Local setup is the
    trust anchor; both profiles intentionally use one user-supplied test password.
    """
    private_dir(directory)
    if not secret:
        raise VaultError("empty passphrase is forbidden")
    lock_path = directory / "setup.lock"
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "r+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if is_ready(directory):
            return
        if any(profile_path(directory, role).exists() for role in ROLES):
            raise VaultError("incomplete previous setup; preserve its vaults for queue recovery")
        pair_id = b64(secrets.token_bytes(32))
        payload_keys = {role: PrivateKey.generate() for role in ROLES}
        sender_keys = {role: ed25519.Ed25519PrivateKey.generate() for role in ROLES}
        created_queues = []
        created_files = []
        cleanup_ok = True
        try:
            with ExitStack() as stack:
                vaults = {}
                for role in ROLES:
                    path = profile_path(directory, role)
                    vaults[role] = stack.enter_context(Vault(path, secret, create=True))
                    created_files.append(path)
                    register(vaults[role], role)
                with Client(server) as client:
                    profiles = {}
                    for role in ROLES:
                        peer = "Bob" if role == "Alice" else "Alice"
                        incoming = client.create_queue(basic_auth=basic_auth)
                        created_queues.append(incoming)
                        profiles[role] = {
                            "format": FORMAT,
                            "role": role,
                            "peer": peer,
                            "conversation": pair_id,
                            "server": server.uri,
                            "receive": incoming.export(),
                            "payload_private": b64(bytes(payload_keys[role])),
                            "peer_public": b64(bytes(payload_keys[peer].public_key)),
                            "sender_private": b64(sender_keys[role].private_bytes_raw()),
                        }
                        # Keep recovery credentials encrypted even if setup is interrupted.
                        vaults[role].put("terminal_demo", profiles[role])
                    for role in ROLES:
                        peer = profiles[role]["peer"]
                        outgoing = profiles[peer]["receive"]["sender_id"]
                        profiles[role]["send_id"] = outgoing
                        vaults[role].put("terminal_demo", profiles[role])
                        client.secure_sender(unb64(outgoing), sender_keys[role])
                atomic_write(directory / "pair.ready", READY, overwrite=False)
        except BaseException:
            # Best effort cleanup; retain encrypted recovery credentials if deletion fails.
            for incoming in created_queues:
                try:
                    with Client(server) as client:
                        client.delete_queue(incoming)
                except (ValueError, OSError, EOFError, SSL.Error):
                    cleanup_ok = False
            if cleanup_ok:
                for path in created_files:
                    path.unlink(missing_ok=True)
            raise


def safe_terminal(text: str) -> str:
    """Never execute sender-controlled terminal escapes or bidi format controls."""
    return "".join(
        f"\\u{ord(char):04x}" if unicodedata.category(char).startswith("C") else char
        for char in text
    )


class DemoMessages:
    def __init__(self, vault: Vault, role: str):
        self.vault = vault
        self.profile = vault.get("terminal_demo")
        if (
            self.profile is None
            or self.profile["format"] != FORMAT
            or self.profile["role"] != role
            or self.profile["peer"] != ("Bob" if role == "Alice" else "Alice")
        ):
            raise VaultError("invalid local demo profile")
        self.box = Box(
            PrivateKey(unb64(self.profile["payload_private"])),
            PublicKey(unb64(self.profile["peer_public"])),
        )
        # No hidden plaintext database or sidecar; schema and history are in the vault.
        with vault.transaction() as db:
            db.execute(SCHEMA)

    @staticmethod
    def validate_text(text: str) -> None:
        if not isinstance(text, str) or not 1 <= len(text.encode("utf-8")) <= MAX_TEXT_BYTES:
            raise ValueError("message must contain 1..8192 UTF-8 bytes")

    def prepare(self, text: str) -> tuple[str, bytes]:
        self.validate_text(text)
        mid = b64(secrets.token_bytes(32))
        envelope = {
            "format": FORMAT,
            "conversation": self.profile["conversation"],
            "from": self.profile["role"],
            "to": self.profile["peer"],
            "id": mid,
            "text": text,
        }
        ciphertext = bytes(self.box.encrypt(json.dumps(envelope, ensure_ascii=False).encode()))
        if len(ciphertext) > 16048:
            raise ValueError("message exceeds SMP payload limit")
        with self.vault.transaction() as db:
            db.execute(
                "INSERT INTO demo_messages VALUES (?,?,?,?,?,?)",
                (mid, "out", text, ciphertext, "not_sent", int(time.time())),
            )
        return mid, ciphertext

    def outgoing_state(self, mid: str, state: str) -> None:
        if state not in ("acceptance_unknown", "server_accepted", "rejected"):
            raise ValueError("invalid send state")
        with self.vault.transaction() as db:
            if (
                db.execute(
                    "UPDATE demo_messages SET state=? WHERE id=? AND direction='out'", (state, mid)
                ).rowcount
                != 1
            ):
                raise VaultError("unknown outgoing message")

    def receive(self, delivery) -> tuple[bool, str]:
        ciphertext = delivery.ciphertext
        if not 40 <= len(ciphertext) <= 16048:
            raise ValueError("invalid demo ciphertext size")
        envelope = json.loads(self.box.decrypt(ciphertext))
        if not isinstance(envelope, dict) or set(envelope) != {
            "format",
            "conversation",
            "from",
            "to",
            "id",
            "text",
        }:
            raise ValueError("invalid demo envelope")
        if (
            envelope["format"] != FORMAT
            or envelope["conversation"] != self.profile["conversation"]
            or envelope["from"] != self.profile["peer"]
            or envelope["to"] != self.profile["role"]
            or not isinstance(envelope["id"], str)
            or len(unb64(envelope["id"])) != 32
        ):
            raise ValueError("invalid demo conversation context")
        self.validate_text(envelope["text"])
        with self.vault.transaction() as db:
            old = db.execute(
                "SELECT timestamp,ciphertext FROM deliveries WHERE queue=? AND message_id=?",
                ("terminal-demo", delivery.message_id),
            ).fetchone()
            if old is not None and old != (delivery.timestamp, ciphertext):
                raise VaultError("router reused message ID with changed contents")
            seen = db.execute(
                "SELECT direction,ciphertext FROM demo_messages WHERE id=?", (envelope["id"],)
            ).fetchone()
            if seen is not None and seen != ("in", ciphertext):
                raise VaultError("conflicting authenticated application message ID")
            fresh = seen is None
            if fresh:
                db.execute(
                    "INSERT INTO demo_messages VALUES (?,?,?,?,?,?)",
                    (
                        envelope["id"],
                        "in",
                        envelope["text"],
                        ciphertext,
                        "received",
                        int(time.time()),
                    ),
                )
            db.execute(
                "INSERT OR IGNORE INTO deliveries VALUES (?,?,?,?, 'stored')",
                ("terminal-demo", delivery.message_id, delivery.timestamp, ciphertext),
            )
        # Caller must not ACK until the authenticated message/history transaction persists.
        return fresh, envelope["text"]

    def history(self, limit: int = 20) -> list:
        return self.vault.db.execute(
            "SELECT direction,text,state FROM "
            "(SELECT rowid,direction,text,state FROM demo_messages ORDER BY rowid DESC LIMIT ?) "
            "ORDER BY rowid",
            (limit,),
        ).fetchall()
