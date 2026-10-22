"""SQLite runs only in RAM; disk contains an XChaCha20-Poly1305 sealed snapshot.

An exclusive process lock and atomic fsync/replace serialize writers. This protects
against record tampering, not rollback of the entire vault by a storage attacker.
"""

import fcntl
import json
import os
import secrets
import sqlite3
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
)
from nacl.exceptions import CryptoError

MAGIC = b"PMSVAULT\x01"
MAX_VAULT_SIZE = 64 * 1024 * 1024
SCHEMA = """
PRAGMA user_version=1;
CREATE TABLE state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE deliveries (
 queue TEXT NOT NULL, message_id BLOB NOT NULL, timestamp INTEGER NOT NULL,
 ciphertext BLOB NOT NULL, state TEXT NOT NULL CHECK(state IN ('stored','acknowledged')),
 PRIMARY KEY(queue, message_id)
);
"""


class VaultError(ValueError):
    """Vault authentication, format or integrity failure."""


def read_private(path: Path, max_size: int = MAX_VAULT_SIZE) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
            or info.st_size > max_size
        ):
            raise VaultError("private file must be owned by this user, mode 0600, bounded size")
        return stream.read(max_size + 1)


def private_dir(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise VaultError("vault directory must be owned by this user with mode 0700")


def atomic_write(path: Path, data: bytes, *, overwrite: bool = True) -> None:
    private_dir(path.parent)
    fd, temp = tempfile.mkstemp(prefix=".sealed-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if overwrite:
            os.replace(temp, path)
        else:
            os.link(temp, path)  # fails if target already exists
            os.unlink(temp)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def derive(secret: str, salt: bytes) -> bytes:
    if not secret:
        raise VaultError("empty passphrase is forbidden")
    return hash_secret_raw(
        secret.encode("utf-8"),
        salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=1,
        hash_len=32,
        type=Type.ID,
    )


class Vault:
    def __init__(self, path: Path, passphrase: str, *, create: bool = False):
        self.path = path
        self.db = None
        self.key = None
        private_dir(path.parent)
        lock_fd = os.open(str(path) + ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        self.lock = os.fdopen(lock_fd, "r+b")
        try:
            info = os.fstat(lock_fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise VaultError("insecure vault lock")
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.db = sqlite3.connect(":memory:", isolation_level=None)
            if create:
                if path.exists():
                    raise FileExistsError(path)
                self.salt = secrets.token_bytes(16)
                self.key = derive(passphrase, self.salt)
                self.db.executescript(SCHEMA)
                atomic_write(path, self._seal(), overwrite=False)
            else:
                blob = read_private(path)
                if not blob.startswith(MAGIC) or len(blob) < len(MAGIC) + 16 + 24 + 16:
                    raise VaultError("invalid vault format")
                self.salt = blob[len(MAGIC) : len(MAGIC) + 16]
                self.key = derive(passphrase, self.salt)
                header = blob[: len(MAGIC) + 16]
                nonce = blob[len(header) : len(header) + 24]
                try:
                    plain = crypto_aead_xchacha20poly1305_ietf_decrypt(
                        blob[len(header) + 24 :], header, nonce, self.key
                    )
                    self.db.deserialize(plain)
                    if self.db.execute("PRAGMA quick_check").fetchone() != (
                        "ok",
                    ) or self.db.execute("PRAGMA user_version").fetchone() != (1,):
                        raise VaultError("invalid database schema or integrity")
                    self.db.execute("SELECT key,value FROM state LIMIT 1")
                    self.db.execute("SELECT message_id FROM deliveries LIMIT 1")
                except (CryptoError, sqlite3.DatabaseError) as exc:
                    raise VaultError("wrong passphrase or damaged vault") from exc
            self.db.execute("PRAGMA trusted_schema=OFF")
            # Prevent superseded serialized ratchets lingering in SQLite free pages.
            # This does not wipe Python copies, older snapshots, backups or SSD cells.
            self.db.execute("PRAGMA secure_delete=ON")
        except BaseException:
            self.close()
            raise

    def _seal(self) -> bytes:
        header = MAGIC + self.salt
        nonce = secrets.token_bytes(24)
        plain = self.db.serialize()
        if len(plain) > MAX_VAULT_SIZE - 128:
            raise VaultError("vault size limit reached")
        return (
            header
            + nonce
            + crypto_aead_xchacha20poly1305_ietf_encrypt(plain, header, nonce, self.key)
        )

    @contextmanager
    def transaction(self):
        previous = self.db.serialize()
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield self.db
            self.db.execute("COMMIT")
            atomic_write(self.path, self._seal())
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            self.db.deserialize(previous)
            raise

    def get(self, key: str, default=None):
        row = self.db.execute("SELECT value FROM state WHERE key=?", (key,)).fetchone()
        return default if row is None else json.loads(row[0])

    def put(self, key: str, value) -> None:
        with self.transaction() as db:
            db.execute("INSERT OR REPLACE INTO state VALUES (?,?)", (key, json.dumps(value)))

    def record_delivery(self, queue: str, delivery) -> bool:
        # Caller may ACK only after this encrypted snapshot is durably stored.
        with self.transaction() as db:
            old = db.execute(
                "SELECT timestamp,ciphertext FROM deliveries WHERE queue=? AND message_id=?",
                (queue, delivery.message_id),
            ).fetchone()
            if old is not None and old != (delivery.timestamp, delivery.ciphertext):
                raise VaultError("router reused a message ID with different contents")
            cursor = db.execute(
                "INSERT OR IGNORE INTO deliveries VALUES (?,?,?,?, 'stored')",
                (queue, delivery.message_id, delivery.timestamp, delivery.ciphertext),
            )
            return cursor.rowcount == 1

    def acknowledged(self, queue: str, message_id: bytes) -> None:
        with self.transaction() as db:
            db.execute(
                "UPDATE deliveries SET state='acknowledged' WHERE queue=? AND message_id=?",
                (queue, message_id),
            )

    def backup(self, destination: Path) -> None:
        atomic_write(destination, self._seal(), overwrite=False)

    @staticmethod
    def restore(source: Path, destination: Path, passphrase: str) -> None:
        # Authenticate and structurally validate before making a new recovery file.
        with Vault(source, passphrase) as original:
            # Mark only the recovery snapshot in RAM; never change the source.
            # Old ratchet states must not resume after restoring a historical backup.
            original.db.execute(
                "INSERT OR REPLACE INTO state VALUES ('restore_requires_repair','true')"
            )
            original.backup(destination)

    def close(self) -> None:
        if self.db is not None:
            self.db.close()
            self.db = None
        self.key = None  # Best effort only: Python/OpenSSL copies cannot be zeroized reliably.
        self.lock.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
