from pathlib import Path

import pytest

from private_messenger.identity import register
from private_messenger.smp.queues import Delivery
from private_messenger.storage.vault import Vault, VaultError


@pytest.fixture
def directory(tmp_path):
    path = tmp_path / "private"
    path.mkdir(mode=0o700)
    return path


def test_identity_persistence_and_no_plaintext(directory):
    path = directory / "identity.vault"
    with Vault(path, "test passphrase", create=True) as vault:
        profile = register(vault, "Sensitive Local Name")
        with pytest.raises(ValueError):
            register(vault, "second")
    assert b"Sensitive Local Name" not in path.read_bytes()
    assert b"SQLite format" not in path.read_bytes()
    assert path.stat().st_mode & 0o777 == 0o600
    with Vault(path, "test passphrase") as vault:
        assert vault.get("identity")["local_id"] == profile["local_id"]


def test_recovery_and_deduplication(directory):
    path = directory / "state.vault"
    delivery = Delivery(bytes(24), 123, False, b"opaque ciphertext")
    with Vault(path, "test", create=True) as vault:
        assert vault.record_delivery("q", delivery)
        assert not vault.record_delivery("q", delivery)
        vault.backup(directory / "backup.vault")
    Vault.restore(directory / "backup.vault", directory / "restored.vault", "test")
    with Vault(directory / "restored.vault", "test") as restored:
        assert not restored.record_delivery("q", delivery)
        restored.acknowledged("q", bytes(24))
        assert restored.db.execute("SELECT state FROM deliveries").fetchone() == ("acknowledged",)


def test_wrong_secret_tampering_and_lock(directory):
    path = directory / "test.vault"
    with Vault(path, "test", create=True):
        with pytest.raises(BlockingIOError):
            Vault(path, "test")
    with pytest.raises(VaultError):
        Vault(path, "wrong")
    data = path.read_bytes()
    path.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
    with pytest.raises(VaultError):
        Vault(path, "test")


def test_duplicate_id_with_changed_contents_is_rejected(directory):
    path = directory / "test.vault"
    with Vault(path, "test", create=True) as vault:
        vault.record_delivery("q", Delivery(bytes(24), 123, False, b"first ciphertext"))
        with pytest.raises(VaultError):
            vault.record_delivery("q", Delivery(bytes(24), 123, False, b"altered ciphertext"))
        assert vault.db.execute("SELECT ciphertext FROM deliveries").fetchone() == (
            b"first ciphertext",
        )


def test_atomic_failure_restores_memory(directory, monkeypatch):
    import private_messenger.storage.vault as module

    path = directory / "test.vault"
    with Vault(path, "test", create=True) as vault:
        before = path.read_bytes()

        def fail(*args, **kwargs):
            raise OSError("simulated storage failure")

        monkeypatch.setattr(module, "atomic_write", fail)
        with pytest.raises(OSError):
            vault.put("secret", "must not commit")
        assert vault.get("secret") is None
        assert path.read_bytes() == before


def test_reject_insecure_directory_and_symlink(directory):
    insecure = directory / "insecure"
    insecure.mkdir(mode=0o755)
    with pytest.raises(VaultError):
        Vault(insecure / "state.vault", "test", create=True)
    path = directory / "state.vault"
    path.symlink_to(Path("/dev/null"))
    with pytest.raises(OSError):
        Vault(path, "test")
