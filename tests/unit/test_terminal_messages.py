import json
import secrets

import pytest
from nacl.exceptions import CryptoError
from nacl.public import Box, PrivateKey, PublicKey

from private_messenger.config import b64, unb64
from private_messenger.messaging.local_demo import FORMAT, DemoMessages, safe_terminal
from private_messenger.smp.queues import Delivery
from private_messenger.storage.vault import Vault, VaultError


@pytest.fixture
def pair(tmp_path):
    keys = {role: PrivateKey.generate() for role in ("Alice", "Bob")}
    vaults = {}
    try:
        for role, peer in (("Alice", "Bob"), ("Bob", "Alice")):
            vault = vaults[role] = Vault(tmp_path / f"{role}.vault", "test secret", create=True)
            vault.put(
                "terminal_demo",
                {
                    "format": FORMAT,
                    "role": role,
                    "peer": peer,
                    "conversation": "fixture-pair",
                    "payload_private": b64(bytes(keys[role])),
                    "peer_public": b64(bytes(keys[peer].public_key)),
                },
            )
        yield {role: DemoMessages(vault, role) for role, vault in vaults.items()}
    finally:
        for vault in vaults.values():
            vault.close()


def delivery(ciphertext, mid=None, timestamp=1234):
    return Delivery(mid or secrets.token_bytes(24), timestamp, False, ciphertext)


def test_bidirectional_unicode_and_out_of_order(pair):
    alice, bob = pair["Alice"], pair["Bob"]
    first = alice.prepare("Ahoj Bobe, žluťoučký kůň 🐴")[1]
    second = alice.prepare("druhá zpráva")[1]
    assert bob.receive(delivery(second)) == (True, "druhá zpráva")
    assert bob.receive(delivery(first)) == (True, "Ahoj Bobe, žluťoučký kůň 🐴")
    reply = bob.prepare("Ahoj Alice!")[1]
    assert alice.receive(delivery(reply)) == (True, "Ahoj Alice!")
    assert b"druh" not in bob.vault.path.read_bytes()


def test_replay_under_new_router_id_and_conflicts(pair):
    alice, bob = pair["Alice"], pair["Bob"]
    ciphertext = alice.prepare("only once")[1]
    original = delivery(ciphertext)
    assert bob.receive(original)[0]
    assert not bob.receive(original)[0]
    assert not bob.receive(delivery(ciphertext))[0]  # malicious router republishes under a new ID
    assert len(bob.history()) == 1
    other = alice.prepare("different")[1]
    with pytest.raises(VaultError, match="router reused"):
        bob.receive(delivery(other, mid=original.message_id))
    envelope = json.loads(alice.box.decrypt(ciphertext))
    envelope["text"] = "changed but same authenticated application ID"
    conflicting = bytes(alice.box.encrypt(json.dumps(envelope).encode()))
    with pytest.raises(VaultError, match="conflicting authenticated"):
        bob.receive(delivery(conflicting))
    assert len(bob.history()) == 1


def test_ciphertext_tampering_reflection_and_context(pair):
    alice, bob = pair["Alice"], pair["Bob"]
    ciphertext = alice.prepare("secret payload")[1]
    altered = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])
    with pytest.raises(CryptoError):
        bob.receive(delivery(altered))
    with pytest.raises(ValueError, match="context"):
        alice.receive(delivery(ciphertext))  # reflect Alice's valid ciphertext back at her
    envelope = json.loads(alice.box.decrypt(ciphertext))
    envelope["conversation"] = "another-pair"
    with pytest.raises(ValueError, match="context"):
        bob.receive(delivery(bytes(alice.box.encrypt(json.dumps(envelope).encode()))))
    assert not bob.history()
    assert not bob.vault.db.execute("SELECT * FROM deliveries").fetchall()


def test_restore_history_replays_and_authenticated_persistence(pair):
    bob = pair["Bob"]
    item = delivery(pair["Alice"].prepare("survives restart")[1])
    bob.receive(item)
    path = bob.vault.path
    bob.vault.close()
    with Vault(path, "test secret") as restored:
        restored_messages = DemoMessages(restored, "Bob")
        assert restored_messages.history() == [("in", "survives restart", "received")]
        assert not restored_messages.receive(delivery(item.ciphertext))[0]


def test_failed_snapshot_does_not_commit_or_ack(pair, monkeypatch):
    bob = pair["Bob"]
    item = delivery(pair["Alice"].prepare("durable before ACK")[1])

    def fail(*args, **kwargs):
        raise OSError("simulated disk failure")

    monkeypatch.setattr("private_messenger.storage.vault.atomic_write", fail)
    with pytest.raises(OSError, match="disk failure"):
        bob.receive(item)
    assert bob.history() == []
    assert bob.vault.db.execute("SELECT count(*) FROM deliveries").fetchone() == (0,)


def test_standard_box_interoperability_and_size_bounds(pair):
    alice, bob = pair["Alice"], pair["Bob"]
    _, ciphertext = alice.prepare("x" * 8192)
    independent_box = Box(
        PrivateKey(unb64(bob.profile["payload_private"])),
        PublicKey(unb64(bob.profile["peer_public"])),
    )
    assert json.loads(independent_box.decrypt(ciphertext))["text"] == "x" * 8192
    with pytest.raises(ValueError):
        alice.prepare("x" * 8193)
    with pytest.raises(ValueError):
        alice.prepare("🐴" * 2049)
    assert len(ciphertext) <= 16048


def test_terminal_control_characters_are_never_executed():
    assert safe_terminal("ahoj\x1b[2J\n\u202etest") == "ahoj\\u001b[2J\\u000a\\u202etest"
