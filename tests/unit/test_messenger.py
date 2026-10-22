"""Application state tests: mocked relay, real native crypto and encrypted vault.

These tests are NOT evidence of SMP/public-server interoperability.
"""

import copy
import secrets
import time
from contextlib import ExitStack

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

pytest.importorskip("private_messenger._crypto_native", reason="build native crypto")

from private_messenger.config import b64, unb64
from private_messenger.identity import register
from private_messenger.messaging.service import Messenger
from private_messenger.smp.client import AmbiguousSendError
from private_messenger.smp.queues import Delivery, ReceiveQueue
from private_messenger.storage.vault import Vault


@pytest.fixture
def application_pair(tmp_path, monkeypatch):
    queues = {}
    server = f"smp://{b64(secrets.token_bytes(32))}@reference.invalid:5223"

    class FakeClient:
        def __init__(self, server, network=None):
            self.transport = None

        def connect(self):
            self.transport = True
            return self

        def close(self):
            self.transport = None

        def __enter__(self):
            return self.connect()

        def __exit__(self, *_):
            self.close()

        def create_queue(self, **kwargs):
            key = ReceiveQueue(
                secrets.token_bytes(24),
                secrets.token_bytes(24),
                ed25519.Ed25519PrivateKey.generate(),
                x25519.X25519PrivateKey.generate(),
                x25519.X25519PrivateKey.generate().public_key(),
                True,
            )
            queues[key.sender_id] = {"messages": [], "sender": None}
            return key

        def secure_sender(self, sid, key):
            queues[sid]["sender"] = key.public_key().public_bytes_raw()

        def send_ciphertext(self, sid, wire, key):
            assert key.public_key().public_bytes_raw() == queues[sid]["sender"]
            queues[sid]["messages"].append(
                Delivery(secrets.token_bytes(24), int(time.time()), False, wire)
            )

        def delete_queue(self, key):
            del queues[key.sender_id]

    monkeypatch.setattr("private_messenger.messaging.service.Client", FakeClient)
    with ExitStack() as stack:
        alice_vault = stack.enter_context(
            Vault(tmp_path / "a/alice.vault", "Alice password", create=True)
        )
        bob_vault = stack.enter_context(
            Vault(tmp_path / "b/bob.vault", "Bob password", create=True)
        )
        for vault, name in ((alice_vault, "Alice"), (bob_vault, "Bob")):
            register(vault, name)
            vault.put("servers", [server])
        alice = stack.enter_context(Messenger(alice_vault))
        bob = stack.enter_context(Messenger(bob_vault))

        def deliver(service, cid):
            sid = unb64(service.contact(cid)["receive"]["sender_id"])
            item = queues[sid]["messages"].pop(0)
            return item, service.receive(cid, item)

        yield alice, bob, queues, deliver, FakeClient


def connect(pair):
    alice, bob, _, deliver, _ = pair
    invitation = bob.address()
    aid = alice.connect(invitation["invitation"])
    bid = invitation["id"]
    assert deliver(bob, bid)[1]["event"] == "request"
    with pytest.raises(ValueError, match="verify"):
        alice.send(aid, "not yet allowed")
    bob.accept(bid)
    assert deliver(alice, aid)[1]["event"] == "accept"
    alice.flush()
    assert deliver(bob, bid)[1]["event"] == "receipt"
    a_fingerprint = alice.fingerprint(aid)["fingerprint"]
    assert bob.fingerprint(bid)["fingerprint"] == a_fingerprint
    alice.fingerprint(aid, a_fingerprint)
    bob.fingerprint(bid, a_fingerprint)
    return aid, bid


def test_remote_invitation_acceptance_unicode_and_authenticated_receipt(application_pair):
    alice, bob, _, deliver, _ = application_pair
    aid, bid = connect(application_pair)
    mid = alice.send(aid, "Žluťoučký kůň 🐴")
    assert alice.history(aid)[0]["status"] == "server_accepted"
    assert deliver(bob, bid)[1]["body"] == "Žluťoučký kůň 🐴"
    bob.flush()
    assert deliver(alice, aid)[1]["event"] == "receipt"
    assert alice.history(aid)[0]["id"] == mid
    assert alice.history(aid)[0]["status"] == "recipient_received"
    assert bob.history(bid)[0]["status"] == "received"


def test_replay_new_router_id_does_not_advance_ratchet_or_duplicate_history(application_pair):
    alice, bob, _, deliver, _ = application_pair
    aid, bid = connect(application_pair)
    alice.send(aid, "one insertion")
    item, _ = deliver(bob, bid)
    state = copy.deepcopy(bob.contact(bid)["native"])
    replay = Delivery(secrets.token_bytes(24), item.timestamp + 1, False, item.ciphertext)
    assert bob.receive(bid, replay)["event"] == "duplicate"
    assert bob.contact(bid)["native"] == state
    assert len(bob.history(bid)) == 1


def test_decrypt_and_receipt_state_roll_back_together_on_disk_failure(
    application_pair, monkeypatch
):
    alice, bob, queues, deliver, _ = application_pair
    aid, bid = connect(application_pair)
    alice.send(aid, "safe transaction")
    sid = unb64(bob.contact(bid)["receive"]["sender_id"])
    item = queues[sid]["messages"].pop(0)
    before = bob.contact(bid)
    snapshot = bob.vault.path.read_bytes()
    from private_messenger.storage import vault as storage

    real_write = storage.atomic_write

    def fail(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(storage, "atomic_write", fail)
    with pytest.raises(OSError, match="disk full"):
        bob.receive(bid, item)
    assert bob.contact(bid) == before
    assert bob.history(bid) == []
    assert bob.vault.path.read_bytes() == snapshot
    monkeypatch.setattr(storage, "atomic_write", real_write)
    assert bob.receive(bid, item)["event"] == "text"
    assert len(bob.history(bid)) == 1


def test_ambiguous_send_retries_identical_packet_and_recipient_deduplicates(
    application_pair, monkeypatch
):
    alice, bob, queues, deliver, fake = application_pair
    aid, bid = connect(application_pair)
    real_send = fake.send_ciphertext
    calls = []

    def uncertain(self, sid, wire, key):
        real_send(self, sid, wire, key)
        calls.append(wire)
        if len(calls) == 1:
            self.close()
            raise AmbiguousSendError("simulated connection loss after server acceptance")

    monkeypatch.setattr(fake, "send_ciphertext", uncertain)
    alice.send(aid, "same opaque retry")
    assert alice.history(aid)[0]["status"] == "acceptance_unknown"
    with alice.vault.transaction() as db:
        db.execute("UPDATE outbox SET next_attempt=0 WHERE contact=?", (aid,))
    alice.flush()
    assert calls[0] == calls[1]
    assert deliver(bob, bid)[1]["event"] == "text"
    assert deliver(bob, bid)[1]["event"] == "duplicate"
    assert len(bob.history(bid)) == 1


def test_fingerprint_mismatch_and_tampering_leave_contact_state_unchanged(application_pair):
    alice, bob, queues, _, _ = application_pair
    aid, bid = connect(application_pair)
    with pytest.raises(ValueError, match="fingerprint"):
        alice.fingerprint(aid, "0" * 60)
    alice.send(aid, "authenticate before committing")
    sid = unb64(bob.contact(bid)["receive"]["sender_id"])
    item = queues[sid]["messages"].pop(0)
    wire = item.ciphertext[:-1] + bytes([item.ciphertext[-1] ^ 1])
    before = bob.contact(bid)
    with pytest.raises(ValueError):
        bob.receive(bid, Delivery(item.message_id, item.timestamp, False, wire))
    assert bob.contact(bid) == before
    assert bob.history(bid) == []


def test_backup_restore_blocks_old_ratchets_but_preserves_history(application_pair, tmp_path):
    alice, bob, _, deliver, _ = application_pair
    aid, bid = connect(application_pair)
    alice.send(aid, "retained history")
    deliver(bob, bid)
    backup = tmp_path / "backups/bob.vault"
    bob.vault.backup(backup)
    restored_path = tmp_path / "recovered/bob.vault"
    Vault.restore(backup, restored_path, "Bob password")
    with Vault(restored_path, "Bob password") as recovered, Messenger(recovered) as messenger:
        assert messenger.contact(bid)["state"] == "recovery_required"
        assert messenger.contact(bid)["native"] is None
        assert messenger.history(bid)[0]["body"] == "retained history"
        with pytest.raises(ValueError):
            messenger.send(bid, "never reuse an old ratchet state")
        assert messenger.address()["invitation"].startswith("PMS2:")
    with Vault(backup, "Bob password") as original:
        assert original.get("restore_requires_repair") is None
