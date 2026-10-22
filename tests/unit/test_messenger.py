"""Application state tests: mocked relay, real native crypto and encrypted vault.

These tests are NOT evidence of SMP/public-server interoperability.
"""

import copy
import io
import json
import queue
import secrets
import threading
import time
from contextlib import ExitStack

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

pytest.importorskip("private_messenger._crypto_native", reason="build native crypto")

from private_messenger.config import b64, unb64
from private_messenger.identity import register
from private_messenger.messaging.secure_terminal import chat_words
from private_messenger.messaging.service import Messenger
from private_messenger.messaging.terminal_ui import ChatUI
from private_messenger.smp.client import AmbiguousSendError, RouterError
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
            if key.sender_id not in queues:
                raise RouterError(b"ERR AUTH")
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


@pytest.mark.parametrize(
    "form", ["json_command", "json_paste", "quoted_json", "token", "token_command", "add", "named"]
)
def test_copied_invitation_export_connects_without_trusting_outer_metadata(application_pair, form):
    from private_messenger.cli import parser

    alice, bob, _, deliver, _ = application_pair
    exported = bob.address()
    bid = exported["id"]
    exported.update(id="untrusted-export-id", expires=0, verified=True)
    raw = json.dumps(exported)
    line = {
        "json_command": "connect " + raw,
        "json_paste": raw,
        "quoted_json": "connect '" + raw + "' --name Bob",
        "token": exported["invitation"],
        "token_command": "connect " + exported["invitation"],
        "add": "/add " + raw + " --name Bob",
        "named": "/add Bob " + exported["invitation"],
    }[form]
    args = parser().parse_args(chat_words(line))
    aid = alice.connect(args.invitation, args.name)
    assert aid != exported["id"]
    assert alice.contact(aid)["verified"] is False
    assert deliver(bob, bid)[1]["event"] == "request"
    bob.accept(bid)
    assert deliver(alice, aid)[1]["event"] == "accept"
    assert alice.fingerprint(aid)["fingerprint"] == bob.fingerprint(bid)["fingerprint"]
    with pytest.raises(ValueError, match="verify"):
        alice.send(aid, "outer metadata cannot authorize text")


@pytest.mark.parametrize(
    "value", ['{"invitation": 7}', '{"expires": 0}', '{"invitation":', "x" * 8193]
)
def test_bad_copied_export_creates_no_contact_or_router_queue(application_pair, value):
    alice, _, queues, _, _ = application_pair
    before = len(queues)
    with pytest.raises(ValueError):
        alice.connect(value)
    assert alice.all_contacts() == []
    assert len(queues) == before


def test_damaged_pasted_export_cannot_be_mistaken_for_text_to_another_contact():
    value = '{"expires": 0, "invitation": "PMS2:TRUNCATED"'
    assert chat_words(value) == ["connect", value]
    assert chat_words("connect " + value) == ["connect", value]


def test_guided_chat_pairing_verification_and_plain_text_without_internal_ids(application_pair):
    alice, bob, _, deliver, _ = application_pair
    alice_output, bob_output = [], []
    resumed = []
    a = ChatUI(alice, alice_output.append)
    b = ChatUI(bob, bob_output.append, on_verified=resumed.append)
    b.handle("/address")
    invitation_command = bob_output[-1]
    assert invitation_command.startswith("/add Bob PMS2:")
    a.handle(invitation_command)
    aid = a.selected
    bid = bob.all_contacts()[0]["id"]
    a.handle("Ahoj")
    assert alice.history(aid) == []
    assert "accept" in alice_output[-1]
    b.received(bid, deliver(bob, bid)[1])
    b.handle("/accept")
    a.received(aid, deliver(alice, aid)[1])
    assert a.label(aid) == "Bob"
    assert b.label(bid) == "Alice"
    b.handle("/accept")  # An already accepted contact gives guidance, without another packet.
    assert "verify" in bob_output[-1]
    a.handle("Ahoj")
    assert alice.history(aid) == []
    assert "verify" in alice_output[-1]
    a.handle("/verify Bob")
    b.handle("/verify")
    assert a.pending_verification[1] == b.pending_verification[1]
    a.handle("/no")
    assert not alice.contact(aid)["verified"]
    a.handle("/verify")
    a.handle("/yes")
    b.handle("/yes")
    assert alice.contact(aid)["verified"] and bob.contact(bid)["verified"]
    assert resumed == [bid]
    text = "Ahoj Bobe! \"Uvozovka a apostrof nejsou problém: don't 🐴"
    a.handle(text)
    assert alice.history(aid)[0]["body"] == text
    # Acceptance receipt can precede application text in Bob's queue.
    event = deliver(bob, bid)[1]
    if event["event"] == "receipt":
        event = deliver(bob, bid)[1]
    assert event["body"] == text
    b.received(bid, event)
    assert text in bob_output[-1]
    assert "waiting for recipient confirmation" in alice_output[-1]
    assert not any(line.startswith('{"') for line in alice_output + bob_output)
    # A single existing contact remains usable immediately after restarting the UI.
    restarted = ChatUI(bob, bob_output.append)
    restarted.handle("Ahoj Alice, odpověď po přihlášení")
    assert bob.history(bid)[-1]["direction"] == "out"
    assert restarted.selected == bid


def test_chat_rejects_ambiguous_names_and_does_not_retarget_verification(application_pair):
    from private_messenger.messaging.service import put_contact

    alice, _, _, _, _ = application_pair
    aid, _ = connect(application_pair)
    duplicate = copy.deepcopy(alice.contact(aid))
    duplicate.update(id=secrets.token_hex(8), verified=False, name="Bob")
    original = alice.contact(aid)
    original.update(verified=False)
    with alice.vault.transaction() as db:
        put_contact(db, original)
        put_contact(db, duplicate)
    ui = ChatUI(alice, lambda text: None)
    with pytest.raises(ValueError, match="specific contact"):
        ui.handle("/verify Bob")
    with pytest.raises(ValueError, match="specific contact"):
        ui.handle("/accept Bob")
    with pytest.raises(ValueError, match="specific contact"):
        ui.handle("Ahoj")
    ui.handle("/verify " + aid)
    ui.handle("/chat " + duplicate["id"])
    assert ui.pending_verification is None
    # A stale 'yes' after selecting someone else cannot verify either contact.
    with pytest.raises(ValueError, match="/verify"):
        ui.handle("/yes")
    assert not alice.contact(aid)["verified"]
    assert not alice.contact(duplicate["id"])["verified"]
    assert alice.history(aid) == []
    assert alice.history(duplicate["id"]) == []


def test_chat_parser_errors_are_short_and_damaged_exports_are_never_sent(application_pair):
    alice, _, _, _, _ = application_pair
    aid, _ = connect(application_pair)
    ui = ChatUI(alice, lambda text: None)
    with pytest.raises(ValueError):
        ui.handle('/add {"invitation": "PMS2:TRUNCATED"')
    with pytest.raises(ValueError, match="Help"):
        ui.handle("/send")
    assert alice.history(aid) == []


def test_slash_commands_and_plain_words_have_distinct_meanings(application_pair):
    alice, _, _, _, _ = application_pair
    aid, _ = connect(application_pair)
    ui = ChatUI(alice, lambda text: None)
    # Even words which name commands are ordinary messages without a leading slash.
    for word in ("help", "contacts", "verify", "quit", "yes"):
        assert ui.handle(word) is True
    assert [item["body"] for item in alice.history(aid)] == [
        "help",
        "contacts",
        "verify",
        "quit",
        "yes",
    ]
    before = alice.history(aid)
    with pytest.raises(ValueError, match="/help"):
        ui.handle("/unknown-command")
    assert alice.history(aid) == before
    assert ui.handle("/quit") is False


def test_add_charlie_while_bob_is_selected_and_choose_from_saved_contacts(
    application_pair, tmp_path
):
    alice, bob, queues, deliver, _ = application_pair
    aid, _ = connect(application_pair)
    output = []
    a = ChatUI(alice, output.append)
    assert a.selected == aid
    with Vault(tmp_path / "charlie.vault", "Charlie's own password", create=True) as vault:
        register(vault, "Charlie")
        vault.put("servers", alice.vault.get("servers"))
        with Messenger(vault) as charlie:
            c = ChatUI(charlie, lambda text: None)
            invitation = charlie.address()
            queue_count = len(queues)
            # Reproduce the reported accidental forwarding, also guarding fragments and exports.
            for text in (
                "nový kontakt " + invitation["invitation"],
                invitation["invitation"],
                json.dumps(invitation),
                invitation["invitation"][5:],
                "/send Bob " + invitation["invitation"],
            ):
                with pytest.raises(ValueError, match="/add"):
                    a.handle(text)
                assert alice.history(aid) == []
                assert a.selected == aid
                assert len(queues) == queue_count
            a.handle("/add Charlie " + invitation["invitation"])
            cid = a.selected
            assert cid != aid
            assert alice.contact(cid)["name"] == "Charlie"
            assert not alice.contact(cid)["verified"]
            with pytest.raises(ValueError, match="/chat"):
                a.handle("/add " + invitation["invitation"])
            c.received(invitation["id"], deliver(charlie, invitation["id"])[1])
            c.handle("/accept")
            a.received(cid, deliver(alice, cid)[1])
            for ui in (a, c):
                ui.handle("/verify")
            assert a.pending_verification[1] == c.pending_verification[1]
            for ui in (a, c):
                ui.handle("/yes")
            a.handle("/chat")
            assert a.contact_choices == (aid, cid)
            assert any("1. Bob" in line for line in output)
            assert any("2. Charlie" in line for line in output)
            # Another stored contact appears after the menu, without renumbering that menu.
            other = bob.address()
            alice.connect(other["invitation"], "Aaron")
            a.handle("/chat 2")
            assert a.selected == cid
            a.handle("Ahoj Charlie, pouze pro tebe")
            while (event := deliver(charlie, invitation["id"])[1])["event"] != "text":
                assert event["event"] == "receipt"
            assert event["body"] == "Ahoj Charlie, pouze pro tebe"
            assert alice.history(aid) == []
            with pytest.raises(ValueError, match="number"):
                a.handle("/chat 99")
            assert a.selected == cid
            a.handle("/contacts")
            assert a.contact_choices[1:] == (aid, cid)
            a.handle("/chat 2")
            assert a.selected == aid
            a.handle("Ahoj Bobe, vybral jsem tě ze seznamu")
            assert alice.history(aid)[0]["body"] == "Ahoj Bobe, vybral jsem tě ze seznamu"
            assert len(alice.history(cid)) == 1


def assert_no_contact_messages(vault, cid):
    for statement in (
        "SELECT count(*) FROM messages WHERE contact=?",
        "SELECT count(*) FROM outbox WHERE contact=?",
        "SELECT count(*) FROM received_packets WHERE contact=?",
    ):
        assert vault.db.execute(statement, (cid,)).fetchone() == (0,)
    assert vault.db.execute(
        "SELECT count(*) FROM deliveries WHERE queue=?", ("pm2:" + cid,)
    ).fetchone() == (0,)


def test_delete_removes_all_contact_state_and_fresh_pairing_uses_new_keys(application_pair):
    alice, bob, queues, deliver, _ = application_pair
    aid, bid = connect(application_pair)
    original_a, original_b = alice.contact(aid), bob.contact(bid)
    identity = alice.vault.get("identity")
    alice.send(aid, "erase my outgoing history")
    deliver(bob, bid)
    bob.send(bid, "erase my incoming history")
    while not any(item["direction"] == "in" for item in alice.history(aid)):
        deliver(alice, aid)
    other = alice.address()
    unrelated = alice.contact(other["id"])
    sender_client = alice.clients[aid]
    assert alice.delete_contact(aid) == "server_deleted"
    assert sender_client.transport is None
    assert aid not in alice.clients
    with pytest.raises(ValueError, match="unknown contact"):
        alice.contact(aid)
    assert_no_contact_messages(alice.vault, aid)
    assert unb64(original_a["receive"]["sender_id"]) not in queues
    assert alice.contact(other["id"]) == unrelated
    assert alice.vault.get("identity") == identity
    assert bob.contact(bid)["state"] == "active"  # Deletion is explicitly local to each endpoint.
    assert bob.delete_contact(bid) == "server_deleted"
    assert_no_contact_messages(bob.vault, bid)
    new_aid, new_bid = connect(application_pair)
    assert (new_aid, new_bid) != (aid, bid)
    assert alice.contact(new_aid)["bundle"]["identity"] != original_a["bundle"]["identity"]
    assert bob.contact(new_bid)["receive"]["sender_id"] != original_b["receive"]["sender_id"]
    alice.send(new_aid, "fresh authenticated conversation")
    assert deliver(bob, new_bid)[1]["body"] == "fresh authenticated conversation"
    assert len(bob.history(new_bid)) == 1


def test_delete_confirmation_cancelled_selection_and_unused_invitation(application_pair):
    alice, _, _, _, _ = application_pair
    aid, _ = connect(application_pair)
    unused = alice.address()
    retired = []
    ui = ChatUI(alice, lambda text: None, on_deleting=retired.append)
    ui.handle("/del Bob")
    ui.handle("/no")
    assert alice.contact(aid)["state"] == "active"
    assert retired == []
    ui.handle("/del Bob")
    ui.handle("/chat " + unused["id"])
    with pytest.raises(ValueError, match="/verify"):
        ui.handle("/yes")
    assert alice.contact(aid)["state"] == "active"
    ui.handle("/contacts --all")
    number = ui.contact_choices.index(unused["id"]) + 1
    ui.handle(f"/del {number}")
    ui.handle("/yes")
    assert retired == [unused["id"]]
    assert ui.selected is None
    assert ui.contact_choices == ()
    assert alice.contact(aid)["state"] == "active"
    with pytest.raises(ValueError, match="/chat"):
        ui.handle("This must not silently go to the only remaining Bob")
    assert alice.history(aid) == []
    with pytest.raises(ValueError, match="unknown contact"):
        alice.contact(unused["id"])
    ui.handle("/del Bob")
    ui.handle("/yes")
    assert alice.all_contacts() == []


def test_failed_remote_delete_retires_crypto_and_survives_restart_for_retry(
    application_pair, monkeypatch, tmp_path
):
    alice, _, _, _, fake = application_pair
    aid, _ = connect(application_pair)
    alice.send(aid, "discard queued and accepted history")
    delete_queue = fake.delete_queue

    def offline(*args):
        raise OSError("test network unavailable")

    monkeypatch.setattr(fake, "delete_queue", offline)
    output = []
    ui = ChatUI(alice, output.append)
    ui.handle("/del")
    ui.handle("/yes")
    pending = alice.contact(aid)
    assert pending["state"] == "deleting"
    assert pending["native"] is None and pending["sender_private"] is None
    assert pending["outgoing"] is None and "bundle" not in pending
    assert "invitation" not in pending
    assert_no_contact_messages(alice.vault, aid)
    assert any("SMP queue deletion could not be confirmed" in text for text in output)
    with pytest.raises(ValueError):
        alice.send(aid, "a deleted ratchet cannot resume")
    with pytest.raises(ValueError, match="pending deletion"):
        alice.receive(aid, None)
    alice.flush()
    snapshot = tmp_path / "pending.vault"
    alice.vault.backup(snapshot)
    monkeypatch.setattr(fake, "delete_queue", delete_queue)
    with Vault(snapshot, "Alice password") as reopened, Messenger(reopened) as restored:
        resumed = ChatUI(restored, output.append)
        resumed.handle("/del")  # Already confirmed durable intent: retry, no second /yes.
        assert restored.all_contacts() == []
        assert_no_contact_messages(reopened, aid)


def test_delete_disk_failure_before_retirement_or_after_remote_ack_is_retryable(
    application_pair, monkeypatch
):
    from private_messenger.storage import vault as storage

    alice, _, queues, _, _ = application_pair
    aid, _ = connect(application_pair)
    alice.send(aid, "data before deletion")
    original = alice.contact(aid)
    encrypted = alice.vault.path.read_bytes()
    write = storage.atomic_write

    def full(*args, **kwargs):
        raise OSError("test disk full")

    monkeypatch.setattr(storage, "atomic_write", full)
    with pytest.raises(OSError):
        alice.delete_contact(aid)
    assert alice.contact(aid) == original
    assert alice.vault.path.read_bytes() == encrypted
    sid = unb64(original["receive"]["sender_id"])
    assert sid in queues
    monkeypatch.setattr(storage, "atomic_write", write)
    alice.begin_contact_deletion(aid)
    retired_snapshot = alice.vault.path.read_bytes()
    monkeypatch.setattr(storage, "atomic_write", full)
    with pytest.raises(OSError):
        alice.delete_contact(aid)
    assert alice.contact(aid)["state"] == "deleting"
    assert_no_contact_messages(alice.vault, aid)
    assert alice.vault.path.read_bytes() == retired_snapshot
    assert sid not in queues  # DEL succeeded even though the final local commit failed.
    monkeypatch.setattr(storage, "atomic_write", write)
    assert (
        alice.delete_contact(aid) == "server_unconfirmed"
    )  # AUTH is never called proof of deletion.
    assert alice.all_contacts() == []


@pytest.mark.parametrize("pending", [False, True])
def test_local_only_delete_is_explicit_and_never_contacts_server(
    application_pair, monkeypatch, pending
):
    alice, _, queues, _, fake = application_pair
    aid, _ = connect(application_pair)
    sid = unb64(alice.contact(aid)["receive"]["sender_id"])

    def forbidden(*args, **kwargs):
        raise AssertionError("local-only deletion contacted the router")

    monkeypatch.setattr(fake, "__enter__", forbidden)
    output = []
    ui = ChatUI(alice, output.append)
    ui.handle("/del Bob --local")
    assert "The server queue will remain" in output[-1]
    assert alice.contact(aid)["state"] == "active"
    ui.handle("/no")
    assert alice.contact(aid)["state"] == "active"
    if pending:
        alice.begin_contact_deletion(aid)
    ui.handle("/del Bob --local")
    assert ui.pending_deletion == (aid, True)
    ui.handle("/yes")
    assert alice.all_contacts() == []
    assert_no_contact_messages(alice.vault, aid)
    assert sid in queues  # No claim of remote deletion, and all local queue keys are gone.
    assert any("locally only; the server queue was not removed" in text for text in output)


def test_chat_discards_receiver_events_queued_during_deletion(application_pair, monkeypatch):
    from private_messenger.messaging import secure_terminal
    from private_messenger.networking.connection import Network

    alice, _, _, _, _ = application_pair
    aid, _ = connect(application_pair)
    ready, finished = threading.Event(), threading.Event()
    decisions, worker_flags = [], []

    def receiver(contact, network, events, worker_stop):
        assert set(contact) == {"id", "incoming_server", "receive"}
        worker_flags.append(worker_stop)
        ready.set()
        if not worker_stop.wait(5):
            finished.set()
            return
        decision = queue.Queue(maxsize=1)
        # Simulate events posted before the retired receiver observes its stop flag.
        events.put(("connected", (aid, 18)))
        events.put(("acked", (aid, secrets.token_bytes(24))))
        events.put(("delivery", (aid, None, decision)))
        events.put(("reconnecting", aid))
        events.put(("fatal", aid))
        decisions.append(decision.get(timeout=5))
        finished.set()

    def inputs(events, stop):
        if ready.wait(5):
            events.put(("input", "/del Bob"))
            events.put(("input", "/yes"))
            finished.wait(5)
        events.put(("input", "/quit"))

    monkeypatch.setattr(secure_terminal, "subscribe", receiver)
    monkeypatch.setattr(secure_terminal, "keyboard", inputs)
    monkeypatch.setattr(secure_terminal.sys, "stdin", io.StringIO())
    assert secure_terminal.run_shell(alice.vault, network=Network("DIRECT")) == 0
    assert worker_flags and all(flag.is_set() for flag in worker_flags)
    assert decisions == [False]
    assert alice.all_contacts() == []
    assert_no_contact_messages(alice.vault, aid)


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
