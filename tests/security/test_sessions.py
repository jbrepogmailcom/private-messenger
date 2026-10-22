"""Real upstream native crypto; never mocks counted as ratchet/PQ verification.

Compromise tests assume honest future randomness, trusted endpoint code, no active
attacker after the snapshot, and erasure outside retained skipped keys/backups.
They exercise behavior, not a substitute for the upstream proofs or an audit.
"""

import base64
import copy
import json
import secrets
import time
import zlib

import pytest

pytest.importorskip("private_messenger._crypto_native", reason="build pinned native crypto first")

from private_messenger.config import b64
from private_messenger.crypto.backend import SUITE, operation
from private_messenger.sessions import invitations


def keys():
    return operation("generate", local_address=b64(secrets.token_bytes(32)))


def pair():
    alice, bob = keys(), keys()
    alice["state"] = operation(
        "initiate",
        state=alice["state"],
        peer_address=bob["state"]["local_address"],
        bundle=bob["bundle"],
    )["state"]
    return alice["state"], bob["state"]


def send(state, text):
    message = operation("encrypt", state=state, plaintext=list(text.encode()))
    return message["state"], message


def receive(state, peer, message):
    result = operation(
        "decrypt",
        state=state,
        peer_address=peer["local_address"],
        message_type=message["message_type"],
        ciphertext=message["ciphertext"],
    )
    return result["state"], bytes(result["plaintext"]).decode()


def established():
    alice, bob = pair()
    alice, msg = send(alice, "first")
    bob, _ = receive(bob, alice, msg)
    bob, msg = send(bob, "reply")
    alice, _ = receive(alice, bob, msg)
    return alice, bob


def test_real_triple_ratchet_out_of_order_and_setup_key_retirement():
    alice, bob = pair()
    outgoing = []
    for index in range(12):
        alice, msg = send(alice, f"message {index}")
        outgoing.append(msg)
    for index in reversed(range(12)):
        bob, text = receive(bob, alice, outgoing[index])
        assert text == f"message {index}"
    assert all(bob[name] is None for name in ("prekey", "signed_prekey", "kem_prekey"))
    assert all(alice[name] is None for name in ("prekey", "signed_prekey", "kem_prekey"))
    assert operation("fingerprint", state=alice) == operation("fingerprint", state=bob)
    assert len(operation("fingerprint", state=bob)["fingerprint"]) == 60
    with pytest.raises(ValueError):
        receive(bob, alice, outgoing[0])


def test_tampering_has_no_state_transition_and_legitimate_packet_still_decrypts():
    alice, bob = established()
    alice, msg = send(alice, "authenticated text")
    before = copy.deepcopy(bob)
    tampered = copy.deepcopy(msg)
    tampered["ciphertext"][-1] ^= 1
    with pytest.raises(ValueError):
        receive(bob, alice, tampered)
    assert bob == before
    bob, text = receive(bob, alice, msg)
    assert text == "authenticated text"
    assert bob != before


def test_post_compromise_recovery_after_honest_fresh_dh_exchange():
    alice, bob = established()
    attacker = copy.deepcopy(alice)  # a one-time endpoint state exposure
    alice, msg = send(alice, "drive peer ratchet")
    bob, _ = receive(bob, alice, msg)
    bob, msg = send(bob, "first response after compromise")
    alice, plaintext = receive(alice, bob, msg)
    attacker, stolen_plaintext = receive(attacker, bob, msg)
    assert plaintext == stolen_plaintext  # no immediate/magical healing is claimed
    alice, msg = send(alice, "fresh local DH entropy")
    bob, _ = receive(bob, alice, msg)
    bob, msg = send(bob, "healed response")
    alice, plaintext = receive(alice, bob, msg)
    assert plaintext == "healed response"
    with pytest.raises(ValueError):
        receive(attacker, bob, msg)


def test_current_session_cannot_decrypt_previously_consumed_messages():
    alice, bob = established()
    alice, past = send(alice, "past message whose receiving key is consumed")
    bob, _ = receive(bob, alice, past)
    for _ in range(3):
        bob, reply = send(bob, "fresh DH step")
        alice, _ = receive(alice, bob, reply)
        alice, message = send(alice, "advance sender")
        bob, _ = receive(bob, alice, message)
    stolen_current_state = copy.deepcopy(bob)
    with pytest.raises(ValueError):
        receive(stolen_current_state, alice, past)


def test_skipped_key_cache_is_bounded_by_upstream_2000_key_limit():
    alice, bob = established()
    saved = {}
    for index in range(2003):
        alice, message = send(alice, f"skipped message {index}")
        if index in (0, 1000, 2002):
            saved[index] = message
    bob, text = receive(bob, alice, saved[2002])
    assert text == "skipped message 2002"
    bob, text = receive(bob, alice, saved[1000])
    assert text == "skipped message 1000"
    with pytest.raises(ValueError):
        receive(bob, alice, saved[0])


def test_wrong_identity_bad_prekey_signature_and_classical_downgrade_fail():
    alice, bob = keys(), keys()
    bad = copy.deepcopy(bob["bundle"])
    bad["signed_signature"][0] ^= 1
    with pytest.raises(ValueError):
        operation(
            "initiate", state=alice["state"], peer_address=bob["state"]["local_address"], bundle=bad
        )
    bad = copy.deepcopy(bob["bundle"])
    bad["kem"][0] = 8  # legacy Kyber is not the selected standardized KEM
    with pytest.raises(ValueError):
        operation(
            "initiate", state=alice["state"], peer_address=bob["state"]["local_address"], bundle=bad
        )


def test_signed_qr_compatible_invitation_and_changed_route_rejection():
    bob = keys()
    data = {
        "v": 2,
        "suite": SUITE,
        "id": b64(secrets.token_bytes(32)),
        "expires": int(time.time()) + 86400,
        "address": bob["state"]["local_address"],
        "server": f"smp://{b64(secrets.token_bytes(32))}@router.invalid:5223",
        "sender_id": b64(secrets.token_bytes(24)),
        "bundle": invitations.compact_bundle(bob["bundle"]),
    }
    invitation = invitations.encode(data, bob["state"])
    assert len(invitation) <= 4296
    assert set(invitation) <= set("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:")
    assert invitations.decode(invitation) == data
    compressed = base64.b32decode(invitation[5:] + "=" * (-len(invitation[5:]) % 8))
    changed = json.loads(zlib.decompress(compressed))
    changed["data"]["server"] = f"smp://{b64(secrets.token_bytes(32))}@attacker.invalid:5223"
    altered = invitations.PREFIX + base64.b32encode(
        zlib.compress(invitations.canonical(changed))
    ).decode().rstrip("=")
    with pytest.raises(ValueError, match="signature"):
        invitations.decode(altered)
    with pytest.raises(ValueError, match="expired"):
        invitations.decode(invitation, now=data["expires"] + 1)


def test_another_contact_identity_cannot_replace_an_established_session():
    alice, bob = established()
    intruder, peer = established()
    intruder, ciphertext = send(intruder, "another contact's packet")
    before = copy.deepcopy(bob)
    # Even using the expected sender's outer address does not authenticate the key.
    with pytest.raises(ValueError):
        receive(bob, alice, ciphertext)
    assert bob == before


def test_published_upstream_fingerprint_vector():
    # signalapp/libsignal rust/protocol/src/fingerprint.rs, fingerprint_test_v2.
    result = operation(
        "fingerprint_public",
        local_address="+14152222222",
        peer_address="+14153333333",
        local_identity=list(
            bytes.fromhex("0506863bc66d02b40d27b8d49ca7c09e9239236f9d7d25d6fcca5ce13c7064d868")
        ),
        peer_identity=list(
            bytes.fromhex("05f781b6fb32fed9ba1cf2de978d4d5da28dc34046ae814402b5c0dbd96fda907b")
        ),
    )
    assert result["fingerprint"] == "300354477692869396892869876765458257569162576843440918079131"


def test_post_quantum_ratchet_negotiates_and_advances_fresh_epochs():
    alice, bob = pair()
    for _ in range(160):
        alice, msg = send(alice, "drive PQ braid")
        bob, _ = receive(bob, alice, msg)
        bob, msg = send(bob, "drive PQ braid reply")
        alice, _ = receive(alice, bob, msg)
    for state in (alice, bob):
        status = operation("status", state=state)
        assert status["spqr_v1_negotiated"]
        assert status["session_version"] == 4
        assert status["pq_epoch"] >= 3
        assert status["pq_send_epoch"] >= 2
