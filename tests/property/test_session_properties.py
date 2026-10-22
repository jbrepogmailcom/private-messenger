import base64
import secrets
import zlib

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

pytest.importorskip("private_messenger._crypto_native", reason="build pinned crypto")

from private_messenger.config import b64
from private_messenger.crypto.backend import operation
from private_messenger.sessions import invitations, packets


@settings(max_examples=20, deadline=None)
@given(st.binary(max_size=4096))
def test_real_native_ratchet_binary_payload_roundtrip(plaintext):
    a = operation("generate", local_address=b64(secrets.token_bytes(32)))
    b = operation("generate", local_address=b64(secrets.token_bytes(32)))
    state = operation(
        "initiate", state=a["state"], peer_address=b["state"]["local_address"], bundle=b["bundle"]
    )["state"]
    message = operation("encrypt", state=state, plaintext=list(plaintext))
    wire = packets.pack(
        a["state"]["local_address"], message["message_type"], bytes(message["ciphertext"])
    )
    sender, message_type, ciphertext = packets.unpack(wire)
    received = operation(
        "decrypt",
        state=b["state"],
        peer_address=sender,
        message_type=message_type,
        ciphertext=list(ciphertext),
    )
    assert bytes(received["plaintext"]) == plaintext


@given(st.binary(max_size=5000))
def test_packet_parser_bounds(packet):
    try:
        sender, kind, ciphertext = packets.unpack(packet)
    except ValueError:
        return
    assert packets.pack(sender, kind, ciphertext) == packet


@given(st.binary(max_size=2500))
def test_arbitrary_compressed_invitation_payload_has_bounded_errors(payload):
    invite = invitations.PREFIX + base64.b32encode(payload).decode().rstrip("=")
    with pytest.raises(ValueError):
        invitations.decode(invite)


def test_invitation_decompression_bomb_is_rejected_before_json_or_crypto():
    compressed = zlib.compress(b"x" * 1_000_000)
    invite = invitations.PREFIX + base64.b32encode(compressed).decode().rstrip("=")
    with pytest.raises(ValueError, match="excessive"):
        invitations.decode(invite)


def test_nested_invitation_json_fails_as_a_bounded_input_error():
    compressed = zlib.compress(b"[" * 2000 + b"0" + b"]" * 2000)
    invite = invitations.PREFIX + base64.b32encode(compressed).decode().rstrip("=")
    with pytest.raises(ValueError, match="invalid invitation"):
        invitations.decode(invite)
