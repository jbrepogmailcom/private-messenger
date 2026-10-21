from hypothesis import given
from hypothesis import strategies as st

from private_messenger.crypto import smp_box
from private_messenger.smp.framing import batch, pad, unbatch, unpad


@given(st.binary(max_size=16382))
def test_padding_round_trip(value):
    assert unpad(pad(value)) == value


@given(st.lists(st.binary(max_size=128), min_size=1, max_size=30))
def test_batch_round_trip(values):
    assert unbatch(batch(values)) == values


@given(
    st.binary(min_size=32, max_size=32),
    st.binary(min_size=24, max_size=24),
    st.binary(max_size=256),
)
def test_smp_box_against_libsodium_dh_box(private, nonce, message):
    from cryptography.hazmat.primitives.asymmetric import x25519
    from nacl.public import Box, PrivateKey

    alice = x25519.X25519PrivateKey.from_private_bytes(private)
    bob = x25519.X25519PrivateKey.from_private_bytes(bytes(range(32)))
    shared = alice.exchange(bob.public_key())
    expected = Box(PrivateKey(private), PrivateKey(bytes(range(32))).public_key)
    assert smp_box.encrypt(shared, nonce, message) == expected.encrypt(message, nonce).ciphertext
    assert smp_box.decrypt(shared, nonce, smp_box.encrypt(shared, nonce, message)) == message
