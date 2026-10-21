import pytest

from private_messenger.smp.framing import (
    ProtocolError,
    Reader,
    batch,
    large,
    pad,
    short,
    unbatch,
    unpad,
)
from private_messenger.smp.handshake import BlockChain, negotiate


def test_encodings():
    assert short(b"abc") == b"\x03abc"
    assert large(b"abc") == b"\x00\x03abc"
    assert len(pad(b"x")) == 16384
    assert unbatch(batch([b"one", b"two"])) == [b"one", b"two"]


@pytest.mark.parametrize("bad", [b"", b"\0", b"\1\0\5x", b"\1\0\1xy"])
def test_reject_bad_batch(bad):
    with pytest.raises(ProtocolError):
        unbatch(bad)


def test_bounds():
    with pytest.raises(ProtocolError):
        short(bytes(256))
    with pytest.raises(ProtocolError):
        pad(bytes(16383))
    with pytest.raises(ProtocolError):
        Reader(b"\xff").short()
    with pytest.raises(ProtocolError):
        unpad(b"\0\1xx")


@pytest.mark.parametrize("low,high,expected", [(6, 22, 20), (11, 11, 11), (14, 19, 19)])
def test_negotiation(low, high, expected):
    assert negotiate(low, high) == expected


@pytest.mark.parametrize("low,high", [(6, 10), (21, 22), (20, 11)])
def test_no_insecure_negotiation(low, high):
    with pytest.raises(ProtocolError):
        negotiate(low, high)


def test_block_chain_progression_and_tampering():
    from nacl.exceptions import CryptoError

    sending, receiving = BlockChain(bytes(32)), BlockChain(bytes(32))
    first = sending.encrypt(b"a")
    second = sending.encrypt(b"a")
    assert first != second
    assert receiving.decrypt(first) == receiving.decrypt(second) == b"a"
    with pytest.raises(CryptoError):
        receiving.decrypt(first)  # transport replay does not authenticate at next key
    with pytest.raises(CryptoError):
        BlockChain(bytes(32)).decrypt(first[:-1] + bytes([first[-1] ^ 1]))
