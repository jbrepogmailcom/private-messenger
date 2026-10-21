import struct

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from nacl.exceptions import CryptoError

from private_messenger.crypto import smp_box
from private_messenger.smp.client import Client
from private_messenger.smp.framing import ProtocolError, pad, short
from private_messenger.smp.queues import ReceiveQueue


def test_queue_restoration_and_invalid_delivery():
    auth = ed25519.Ed25519PrivateKey.generate()
    dh = x25519.X25519PrivateKey.generate()
    server_key = x25519.X25519PrivateKey.generate()
    queue = ReceiveQueue(bytes(24), b"s" * 24, auth, dh, server_key.public_key(), True)
    restored = ReceiveQueue.restore(queue.export())
    assert restored.export() == queue.export()
    mid = b"m" * 24
    secret = server_key.exchange(dh.public_key())
    encrypted = smp_box.encrypt(secret, mid, pad(struct.pack("!Q", 123) + b"F opaque", 16050))
    wire = b"MSG " + short(mid) + encrypted
    delivery = Client._delivery(restored, wire)
    assert delivery.ciphertext == b"opaque" and delivery.timestamp == 123
    with pytest.raises(CryptoError):
        Client._delivery(restored, wire[:-1] + bytes([wire[-1] ^ 1]))
    with pytest.raises(ProtocolError):
        Client._delivery(restored, b"MSG " + short(b"short") + encrypted)
    encrypted = smp_box.encrypt(secret, mid, pad(struct.pack("!Q", 123) + b"X opaque", 16050))
    with pytest.raises(ProtocolError):
        Client._delivery(restored, b"MSG " + short(mid) + encrypted)
