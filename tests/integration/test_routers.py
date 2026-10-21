"""Real infrastructure only. No fake router is counted as interoperability."""

import importlib.util
import os
import secrets
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from private_messenger.config import Server
from private_messenger.smp.client import Client, RouterError
from private_messenger.smp.framing import ProtocolError


@pytest.mark.public
def test_public_two_process_demo():
    uri = os.environ.get("PM_PUBLIC_SMP_SERVER")
    if not uri:
        pytest.skip("set PM_PUBLIC_SMP_SERVER to explicitly opt in to real public queue tests")
    path = Path(__file__).parents[2] / "scripts/demo.py"
    spec = importlib.util.spec_from_file_location("alice_bob_demo", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    result = module.demo(uri)
    assert result["online_two_process_delivery"]
    assert result["offline_delivery"]
    assert result["redelivery_deduplicated_after_process_restart"]


def exercise_router(uri: str, version: int):
    server = Server.parse(uri)
    with Client(server, minimum=version, maximum=version) as bob:
        bob.ping()
        queue = bob.create_queue()
        try:
            sender_key = ed25519.Ed25519PrivateKey.generate()
            with Client(server, minimum=version, maximum=version) as alice:
                alice.secure_sender(queue.sender_id, sender_key)
                with pytest.raises(RouterError, match="ERR AUTH"):
                    alice.send_ciphertext(
                        queue.sender_id,
                        secrets.token_bytes(48),
                        ed25519.Ed25519PrivateKey.generate(),
                    )
                ciphertext = secrets.token_bytes(128)  # opaque transport fixture, no user plaintext
                alice.send_ciphertext(queue.sender_id, ciphertext, sender_key)
            received = bob.get(queue)
            assert received.ciphertext == ciphertext
            with pytest.raises(ProtocolError):
                bob.subscribe(queue)  # prohibited GET/SUB mixing
            with pytest.raises(RouterError):
                bob.command(b"GET", queue.sender_id, queue.auth_private)  # recipient ID required
            with pytest.raises(RouterError):
                bob.acknowledge(queue, secrets.token_bytes(24))
            bob.close()  # real disconnect before ACK
            bob.reconnect()
            redelivery = bob.get(queue)
            assert redelivery.message_id == received.message_id
            bob.acknowledge(queue, received.message_id)
            assert bob.get(queue) is None
        finally:
            if bob.transport is None:
                bob.reconnect()
            bob.delete_queue(queue)


@pytest.mark.public
@pytest.mark.parametrize("version", [14, 15, 16, 17, 18, 19, 20])
def test_public_versions_authentication_and_reconnect(version):
    uri = os.environ.get("PM_PUBLIC_SMP_SERVER")
    if not uri:
        pytest.skip("public infrastructure tests require PM_PUBLIC_SMP_SERVER")
    exercise_router(uri, version)


@pytest.mark.local_reference
@pytest.mark.parametrize("version", [11, 14, 15, 16, 17, 18])
def test_unmodified_local_reference(version):
    uri = os.environ.get("PM_LOCAL_SMP_SERVER")
    if not uri:
        pytest.skip("unmodified local reference server required: PM_LOCAL_SMP_SERVER")
    exercise_router(uri, version)


@pytest.mark.local_reference
def test_reference_unsupported_version_does_not_downgrade():
    uri = os.environ.get("PM_LOCAL_SMP_SERVER")
    if not uri:
        pytest.skip("requires unmodified local reference server")
    with Client(Server.parse(uri)) as client:
        highest = client.version
    if highest == 20:
        pytest.skip("server supports every client version; unit tests cover disjoint ranges")
    with pytest.raises(ProtocolError, match="no compatible secure SMP version"):
        Client(Server.parse(uri), minimum=highest + 1).connect()
