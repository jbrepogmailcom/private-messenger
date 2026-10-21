"""Two independent CLI processes, real router, encrypted opaque random payloads.

No SimpleX engine, agent, account or database is used. No user messages are sent.
All temporary queues are deleted at the end; no credentials appear in the report.
"""

import argparse
import hashlib
import json
import os
import secrets
import select
import subprocess
import sys
import tempfile
from pathlib import Path

from private_messenger.crypto import smp_box
from private_messenger.smp.framing import pad


def demo(server: str) -> dict:
    summary = {
        "server": server,
        "infrastructure": "real; classification supplied by caller",
        "external_messaging_engine": False,
    }
    with tempfile.TemporaryDirectory(prefix="private-messenger-demo-") as temporary:
        root = Path(temporary)
        os.chmod(root, 0o700)
        secret = root / "passphrase"
        secret.write_text(secrets.token_urlsafe(32))
        secret.chmod(0o600)

        def command(person: str, *args: str) -> list[str]:
            return [
                sys.executable,
                "-m",
                "private_messenger.cli",
                "--vault",
                str(root / f"{person}.vault"),
                "--passphrase-file",
                str(secret),
                *args,
            ]

        def run(person: str, *args: str):
            result = subprocess.run(  # noqa: S603 -- fixed Python executable, argument list, no shell
                command(person, *args), check=True, capture_output=True, text=True, timeout=40
            )  # noqa: S603
            return json.loads(result.stdout)

        def payload(name: str) -> tuple[Path, str]:
            # Encrypted random test bytes; this is NOT an authenticated conversation.
            body = smp_box.encrypt(
                secrets.token_bytes(32), secrets.token_bytes(24), pad(secrets.token_bytes(128), 512)
            )
            path = root / name
            path.write_bytes(body)
            return path, hashlib.sha256(body).hexdigest()

        run("Alice", "register", "Alice")
        run("Bob", "register", "Bob")
        created = run("Bob", "smp", "create", "incoming", server)
        summary["negotiated_smp_version"] = created["version"]
        try:
            address = run("Bob", "smp", "address", "incoming")["address"]
            run("Alice", "smp", "secure", "to-bob", address)
            summary["sender_key_separation"] = True

            # Bob's CLI has exited completely. Alice starts a separate Python process.
            offline, digest = payload("offline.bin")
            accepted = run("Alice", "smp", "send", "to-bob", str(offline))
            assert accepted["event"] == "server_accepted"
            assert accepted["recipient_delivery"] == "unconfirmed"
            first = run("Bob", "smp", "get", "incoming", "--no-ack")
            assert first["new"] and first["ciphertext_sha256"] == digest
            # Bob exits without ACK. Restarting must produce one history record.
            duplicate = run("Bob", "smp", "get", "incoming")
            assert not duplicate["new"] and duplicate["ciphertext_sha256"] == digest
            summary["offline_delivery"] = True
            summary["redelivery_deduplicated_after_process_restart"] = True
            empty = run("Bob", "smp", "get", "incoming")
            assert empty["event"] == "empty"
            summary["ack_removes_message"] = True

            # Online path: Bob stays alive, subscribed, while Alice runs independently.
            online, digest = payload("online.bin")
            listener = subprocess.Popen(  # noqa: S603 -- fixed executable, no shell
                command("Bob", "smp", "subscribe", "incoming"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )  # noqa: S603
            try:
                ready, _, _ = select.select([listener.stdout], [], [], 30)
                if not ready:
                    raise TimeoutError("Bob did not subscribe")
                line = listener.stdout.readline()
                if not line:
                    raise RuntimeError("Bob failed: " + listener.stderr.read())
                assert json.loads(line)["event"] == "subscribed"
                run("Alice", "smp", "send", "to-bob", str(online))
                stdout, stderr = listener.communicate(timeout=30)
                if listener.returncode:
                    raise RuntimeError("Bob failed: " + stderr)
                received = json.loads(stdout)
                assert received["ciphertext_sha256"] == digest and received["new"]
                summary["online_two_process_delivery"] = True
            finally:
                if listener.poll() is None:
                    listener.terminate()
                    listener.communicate(timeout=5)
        finally:
            run("Bob", "smp", "delete", "incoming")
            summary["temporary_queue_deleted"] = True
    return summary


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--server", required=True, help="pinned smp://identity@host[:port]")
    args = p.parse_args()
    print(json.dumps(demo(args.server), indent=2))
