"""One-command transport demo with temporary local Alice/Bob profiles.

Fetches the operator's public NEW password over verified HTTPS, requires the
already verified router pin, and removes all temporary credentials after the test.
"""

import subprocess
import tempfile
from pathlib import Path

from demo import demo

from private_messenger.networking.swiss import SERVER, download_public_password
from private_messenger.networking.swiss import SameOriginHTTPS as SameOriginHTTPS
from private_messenger.networking.swiss import public_router_password as public_router_password
from private_messenger.storage.vault import atomic_write


def main() -> int:
    print("Preparing a test through Urban-Network in Switzerland…", flush=True)
    try:
        password = download_public_password()
        with tempfile.TemporaryDirectory(prefix="pm-swiss-demo-") as directory:
            auth = Path(directory) / "router.auth"
            atomic_write(auth, password, overwrite=False)
            print(
                "Starting separate Alice and Bob clients. The test takes about half a minute…",
                flush=True,
            )
            result = demo(SERVER, auth)
        if not all(
            result.get(key)
            for key in (
                "online_two_process_delivery",
                "offline_delivery",
                "redelivery_deduplicated_after_process_restart",
                "ack_removes_message",
                "temporary_queue_deleted",
            )
        ):
            raise ValueError("incomplete transport test")
    except (ValueError, OSError, TimeoutError, RuntimeError, subprocess.SubprocessError):
        print(
            "The test failed. Check your internet connection and Urban-Network availability.",
            flush=True,
        )
        return 1
    print("✓ Alice and Bob were created as separate test profiles.")
    print("✓ Alice sent Bob data both online and while he was disconnected.")
    print("✓ Redelivery, acknowledgement and cleanup passed.")
    print("Done. For interactive text chat, run ./chat Alice and ./chat Bob in two terminals.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
