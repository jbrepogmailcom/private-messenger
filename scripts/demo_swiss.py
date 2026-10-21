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
    print("Připravuji test přes Urban-Network ve Švýcarsku…", flush=True)
    try:
        password = download_public_password()
        with tempfile.TemporaryDirectory(prefix="pm-swiss-demo-") as directory:
            auth = Path(directory) / "router.auth"
            atomic_write(auth, password, overwrite=False)
            print(
                "Spouštím oddělené klienty Alice a Bob. Test potrvá přibližně půl minuty…",
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
            "Test se nezdařil. Ověř internetové připojení a dostupnost Urban-Network.", flush=True
        )
        return 1
    print("✓ Alice a Bob byli vytvořeni jako oddělené testovací profily.")
    print("✓ Alice předala Bobovi data online i během jeho odpojení.")
    print("✓ Opakované doručení, potvrzení a úklid prošly.")
    print("Hotovo. Pro interaktivní textový test spusť ./chat Alice a ./chat Bob ve dvou oknech.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
