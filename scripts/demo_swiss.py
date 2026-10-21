"""One-command transport demo with temporary local Alice/Bob profiles.

Fetches the operator's public NEW password over verified HTTPS, requires the
already verified router pin, and removes all temporary credentials after the test.
"""

import html
import re
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from demo import demo

from private_messenger.config import Server
from private_messenger.storage.vault import atomic_write

PAGE = "https://urban-network.ch/services/simplex"
SERVER = "smp://LtowhzwGvh3lqlFvMqxCTPmZ_OzcwOq_NCsNG7ya1lc=@urban-network.dyndns.org:5224"
MAX_PAGE_SIZE = 256 * 1024


class SameOriginHTTPS(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        url = urllib.parse.urlsplit(newurl)
        if url.scheme != "https" or url.netloc != "urban-network.ch":
            raise ValueError("unexpected operator website redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def public_router_password(page: str) -> bytes:
    """Read only the descriptor matching our existing pinned router identity."""
    expected = Server.parse(SERVER)
    for match in re.finditer(r"smp://[^\s<>\"']+", html.unescape(page)):
        try:
            uri = urllib.parse.urlsplit(match[0])
            host = uri.hostname.split(",")[0] if uri.hostname else ""
            candidate = Server.parse(f"smp://{uri.username}@{host}:{uri.port or 5223}")
            password = uri.password.encode("utf-8") if uri.password else b""
            if candidate == expected and 1 <= len(password) <= 255:
                return password
        except ValueError:
            continue
    raise ValueError("operator page has no matching pinned router descriptor")


def download_public_password() -> bytes:
    opener = urllib.request.build_opener(SameOriginHTTPS())
    # Fixed HTTPS URL, default CA validation, same-origin HTTPS redirects only.
    with opener.open(PAGE, timeout=20) as response:  # noqa: S310
        page = response.read(MAX_PAGE_SIZE + 1)
        if len(page) > MAX_PAGE_SIZE:
            raise ValueError("operator page exceeds size limit")
    return public_router_password(page.decode("utf-8"))


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
    print("Hotovo. Textový chat zatím není implementovaný; toto ověřuje přenos dat.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
