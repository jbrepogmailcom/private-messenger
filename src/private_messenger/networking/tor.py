"""Owned Tor lifecycle; SOCKS remains in the independent Python network adapter.

No system service/configuration is changed. Tor state lives in a private RAM
directory while running; guard state is retained only in the encrypted vault.
An explicitly configured external proxy is never replaced after an error.
"""

import os
import re
import select
import shutil
import socket

# Supervise only the installed Tor executable, with fixed arguments and no shell.
import subprocess  # nosec B404
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from private_messenger.config import b64, unb64
from private_messenger.networking.connection import Network
from private_messenger.storage.vault import atomic_write, read_private

MAX_STATE = 1024 * 1024
BOOTSTRAP_SECONDS = 180


class TorUnavailable(OSError):
    """No usable Tor route; never authorizes DIRECT fallback."""


def configured_network(vault) -> Network:
    return Network(**({"mode": "TOR"} | vault.get("network", {})))


def configure_chat(vault, mode="TOR", proxy_host=None, proxy_port=None) -> None:
    previous = vault.get("network", {})
    # DIRECT's default proxy fields were never a request to use an external Tor.
    config = dict(previous) if previous.get("mode") == mode else {"mode": mode}
    config["mode"] = mode
    if proxy_host is not None or proxy_port is not None:
        if mode != "TOR":
            raise ValueError("Tor proxy options require TOR mode")
        config.update(
            proxy_host=proxy_host if proxy_host is not None else "127.0.0.1",
            proxy_port=proxy_port if proxy_port is not None else 9050,
        )
    Network(**config)
    if config != previous:
        vault.put("network", config)


def _stop(process) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    process.stdout.close()


def _discard_output(stream) -> None:
    try:
        while stream.read(8192):
            pass
    except (OSError, ValueError):
        pass


@contextmanager
def messaging_network(vault, progress=None):
    config = vault.get("network", {})
    network = configured_network(vault)
    if network.mode == "DIRECT" or "proxy_host" in config or "proxy_port" in config:
        yield network  # Explicit external SOCKS configuration; no managed fallback.
        return
    binary = shutil.which("tor")
    if binary is None:
        raise TorUnavailable(
            "Tor není nainstalovaný. Nainstaluj tor nebo nastav vlastní SOCKS proxy."
        )
    # TemporaryDirectory creates an unpredictable 0700 child, never a shared fixed file.
    ram = Path("/dev/shm")  # noqa: S108  # nosec B108
    if not ram.is_dir():
        raise TorUnavailable("Pro spravovaný Tor chybí /dev/shm; nastav vlastní Tor SOCKS proxy.")
    with tempfile.TemporaryDirectory(prefix="pm-tor-", dir=ram) as directory:
        root = Path(directory)
        data = root / "data"
        data.mkdir(mode=0o700)
        retained = vault.get("tor_guard_state")
        if retained is not None:
            state = unb64(retained)
            if len(state) > MAX_STATE:
                raise ValueError("retained Tor state exceeds size limit")
            atomic_write(data / "state", state, overwrite=False)
        config_file = root / "torrc"
        atomic_write(config_file, b"", overwrite=False)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        if progress:
            progress("Spouštím vlastní Tor; čekám na připojení k síti…")
        # Discovered installed Tor, fixed arguments, no shell or user-provided executable.
        process = subprocess.Popen(  # noqa: S603  # nosec B603
            [
                binary,
                "-f",
                str(config_file),
                "--RunAsDaemon",
                "0",
                "--ClientOnly",
                "1",
                "--__OwningControllerProcess",
                str(os.getpid()),
                "--AvoidDiskWrites",
                "1",
                "--GeoIPFile",
                "/dev/null",
                "--GeoIPv6File",
                "/dev/null",
                "--DataDirectory",
                str(data),
                "--SocksPort",
                f"127.0.0.1:{port} IsolateSOCKSAuth",
                "--Log",
                "notice stdout",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        )
        drain = None
        try:
            pending = b""
            ready = False
            deadline = time.monotonic() + BOOTSTRAP_SECONDS
            while time.monotonic() < deadline and not ready:
                if not select.select([process.stdout], [], [], 0.5)[0]:
                    continue
                chunk = os.read(process.stdout.fileno(), 8192)
                if not chunk:
                    raise TorUnavailable("Tor skončil před připojením. Přímé spojení je zakázané.")
                pending += chunk
                if len(pending) > 32768:
                    raise TorUnavailable("Neočekávaný výstup Toru; připojení bylo zastaveno.")
                while b"\n" in pending:
                    line, pending = pending.split(b"\n", 1)
                    match = re.search(rb"Bootstrapped (\d{1,3})%", line)
                    if match:
                        percent = int(match[1])
                        if progress:
                            progress(f"Tor: {percent} %")
                        ready = percent == 100
            if not ready:
                raise TorUnavailable("Tor se nepřipojil včas. Přímé spojení je zakázané.")
            drain = threading.Thread(target=_discard_output, args=(process.stdout,), daemon=True)
            drain.start()
            yield Network("TOR", "127.0.0.1", port, timeout=45)
        finally:
            _stop(process)  # Only this context's own child process, including on Ctrl+C.
            if drain is not None:
                drain.join(timeout=2)
            state_file = data / "state"
            if state_file.exists():
                serialized = b64(read_private(state_file, MAX_STATE))
                if serialized != retained:
                    vault.put("tor_guard_state", serialized)
