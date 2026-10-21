"""Opt-in real Tor test. Launches and cleans up only its own disposable Tor process."""

import argparse
import json
import select
import shutil
import socket
import subprocess
import tempfile
import time

from private_messenger.config import Server
from private_messenger.networking.connection import Network
from private_messenger.smp.client import Client


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    args = parser.parse_args()
    binary = shutil.which("tor")
    if binary is None:
        parser.error("Tor must already be installed; this script does not install it")
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix="pm-tor-") as directory:
        process = subprocess.Popen(  # noqa: S603 -- explicitly discovered Tor, no shell
            [
                binary,
                "--DataDirectory",
                directory,
                "--SocksPort",
                f"127.0.0.1:{port} IsolateSOCKSAuth",
                "--ClientOnly",
                "1",
                "--AvoidDiskWrites",
                "1",
                "--Log",
                "notice stdout",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            deadline = time.monotonic() + 150
            while time.monotonic() < deadline:
                ready, _, _ = select.select([process.stdout], [], [], 5)
                if not ready:
                    continue
                line = process.stdout.readline()
                if not line:
                    raise RuntimeError("disposable Tor exited before bootstrap")
                if "Bootstrapped" in line:
                    print(line.strip(), flush=True)
                if "Bootstrapped 100%" in line:
                    break
            else:
                raise TimeoutError("Tor failed to bootstrap; no direct fallback")
            with Client(Server.parse(args.server), Network("TOR", "127.0.0.1", port, 45)) as client:
                client.ping()
                queue = client.create_queue()
                client.delete_queue(queue)
                print(
                    json.dumps(
                        {
                            "real_tor": True,
                            "smp_version": client.version,
                            "pinned_tls_ping_create_delete": True,
                            "direct_fallback": False,
                        }
                    ),
                    flush=True,
                )
            return 0
        finally:
            process.terminate()
            process.wait(timeout=10)


if __name__ == "__main__":
    raise SystemExit(main())
