"""Run an unmodified upstream smp-server in a disposable network namespace.

Usage: .venv/bin/python scripts/test_local_reference.py /path/to/upstream/smp-server
Never installs a service or exposes the test server to external interfaces.
"""

import argparse
import base64
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("server_binary", type=Path)
    parser.add_argument("--parent-netns", help=argparse.SUPPRESS)
    args = parser.parse_args()
    current_namespace = os.readlink("/proc/self/ns/net")
    if args.parent_netns is None:
        return subprocess.run(  # noqa: S603 -- fixed unshare executable, no shell
            [
                "/usr/bin/unshare",
                "--user",
                "--map-root-user",
                "--net",
                sys.executable,
                __file__,
                str(args.server_binary),
                "--parent-netns",
                current_namespace,
            ],
            check=False,
        ).returncode  # noqa: S603
    if current_namespace == args.parent_netns:
        parser.error("run in a disposable network namespace, as documented above")
    subprocess.run(["/usr/sbin/ip", "link", "set", "lo", "up"], check=True)  # noqa: S603
    with tempfile.TemporaryDirectory(prefix="pm-reference-") as temporary:
        root = Path(temporary)
        env = dict(
            os.environ,
            SMP_SERVER_CFG_PATH=str(root / "config"),
            SMP_SERVER_LOG_PATH=str(root / "log"),
        )
        binary = str(args.server_binary.resolve())
        subprocess.run(  # noqa: S603 -- user-specified reference executable, no shell
            [binary, "init", "--disable-store-log", "--no-password", "--disable-web", "--yes"],
            env=env,
            check=True,
            capture_output=True,
            timeout=30,
        )  # noqa: S603
        config = root / "config/smp-server.ini"
        config.write_text(
            config.read_text()
            .replace("port = 5223,443", "port = 15223")
            .replace("host = <hostnames>", "host = 127.0.0.1")
        )
        cert = x509.load_pem_x509_certificate((root / "config/ca.crt").read_bytes())
        fp = base64.urlsafe_b64encode(cert.fingerprint(hashes.SHA256())).decode()
        env["PM_LOCAL_SMP_SERVER"] = f"smp://{fp}@127.0.0.1:15223"
        with (root / "server-test.log").open("wb") as log:
            server = subprocess.Popen(  # noqa: S603 -- user-specified reference executable, no shell
                [binary, "start", "--skip-warnings"], env=env, stdout=log, stderr=log
            )  # noqa: S603
            try:
                time.sleep(1)
                if server.poll() is not None:
                    raise RuntimeError(
                        "reference server failed: " + (root / "server-test.log").read_text()
                    )
                result = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "pytest",
                        "-q",
                        "tests/integration",
                        "-m",
                        "local_reference",
                    ],
                    env=env,
                    timeout=120,
                )  # noqa: S603
                return result.returncode
            finally:
                server.terminate()
                server.wait(timeout=10)


if __name__ == "__main__":
    raise SystemExit(main())
