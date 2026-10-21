"""Release manifests and Ed25519 signatures with an explicitly trusted public key.

This tool never downloads/installs an update or trusts a key bundled with one.
Signing keys are encrypted PKCS#8 files; passphrases are prompted, never argv.
"""

import argparse
import getpass
import hashlib
import json
import subprocess
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from private_messenger.config import b64, unb64
from private_messenger.storage.vault import atomic_write, read_private


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def create_manifest(root: Path, artifacts: Path) -> dict:
    def git(*args):
        return subprocess.check_output(["/usr/bin/git", "-C", str(root), *args])  # noqa: S603

    if git("status", "--porcelain", "--untracked-files=no").strip():
        raise ValueError("commit tracked changes before making a release manifest")
    files = git("ls-files", "-z").decode().split("\0")
    return {
        "format": "private-messenger-release-v1",
        "source_commit": git("rev-parse", "HEAD").decode().strip(),
        "source_date_epoch": int(git("show", "-s", "--format=%ct", "HEAD")),
        "source_sha256": {name: digest(root / name) for name in files if name},
        "artifact_sha256": {
            p.name: digest(p)
            for p in sorted(artifacts.iterdir())
            if p.is_file() and p.suffix in (".whl", ".gz")
        },
        "security_review": "unaudited experimental development build",
    }


def sign_manifest(manifest: bytes, private: ed25519.Ed25519PrivateKey) -> dict:
    # Domain separation prevents reusing this signature as a protocol message.
    return {
        "format": "private-messenger-ed25519-v1",
        "signature": b64(private.sign(b"private-messenger-release-v1\0" + manifest)),
    }


def verify_manifest(manifest: bytes, signature: dict, trusted_public: bytes) -> None:
    if signature.get("format") != "private-messenger-ed25519-v1":
        raise ValueError("unsupported signature format")
    public = serialization.load_pem_public_key(trusted_public)
    if not isinstance(public, ed25519.Ed25519PublicKey):
        raise ValueError("expected trusted Ed25519 release public key")
    public.verify(unb64(signature["signature"]), b"private-messenger-release-v1\0" + manifest)


def verify_artifacts(manifest: bytes, directory: Path) -> None:
    document = json.loads(manifest)
    if document.get("format") != "private-messenger-release-v1":
        raise ValueError("unsupported manifest format")
    entries = document.get("artifact_sha256")
    if not isinstance(entries, dict) or not entries:
        raise ValueError("manifest must include release artifacts")
    for name, expected in entries.items():
        if (
            Path(name).name != name
            or name in (".", "..")
            or not isinstance(expected, str)
            or len(expected) != 64
        ):
            raise ValueError("invalid artifact manifest entry")
        if digest(directory / name) != expected:
            raise ValueError("release artifact hash mismatch")


def main():
    parser = argparse.ArgumentParser()
    subs = parser.add_subparsers(dest="command", required=True)
    keygen = subs.add_parser("keygen")
    keygen.add_argument("private_key", type=Path)
    keygen.add_argument("public_key", type=Path)
    manifest = subs.add_parser("manifest")
    manifest.add_argument("--root", type=Path, default=Path.cwd())
    manifest.add_argument("--artifacts", type=Path, default=Path("dist"))
    manifest.add_argument("--output", type=Path, required=True)
    sign = subs.add_parser("sign")
    sign.add_argument("manifest", type=Path)
    sign.add_argument("--key", type=Path, required=True)
    sign.add_argument("--output", type=Path, required=True)
    verify = subs.add_parser("verify")
    verify.add_argument("manifest", type=Path)
    verify.add_argument("signature", type=Path)
    verify.add_argument("--trusted-key", type=Path, required=True)
    verify.add_argument("--artifacts", type=Path, help="defaults to manifest's directory")
    args = parser.parse_args()
    if args.command == "keygen":
        secret = getpass.getpass("New release-key passphrase: ")
        if not secret or secret != getpass.getpass("Repeat passphrase: "):
            raise ValueError("nonempty matching passphrases required")
        private = ed25519.Ed25519PrivateKey.generate()
        atomic_write(
            args.private_key,
            private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(secret.encode()),
            ),
            overwrite=False,
        )
        with args.public_key.open("xb") as stream:
            stream.write(
                private.public_key().public_bytes(
                    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )
    elif args.command == "manifest":
        args.output.write_bytes(canonical(create_manifest(args.root, args.artifacts)))
    elif args.command == "sign":
        private = serialization.load_pem_private_key(
            read_private(args.key), password=getpass.getpass("Release-key passphrase: ").encode()
        )
        if not isinstance(private, ed25519.Ed25519PrivateKey):
            raise ValueError("expected Ed25519 release private key")
        args.output.write_bytes(canonical(sign_manifest(args.manifest.read_bytes(), private)))
    else:
        verify_manifest(
            args.manifest.read_bytes(),
            json.loads(args.signature.read_text()),
            args.trusted_key.read_bytes(),
        )
        verify_artifacts(args.manifest.read_bytes(), args.artifacts or args.manifest.parent)
        print("Manifest signature and artifact hashes valid for supplied trusted key.")


if __name__ == "__main__":
    main()
