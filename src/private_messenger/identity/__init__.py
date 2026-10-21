"""Local-only identity. All network credentials are generated separately per queue."""

import hashlib
import secrets

from cryptography.hazmat.primitives.asymmetric import ed25519

from private_messenger.config import b64, unb64


def register(vault, name: str) -> dict:
    if vault.get("identity") is not None:
        raise ValueError("identity already exists")
    if not name.strip() or len(name.encode("utf-8")) > 256:
        raise ValueError("name must contain 1..256 UTF-8 bytes")
    key = ed25519.Ed25519PrivateKey.generate()
    identity = {
        "name": name,
        "local_id": b64(secrets.token_bytes(32)),
        "auth_private": b64(key.private_bytes_raw()),
        "auth_public": b64(key.public_key().public_bytes_raw()),
    }
    vault.put("identity", identity)
    return public_profile(identity)


def public_profile(identity: dict) -> dict:
    return {
        "name": identity["name"],
        "local_id": identity["local_id"],
        "fingerprint": hashlib.sha256(unb64(identity["auth_public"])).hexdigest(),
        "scope": "local only; never sent to routers",
    }
