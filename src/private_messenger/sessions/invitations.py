"""Application invitations, independently of SMP wire fields.

One per contact, authenticated out of band. Signature covers routing, capabilities
and the complete public prekey bundle. Base32 is QR alphanumeric-compatible;
4296 characters is the version-40-L capacity, never an assertion of usability.
"""

import base64
import json
import time
import zlib

from private_messenger.config import Server, b64, unb64
from private_messenger.crypto.backend import SUITE, operation

PREFIX = "PMS2:"
MAX_INVITATION = 4296
DOMAIN = b"private-messenger invitation v2\0"
BUNDLE_LENGTHS = {
    "identity": 33,
    "prekey": 33,
    "signed_prekey": 33,
    "signed_signature": 64,
    "kem": 1569,
    "kem_signature": 64,
}


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def compact_bundle(bundle: dict) -> dict:
    return {
        key: b64(bytes(value)) if key in BUNDLE_LENGTHS else value for key, value in bundle.items()
    }


def expand_bundle(bundle: dict) -> dict:
    if not isinstance(bundle, dict) or set(bundle) != {*BUNDLE_LENGTHS, "registration_id"}:
        raise ValueError("invalid prekey bundle")
    if type(bundle["registration_id"]) is not int or not 1 <= bundle["registration_id"] < 16380:
        raise ValueError("invalid registration identifier")
    result = {"registration_id": bundle["registration_id"]}
    for name, length in BUNDLE_LENGTHS.items():
        if not isinstance(bundle[name], str):
            raise ValueError("invalid public prekey")
        key = unb64(bundle[name])
        if len(key) != length:
            raise ValueError("invalid public prekey length")
        result[name] = list(key)
    if result["kem"][0] != 0x0A:
        raise ValueError("ML-KEM-1024 required; no downgrade")
    return result


def encode(data: dict, state: dict) -> str:
    expand_bundle(data["bundle"])
    signature = operation("sign", state=state, message=list(DOMAIN + canonical(data)))["signature"]
    envelope = {"data": data, "signature": b64(bytes(signature))}
    invitation = PREFIX + base64.b32encode(
        zlib.compress(canonical(envelope), level=9)
    ).decode().rstrip("=")
    if len(invitation) > MAX_INVITATION:
        raise ValueError("invitation exceeds a single QR code capacity")
    return invitation


def decode(invitation: str, *, now: int | None = None) -> dict:
    if not invitation.startswith(PREFIX) or len(invitation) > MAX_INVITATION:
        raise ValueError("expected a PMS2 invitation")
    payload = invitation[len(PREFIX) :]
    compressed = base64.b32decode(payload + "=" * (-len(payload) % 8))
    decoder = zlib.decompressobj()
    try:
        raw = decoder.decompress(compressed, 8193)
    except zlib.error as exc:
        raise ValueError("invalid invitation compression") from exc
    if len(raw) > 8192 or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise ValueError("invalid or excessive invitation encoding")
    try:
        envelope = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise ValueError("invalid invitation JSON") from exc
    if not isinstance(envelope, dict) or set(envelope) != {"data", "signature"}:
        raise ValueError("invalid invitation envelope")
    data = envelope["data"]
    if not isinstance(data, dict) or set(data) != {
        "v",
        "suite",
        "id",
        "expires",
        "address",
        "server",
        "sender_id",
        "bundle",
    }:
        raise ValueError("invalid invitation fields")
    if type(data["v"]) is not int or data["v"] != 2 or data["suite"] != SUITE:
        raise ValueError("unsupported invitation security capabilities; refusing downgrade")
    clock = int(time.time()) if now is None else now
    if type(data["expires"]) is not int or not clock < data["expires"] <= clock + 8 * 86400:
        raise ValueError("expired invitation or unsupported expiry")
    for key, size in (("id", 32), ("address", 32), ("sender_id", 24)):
        if not isinstance(data[key], str) or len(unb64(data[key])) != size:
            raise ValueError("invalid invitation identifier")
    if not isinstance(data["server"], str) or len(data["server"]) > 512:
        raise ValueError("invalid invitation router")
    Server.parse(data["server"])
    bundle = expand_bundle(data["bundle"])
    if not isinstance(envelope["signature"], str):
        raise ValueError("invalid invitation signature encoding")
    signature = unb64(envelope["signature"])
    if (
        len(signature) != 64
        or not operation(
            "verify",
            identity=bundle["identity"],
            message=list(DOMAIN + canonical(data)),
            signature=list(signature),
        )["valid"]
    ):
        raise ValueError("invitation signature verification failed")
    for key, signature_key in (("signed_prekey", "signed_signature"), ("kem", "kem_signature")):
        if not operation(
            "verify",
            identity=bundle["identity"],
            message=bundle[key],
            signature=bundle[signature_key],
        )["valid"]:
            raise ValueError("prekey signature verification failed")
    return data
