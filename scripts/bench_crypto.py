"""Local upstream-backend benchmark. No sockets, messages or secret output."""

import argparse
import json
import secrets
import statistics
import time

from private_messenger.config import b64
from private_messenger.crypto.backend import SUITE, operation


def benchmark(rounds=160, payload_size=256):
    alice = operation("generate", local_address=b64(secrets.token_bytes(32)))
    bob = operation("generate", local_address=b64(secrets.token_bytes(32)))
    alice["state"] = operation(
        "initiate",
        state=alice["state"],
        peer_address=bob["state"]["local_address"],
        bundle=bob["bundle"],
    )["state"]
    sizes, encrypt_ms, decrypt_ms = [], [], []
    plaintext = list(secrets.token_bytes(payload_size))
    for _ in range(rounds):
        for sender, recipient in ((alice, bob), (bob, alice)):
            before = time.perf_counter()
            message = operation("encrypt", state=sender["state"], plaintext=plaintext)
            encrypt_ms.append((time.perf_counter() - before) * 1000)
            sender["state"] = message["state"]
            before = time.perf_counter()
            result = operation(
                "decrypt",
                state=recipient["state"],
                peer_address=sender["state"]["local_address"],
                message_type=message["message_type"],
                ciphertext=message["ciphertext"],
            )
            decrypt_ms.append((time.perf_counter() - before) * 1000)
            recipient["state"] = result["state"]
            if result["plaintext"] != plaintext:
                raise RuntimeError("native roundtrip mismatch")
            sizes.append(len(message["ciphertext"]) + 37)
    return {
        "suite": SUITE,
        "messages": len(sizes),
        "payload_bytes": payload_size,
        "wire_bytes_min": min(sizes),
        "wire_bytes_max": max(sizes),
        "wire_bytes_mean": round(statistics.mean(sizes), 2),
        "encrypt_ms_median": round(statistics.median(encrypt_ms), 3),
        "decrypt_ms_median": round(statistics.median(decrypt_ms), 3),
        "alice": operation("status", state=alice["state"]),
        "bob": operation("status", state=bob["state"]),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--rounds", type=int, default=160)
    args = parser.parse_args()
    print(json.dumps(benchmark(args.rounds), indent=2))
