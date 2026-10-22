"""Pinned libsignal crypto only. SMP transport never enters the native module."""

import json

REVISION = "b369755533ef5a3fae9b31b989114f22e074dfab"
SUITE = "PM2-LIBSIGNAL-PQXDH-MLKEM1024-TRIPLE-SPQR1-MLKEM768"


class CryptoUnavailable(RuntimeError):
    pass


def operation(op: str, **arguments) -> dict:
    try:
        from private_messenger import _crypto_native
    except ImportError as exc:
        raise CryptoUnavailable(
            "build the pinned native crypto with scripts/build_crypto.sh"
        ) from exc
    if _crypto_native.UPSTREAM_REVISION != REVISION:
        raise CryptoUnavailable("unexpected native crypto revision; refusing fallback")
    return json.loads(_crypto_native.operation(json.dumps({"op": op, **arguments})))
