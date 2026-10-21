"""SMP's specified NaCl-compatible box, via native libsodium primitives.

The reference applies HSalsa20(key, zero16) even for a symmetric key, before
XSalsa20-Poly1305. PyNaCl SecretBox alone omits this first step. No cipher code
is reimplemented: a narrow ctypes binding calls libsodium crypto_core_hsalsa20.
"""

import ctypes
import ctypes.util
from functools import lru_cache

from nacl.secret import SecretBox


@lru_cache(maxsize=1)
def sodium():
    path = ctypes.util.find_library("sodium")
    if not path:
        raise RuntimeError("native libsodium is required (Ubuntu: libsodium23)")
    library = ctypes.CDLL(path)
    library.sodium_init.argtypes = []
    library.sodium_init.restype = ctypes.c_int
    library.crypto_core_hsalsa20.argtypes = [ctypes.c_void_p] * 4
    library.crypto_core_hsalsa20.restype = ctypes.c_int
    library.sodium_memzero.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    library.sodium_memzero.restype = None
    if library.sodium_init() < 0:
        raise RuntimeError("libsodium initialization failed")
    return library


def precompute(key: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("SMP box key must contain 32 bytes")
    lib = sodium()
    output = ctypes.create_string_buffer(32)
    try:
        if lib.crypto_core_hsalsa20(output, bytes(16), key, None) != 0:
            raise RuntimeError("libsodium HSalsa20 failed")
        return output.raw
    finally:
        lib.sodium_memzero(output, 32)


def encrypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    return SecretBox(precompute(key)).encrypt(data, nonce).ciphertext


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    return SecretBox(precompute(key)).decrypt(ciphertext, nonce)
