"""
Common cryptographic helper functions, like XORing byte strings.
"""

import os

# lambda aka block size
LAMBDA_BITS = 256  # book uses lambda as # of bits
LAMBDA = LAMBDA_BITS / 8  # but bytestrings are in bytes


def xor(m: bytes, k: bytes) -> bytes:
    if len(m) != len(k):
        raise Exception("xor lengths mismatched")

    return bytes(a ^ b for a, b in zip(m, k))


# salt for hash
# TODO: should this be done in __main__ etc and passed in instead of a constant?
SALT = os.urandom(LAMBDA)


def hash(m: bytes) -> bytes:
    # do the thing
    return
