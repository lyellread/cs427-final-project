"""
Common cryptographic helper functions, like XORing byte strings.
"""

import os

import pyaes

# lambda aka block size
LAMBDA_BITS = 128  # book uses lambda as # of bits
LAMBDA = LAMBDA_BITS / 8  # but bytestrings are in bytes


def xor(m: bytes, k: bytes) -> bytes:
    if len(m) != len(k):
        raise Exception("xor lengths mismatched")

    return bytes(a ^ b for a, b in zip(m, k))


# salt for hash
# TODO: should this be done in _main_/etc and passed in instead of a constant?
SALT = os.urandom(LAMBDA)


def hash(m: bytes) -> bytes:
    pass


def prp(key: bytes, msg: bytes) -> bytes:
    # this uses AES as a PRP. Works on LAMBDA-length byte strings.

    # PRF / PRPs work on $\bits^\lambda * \bits^lambda -> \bits^\lambda$
    # so make sure inputs are the right size
    assert len(key) == LAMBDA and len(msg) == LAMBDA

    return pyaes.AES(key).encrypt(list(msg))
