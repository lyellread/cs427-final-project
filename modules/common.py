"""
Common cryptographic helper functions, like XORing byte strings.
"""

import os
import pyaes
import logging

# lambda aka block size
LAMBDA_BITS = 128  # book uses lambda as # of bits
LAMBDA = LAMBDA_BITS // 8  # but bytestrings are in bytes


def prp(key: bytes, msg: bytes) -> bytes:
    # this uses AES as a PRP. Works on LAMBDA-length byte strings.

    # PRF / PRPs work on $\bits^\lambda * \bits^lambda -> \bits^\lambda$
    # so make sure inputs are the right size
    assert len(key) == LAMBDA and len(msg) == LAMBDA

    return bytes(pyaes.AES(key).encrypt(list(msg)))


def xor(m: bytes, k: bytes) -> bytes:
    if len(m) != len(k):
        raise Exception(f"xor lengths mismatch")

    return bytes(a ^ b for a, b in zip(m, k))


def get_random_bytes(l):
    return os.urandom(l)


def pad(msg: list, len: int) -> list:

    # Stubbed
    return msg


def unpad(ctx: list, len: int) -> list:

    # Stubbed
    return ctx


def test():
    msg = b"AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD"
    key = get_random_bytes(LAMBDA)

    print(f"Testing with message {msg.hex()} and key {key.hex()}")

    ctx = encrypt(key, msg)

    print(f"Encrypted message {ctx.hex()}")

    msg = decrypt(key, ctx)

    print(f"Decrypted message {msg.hex()}")


def encrypt(key: bytes, msg: bytes) -> bytes:
    """
    Return the message provided in msg encrypted using our custom block
    cipher mode with key.

    This mode is defined as follows:

        r <- {0, 1}^lambda
        c_0 := r

        for i=1 to l:
            c_i := F(k, r) XOR m_i
            r := r + 1 % 2

        return c_0 || ... || c_l
    """

    # Parse msg into blocks.
    m = []
    for x in range(len(msg) // LAMBDA):
        m.append(msg[:LAMBDA])
        msg = msg[LAMBDA:]
    if len(msg) % LAMBDA != 0:
        m.append(msg)

    # Pad the array of blocks
    m = pad(m, LAMBDA)

    # Encrypt the message block by block
    c = []
    r = get_random_bytes(LAMBDA)
    c0 = r
    c.append(c0)

    for i in range(len(m)):
        # logging.debug(
        #     f"[Enc] : r:{r.hex()}, m[i]:{m[i].hex()}, key:{key.hex()}, Fk(r):{prp(key, r).hex()}, Fk(r) XOR m[i]:{xor(prp(key, r), m[i]).hex()}"
        # )
        ci = xor(prp(key, r), m[i])
        c.append(ci)
        r = (int.from_bytes(r, "big") + 1 % (2**LAMBDA)).to_bytes(LAMBDA, byteorder="big")

    return b"".join(c)


def decrypt(key: bytes, ctx: bytes) -> bytes:
    """
    Return the ciphertext provided in ctx decrypted using our custom block
    cipher mode with key.

    This mode is defined as follows:

        r = c0

        for i=1 to l:
            mi := F(k, r) XOR ci
            r := r + 1 % 2

        return m1 || ... || ml
    """

    # Check that the ciphertext is valid length
    assert len(ctx) % LAMBDA == 0

    # Parse ctx into blocks.
    c = []
    for x in range(len(ctx) // LAMBDA):
        c.append(ctx[:LAMBDA])
        ctx = ctx[LAMBDA:]

    # Decrypt the message block by block
    m = []
    r = c[0]

    for i in range(1, len(c)):
        # logging.debug(
        #     f"[Dec] : r:{r.hex()}, c[i]:{c[i].hex()}, key:{key.hex()}, Fk(r):{prp(key, r).hex()}, Fk(r) XOR m[i]:{xor(prp(key, r), c[i]).hex()}"
        # )
        mi = xor(prp(key, r), c[i])
        m.append(mi)
        r = (int.from_bytes(r, "big") + 1 % (2**LAMBDA)).to_bytes(LAMBDA, byteorder="big")

    # Remove padding from the array of blocks
    m = unpad(m, LAMBDA)

    return b"".join(m)
