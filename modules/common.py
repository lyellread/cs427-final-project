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


def pad(msg: list, length: int) -> list:

    # print(f"[Pad] : Pre-padding msg: {msg}")

    padding_offset = len(msg[-1]) % length

    # Check what type of padding is needed
    if padding_offset != 0:
        # Add padding to last block
        msg[-1] += b"\x00" * (length - padding_offset - 1)
        msg[-1] += (length - padding_offset).to_bytes(1, "big")

    else:
        # Add whole new block.
        padding = b""
        padding += b"\x00" * (length - 1)
        padding += length.to_bytes(1, "big")
        msg.append(padding)

    # print(f"[Pad] : Post-padding msg: {msg}")

    assert len(msg[-1]) % length == 0

    return msg


def unpad(msg: list, length: int) -> list:

    # print(f"[Unpad] : Pre-unpadding msg: {msg}")

    # Read last byte of last ciphertext block to determine padding to remove
    padding_byte = msg[-1][-1]

    if padding_byte == length:
        # We can simply discard the last block of the plaintext
        msg = msg[:-1]

    else:
        # We must manipulate the bytes of the last block
        msg[-1] = msg[-1][: (-1 * padding_byte)]

    # print(f"[Unpad] : Post-unpadding msg: {msg}")

    return msg


def test():
    print(" === TEST 1 === ")
    # Block aligned
    msg = b"AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD"
    key = get_random_bytes(LAMBDA)
    print(f"Testing with message {msg.hex()} and key {key.hex()}")
    ctx = encrypt(key, msg)
    print(f"Encrypted message {ctx.hex()}")
    msg = decrypt(key, ctx)
    print(f"Decrypted message {msg.hex()}")

    print(" === TEST 2 === ")
    # Many short of one block
    msg = b"B"
    key = get_random_bytes(LAMBDA)
    print(f"Testing with message {msg.hex()} and key {key.hex()}")
    ctx = encrypt(key, msg)
    print(f"Encrypted message {ctx.hex()}")
    msg = decrypt(key, ctx)
    print(f"Decrypted message {msg.hex()}")

    print(" === TEST 3 === ")
    # One short of a full block
    msg = b"AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCC"
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
        r = (int.from_bytes(r, "big") + 1 % (2 ** LAMBDA)).to_bytes(LAMBDA, byteorder="big")

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
        r = (int.from_bytes(r, "big") + 1 % (2 ** LAMBDA)).to_bytes(LAMBDA, byteorder="big")

    # Remove padding from the array of blocks
    m = unpad(m, LAMBDA)

    return b"".join(m)
