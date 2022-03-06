"""
Common cryptographic helper functions, like XORing byte strings.
"""

import logging
import os
from math import ceil

import pyaes

# lambda aka block size
LAMBDA_BITS = 128  # AES is defined in terms of bit length
LAMBDA = LAMBDA_BITS // 8  # but bytestrings are in bytes


def prp(key: bytes, msg: bytes) -> bytes:
    """
    Implementation of a Pseudorandom Permutation or Block Cipher
    This PRP works on LAMBDA-byte-strings.
    """

    # Assert the input lengths are correct
    assert len(key) == LAMBDA and len(msg) == LAMBDA, "Internal Error: Arguments to prp() are of incorrect lengths"

    # Use AES as the PRP to encrypt one block of msg
    ctx = bytes(pyaes.AES(key).encrypt(list(msg)))

    # Check that the output length of the PRP is of block length
    assert len(ctx) == LAMBDA, "Internal Error: Output of prp() is not of correct length."

    return ctx


def xor(m: bytes, k: bytes) -> bytes:
    """
    Computes XOR between m and k
    """

    # Check that the arguments are the same length.
    if len(m) != len(k):
        raise Exception("Arguments to XOR are not the same length.")

    return bytes(a ^ b for a, b in zip(m, k))


def get_random_bytes(len: int) -> bytes:
    """
    Uses /dev/urandom to get len random bytes
    """

    return os.urandom(len)


def chunk_blocks(msg: bytes) -> list[bytes]:
    """
    Split `msg` into LAMBDA-length chunks (blocks).

    This does *not* pad the last block.
    """

    m = []

    if len(msg) == 0:
        # if m is empty string. append empty string to list
        m.append(b"")
    else:
        # Chunk message into LAMBDA-length blocks if not empty
        num_chunks = ceil(len(msg) / LAMBDA)
        for x in range(num_chunks):
            m.append(msg[:LAMBDA])
            msg = msg[LAMBDA:]

    return m


def pad(msg: list[bytes], length: int) -> list[bytes]:

    # print(f"[Pad] : Pre-padding msg: {msg}")

    assert len(msg[-1]) <= length, "Internal Error: Invalid message provided to pad()"

    # Calculate the amount that msg[-1] is under length
    padding_amount = length - len(msg[-1])

    # Check what type of padding is needed
    if padding_amount != 0:
        # Add padding to last block
        # Append the proper number of zero bytes (one less than the total
        #   number of bytes of padding required)
        msg[-1] += b"\x00" * (padding_amount - 1)

        # Set the last byte appended to be equal to the number of bytes of
        #   padding including this byte that have been used)
        msg[-1] += (padding_amount).to_bytes(1, "big")

    else:
        # Add whole new block. Create an empty bytestring
        padding = b""
        # Append the proper number of zero bytes (one less than the block length
        #   provided in length)
        padding += b"\x00" * (length - 1)
        # Set the last byte appended to be equal to the number of bytes of
        #   padding including this byte that have been used, in this case, length)
        padding += length.to_bytes(1, "big")
        # Add new block
        msg.append(padding)

    # print(f"[Pad] : Post-padding msg: {msg}")

    # Assert that our last message - be it new block or modified last block - is
    #   of length length.
    assert len(msg[-1]) == length, "Internal Error: pad() failed to properly pad the provided message."

    return msg


def unpad(msg: list[bytes], length: int) -> list[bytes]:

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
    m = chunk_blocks(msg)

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

    # Recombine array into a string of bytes.
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
    assert len(ctx) % LAMBDA == 0, "Internal Error: Ciphertext provided to decrypt is not an even number of blocks."

    # Parse ctx into blocks.
    c = chunk_blocks(ctx)

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

    # Join array into a string of bytes for return.
    return b"".join(m)


def hash(msg: bytes) -> bytes:
    """
    Return a LAMBDA-length hash of input `msg`

    This uses the Davies-Meyer compression function with our AES PRP to build
    a hash function out of a block cipher:

    for i = 0 to length / LAMBDA:
        H_i = F(m_i, H_i-1) XOR H_i-1
    retun H_i
    """

    # Parse msg into blocks.
    m = chunk_blocks(msg)

    # Pad the array of blocks to ensure all are LAMBDA-length
    m = pad(m, LAMBDA)

    # perform davies-meyer: H_i = F(m_i, H_i-1) XOR H_i-1
    h = b"\0" * LAMBDA  # initial hash value is 0
    for m_i in m:
        h = xor(prp(m_i, h), h)

    return h
