"""
Common cryptographic helper functions, like XORing byte strings.
"""

import logging
import os
from math import ceil

import pyaes

# Define the block size
LAMBDA_BITS = 128  # The AES implementation we are using is defined to be 128 bit
LAMBDA = LAMBDA_BITS // 8  # Convert into bytes from bits to use with bytestrings


def prp(key: bytes, msg: bytes) -> bytes:
    """
    Implementation of a Pseudorandom Permutation or Block Cipher
    This PRP works on LAMBDA-byte-strings.
    """

    # Assert the input lengths are correct
    assert len(key) == LAMBDA and len(msg) == LAMBDA, "Internal Error: inputs to PRP have incorrect length"

    # Use AES as the PRP to encrypt one block of msg
    ctx = bytes(pyaes.AES(key).encrypt(list(msg)))

    # Check that the output length of the PRP is of block length
    assert len(ctx) == LAMBDA, "Internal Error: output of PRP has incorrect length"

    return ctx


def xor(m: bytes, k: bytes) -> bytes:
    """
    Computes XOR between m and k
    """

    # Check that the arguments are the same length.
    assert len(m) == len(k), "Internal Error: inputs to XOR have incorrect length"

    return bytes(a ^ b for a, b in zip(m, k))


def get_random_bytes(len: int) -> bytes:
    """
    Uses /dev/urandom to get len random bytes
    """

    return os.urandom(len)


def chunk_blocks(msg: bytes, size=LAMBDA) -> list:
    """
    Split msg into size-length chunks (blocks).

    This does *not* pad the last block.
    """

    m = []

    if len(msg) == 0:
        # if m is empty string. append empty string to list
        m.append(b"")
    else:
        # Chunk message into LAMBDA-length blocks if not empty
        num_chunks = ceil(len(msg) / size)
        for _ in range(num_chunks):
            m.append(msg[:size])
            msg = msg[size:]

    return m


def pad(msg: list, length=LAMBDA) -> list:
    """
    Applies the appropriate padding to the blocks provided as a list of blocks.

    This padding scheme consists of adding null bytes for all but the last byte of
    padding, which is reserved for the total count of padding bytes (including itself)
    which are added.

    In the case where all blocks are LAMBDA-sized, a new block is added which consists
    of LAMBDA-1 null bytes followed by a byte containing the value LAMBDA.
    """

    # print(f"[Pad] : Pre-padding msg: {msg}")

    assert len(msg[-1]) <= length, "Internal Error: input to Pad has incorrect length"

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
    assert len(msg[-1]) == length, "Internal Error: output of Pad has incorrect length"

    return msg


def unpad(msg: list, length=LAMBDA) -> list:
    """
    This function performs the inverse of pad(). It takes an array of message
    blocks and removes the padding from the last one by reading the last byte
    of the last block and removing exactly that many bytes from the end of
    the supplied message.
    """

    # print(f"[Unpad] : Pre-unpadding msg: {msg}")

    # Read last byte of last ciphertext block to determine padding to remove
    padding_byte = msg[-1][-1]

    if padding_byte == length:
        # We can simply discard the last block of the plaintext
        msg = msg[:-1]

        # handle empty array correctly
        if len(msg) == 0:
            msg.append(b"")

    else:
        # We must manipulate the bytes of the last block
        msg[-1] = msg[-1][:-padding_byte]

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
        # logging.debug(f"[Enc] : r:{r.hex()}, m[i]:{m[i].hex()}, key:{key.hex()}")
        # logging.debug(f"[Enc] : lengths: r:{len(r)}, m[i]:{len(m[i])}, key:{len(key)}")
        # logging.debug(f"[Enc] : Fk(r):{prp(key, r).hex()}, Fk(r) XOR m[i]:{xor(prp(key, r), m[i]).hex()}")

        ci = xor(prp(key, r), m[i])
        c.append(ci)
        r = (int.from_bytes(r, "big") + 1 % (2 ** LAMBDA)).to_bytes(LAMBDA, byteorder="big")

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
    assert len(ctx) % LAMBDA == 0, "Internal Error: input to Decrypt has incorrect size"

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
        r = (int.from_bytes(r, "big") + 1 % (2 ** LAMBDA)).to_bytes(LAMBDA, byteorder="big")

    # Remove padding from the array of blocks
    m = unpad(m, LAMBDA)

    # Join array into a string of bytes for return.
    return b"".join(m)


def hash(msg: bytes) -> bytes:
    """
    Return a LAMBDA-length hash of input `msg`

    This uses the Davies-Meyer compression function with our AES PRP
    to build a hash function out of a block cipher:

    for i = 0 to length / LAMBDA:
        H_i = F(m_i, H_i-1) XOR H_i-1
    return H_i
    """

    # Parse msg into blocks.
    m = chunk_blocks(msg)

    # Pad the array of blocks to ensure all are LAMBDA-length
    m = pad(m, LAMBDA)

    # Set the IV to all zero bytes.
    h = b"\x00" * LAMBDA

    # Perform Davies-Meyer compression
    for m_i in m:
        h = xor(prp(m_i, h), h)

    return h


def mac(key1: bytes, key2: bytes, msg: bytes) -> bytes:
    """
    Return a LAMBDA-length MAC tag of msg

    This uses ECBC-MAC with our AES-based hash and PRP to construct a MAC
    out of a PRF function. In order to ensure security across all sizes of
    inputs, a second key is used for the last block (ECBC-MAC):

    for i = 0 to l - 1:
        t_i = F(k, m_i XOR t_i-1)
    return F(k_2, m_l XOR t_l-1
    """

    # logging.debug(f"[MAC] : msg:{msg.hex()}, key:{key1.hex()},{key2.hex()}")
    # logging.debug(f"[MAC] : lengths: msg:{len(msg)}, key:{len(key1)},{len(key2)}")
    # logging.debug(f"[MAC] : len mod lambda: {len(msg) % LAMBDA}")

    # Input should be padded already
    assert len(msg) % LAMBDA == 0, "Internal Error: input to MAC has incorrect length"

    # Parse msg into blocks.
    m = chunk_blocks(msg)

    # Keep last block for ecbc
    last_block = m.pop()

    # Set IV to all zero bytes
    t = b"\0" * LAMBDA

    # Perform CBC-Mode Encryption
    for m_i in m:
        t = prp(key1, xor(t, m_i))

    return prp(key2, xor(t, last_block))


def pkbdf2(passw: bytes, salt: bytes, output_length: int) -> bytes:
    """
    PKBDF2 is a secure way to extend a key to a key of a desired length
    using an HMAC and padding over many iterations.

    This implementation uses our existing AES/Davies-Meyer-based hash
    over 1000 iterations and generates a 3*lambda-length output.

    This is defined as follows:

        for i = 1 to (desired_length / block_size):
            T_i = F(pass, salt || i)
            for c = 2 to iters:
                T_i = T_i XOR F(pass, T_i)

        return T_1 || T_2 ... || T_i
    """

    # Define reasonable number of iterations
    ITERATIONS = 2048

    output = b""

    # Take hash of password to normalize length to LAMBDA
    passw = hash(passw)

    # Ensure that salt is of proper length
    assert len(salt) == LAMBDA - 4, "Internal Error: PKBDF2 salt has incorrect length"

    # Iterate PBKDF2 several times to generate key
    for i in range(ceil(output_length / LAMBDA)):
        iv = salt + i.to_bytes(4, byteorder="big")
        t = prp(passw, iv)
        for c in range(1, ITERATIONS):
            t = xor(t, prp(passw, t))

        output += t

    return output
