import pytest
import logging

from modules import common


test_messages = [
    b"A" * common.LAMBDA + b"B" * common.LAMBDA + b"C" * common.LAMBDA + b"D" * common.LAMBDA,
    b"A" * common.LAMBDA + b"B" * (common.LAMBDA - 1),
    b"A" * common.LAMBDA + b"B" * common.LAMBDA + b"CCC",
    b"",
]

@pytest.mark.parametrize('msg', test_messages)
def test_encrypt_determinism(msg):
    # print("\n=== E/D DET TEST === ")

    key = common.get_random_bytes(common.LAMBDA)
    # print(f"Testing with message {msg.hex()} and key {key.hex()}")
    ctx1 = common.encrypt(key, msg)
    # print(f"Testing again with message {msg.hex()} and key {key.hex()}")
    ctx2 = common.encrypt(key, msg)

    # print(f"Encryption 1                 : {ctx1.hex()}")
    # print(f"Encryption 2                 : {ctx2.hex()}")

    # print(f"Encrypt is non-deterministic : {ctx1!=ctx2}")

    assert ctx1 != ctx2


@pytest.mark.parametrize('msg', test_messages)
def test_pad_determinism(msg):
    # print(f"\n=== PAD UNPAD DET TEST ===")

    # print(f"Original Message         : {common.chunk_blocks(msg)}")
    padded = common.pad(common.chunk_blocks(msg))
    # print(f"Padded Message           : {padded}")
    unpadded = common.unpad(padded)
    # print(f"Unpadded Message         : {unpadded}")

    # print(f"Pad / Unpad Are Inverses : {padded==unpadded}")

    assert unpadded == common.chunk_blocks(msg)


@pytest.mark.parametrize('msg', test_messages)
def test_mac_determinism(msg):
    # print(f"\n=== MAC DET TEST ===")

    key1 = common.get_random_bytes(common.LAMBDA)
    key2 = common.get_random_bytes(common.LAMBDA)
    key3 = common.get_random_bytes(common.LAMBDA)

    enc = common.encrypt(key3, msg)

    mac1 = common.mac(key1, key2, enc)
    # print(f"MAC of Message       : {mac1}")
    mac2 = common.mac(key1, key2, enc)
    # print(f"Again MAC of Message : {mac2}")

    # print(f"MAC is Deterministic : {mac1==mac2}")

    assert mac1 == mac2


@pytest.mark.parametrize('msg', test_messages)
def test_encrypt_decrypt(msg):
    # print("\n=== E/D DEC TEST === ")

    key = common.get_random_bytes(common.LAMBDA)
    # print(f"Testing with message {msg.hex()} and key {key.hex()}")
    ctx = common.encrypt(key, msg)

    # print(f"Encrypted message : {ctx.hex()}")
    out = common.decrypt(key, ctx)
    # print(f"Decrypted message : {out.hex()}")
    # print(f"Successful        : {msg == out}")

    assert msg == out


@pytest.mark.parametrize('msg', test_messages)
def test_hash_determinism(msg):

    # print(f"\n=== HASH TEST ===")

    hh1 = common.hash(msg)
    hh2 = common.hash(msg)
    # print(f"Hash hex              : {hh1.hex()}")
    # print(f"Again Hash hex        : {hh2.hex()}")

    # print(f"Hash is Deterministic : {hh1==hh2}")

    assert hh1 == hh2

@pytest.mark.parametrize('msg', test_messages)
def test_pkbdf_determinism(msg):
    # salt = common.get_random_bytes(common.LAMBDA - 32 // 8)
    salt = b''
    keys1 = common.pkbdf2(msg, salt)
    keys2 = common.pkbdf2(msg, salt)
    # PKBDF2 should be deterministic for the same pw and key
    assert keys1 == keys2
