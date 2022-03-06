from modules import common


def test_encrypt():
    print(" === TEST 1 === ")
    # Block aligned
    msg = b"AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD"
    key = common.get_random_bytes(common.LAMBDA)
    print(f"Testing with message {msg.hex()} and key {key.hex()}")
    ctx = common.encrypt(key, msg)
    print(f"Encrypted message {ctx.hex()}")
    out = common.decrypt(key, ctx)
    print(f"Decrypted message {out.hex()} \nSuccessful: {msg == out}")

    print(" === TEST 2 === ")
    # Many short of one block
    msg = b"B"
    key = common.get_random_bytes(common.LAMBDA)
    print(f"Testing with message {msg.hex()} and key {key.hex()}")
    ctx = common.encrypt(key, msg)
    print(f"Encrypted message {ctx.hex()}")
    out = common.decrypt(key, ctx)
    print(f"Decrypted message {out.hex()} \nSuccessful: {msg == out}")

    print(" === TEST 3 === ")
    # One short of a full block
    msg = b"AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCC"
    key = common.get_random_bytes(common.LAMBDA)
    print(f"Testing with message {msg.hex()} and key {key.hex()}")
    ctx = common.encrypt(key, msg)
    print(f"Encrypted message {ctx.hex()}")
    out = common.decrypt(key, ctx)
    print(f"Decrypted message {out.hex()} \nSuccessful: {msg == out}")


def test_hash():
    print("=== HASH TESTING ===")

    message = b"this is a test message!"

    print(f"Hashing test message: {message}")

    hash = common.hash(message)
    print(f"Hash hex: {hash.hex()}")

    print(f"Is hash deterministic? {common.hash(message) == common.hash(message)}")

    print("Trying a different message...")

    message = b"small"
    hash = common.hash(message)
    print(f"Hash hex: {hash.hex()}")

    print("Trying an empty message...")

    message = b""
    hash = common.hash(message)
    print(f"Hash hex: {hash.hex()}")
