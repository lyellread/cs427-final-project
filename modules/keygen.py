import getpass
import logging
import os
import sys

from modules import common


def keygen(keyfile):
    logging.debug(f"Creating keyfile '{keyfile}'")

    # Check that we are not overwriting an existing file
    assert not (
        keyfile != sys.stdout.fileno() and os.path.exists(keyfile)
    ), f"Keyfile {keyfile} exists already, and would be overwritten."

    # Get user password input
    key_password = getpass.getpass(prompt="Password: ")

    # Calculate hash of user input
    password_hash = common.hash(key_password.encode())

    # generate 3 keys -- enc, mac1, mac2
    keys = (
        common.get_random_bytes(common.LAMBDA)
        + common.get_random_bytes(common.LAMBDA)
        + common.get_random_bytes(common.LAMBDA)
    )

    # append hash for semi-validity checking
    # cant really use a MAC here since we only have one key (the password)
    keys += common.hash(keys)

    # Check that the key length is as expected
    assert len(keys) == 4 * common.LAMBDA, "Internal Error: Length of key and hash is not as expected."

    # Encrypt key using hash of the user password
    encrypted_key = common.encrypt(password_hash, keys)

    # Store encrypted key to file
    with open(keyfile, "w") as f:
        f.write(encrypted_key.hex())


def decrypt_key(keyfile):
    logging.debug(f"Decrypting and checking keyfile '{keyfile}'")

    # Store encrypted key to file
    with open(keyfile, "r") as f:
        encrypted_key = bytes.fromhex(f.read())

    # Decrypt the encrypted key by getting password from the user
    key_password = getpass.getpass(prompt="Password: ")

    # Calculate hash of user input
    password_hash = common.hash(key_password.encode())

    # Decrypt and check key
    combined_keys = common.decrypt(password_hash, encrypted_key)

    keys = common.chunk_blocks(combined_keys)
    hash_tag = keys.pop()

    if hash_tag != common.hash(b"".join(keys)):
        logging.error("Invalid password or corrupted key")
        exit(1)

    else:
        logging.debug("Key decrypted successfully")

    # Return the decrypted key
    return common.chunk_blocks(keys)[0]
