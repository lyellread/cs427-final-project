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
    password = getpass.getpass(prompt="Password: ")

    # Generate a random value to use as a salt
    salt = common.get_random_bytes(common.LAMBDA)

    # Create 3 key-encryption keys from password using PKBDF2
    passw_key, passw_mac1, passw_mac2 = common.chunk_blocks(common.pkbdf2(password, salt, common.LAMBDA * 3))

    # generate 3 keys -- enc, mac1, mac2
    keys = (
        common.get_random_bytes(common.LAMBDA)
        + common.get_random_bytes(common.LAMBDA)
        + common.get_random_bytes(common.LAMBDA)
    )

    # Encrypt key using hash of the user password
    encrypted_key = common.encrypt(passw_key, keys)

    # Append MAC to end of ciphertext
    encrypted_key += common.mac(passw_mac1, passw_mac2, encrypted_key)

    # Write password salt and encrypted keys to file
    with open(keyfile, "w") as f:
        f.write(salt.hex())
        f.write(encrypted_key.hex())


def decrypt_key(keyfile):
    logging.debug(f"Decrypting and checking keyfile '{keyfile}'")

    # Store encrypted key to file
    with open(keyfile, "r") as f:
        salt = bytes.fromhex(f.read(common.LAMBDA * 2))  # pull salt from start of file
        key_and_mac = bytes.fromhex(f.read())

    # make sure read-in key is the correct size
    if len(key_and_mac) != common.LAMBDA * 6:
        logging.error("Invalid password or corrupted key")
        exit(1)

    # Decrypt the encrypted key by getting password from the user
    password = getpass.getpass(prompt="Password: ")

    # Create 3 key-encryption keys from password using PKBDF2
    passw_key, passw_mac1, passw_mac2 = common.chunk_blocks(common.pkbdf2(password, salt, common.LAMBDA * 3))

    # Verify MAC before decrypting
    encrypted_key = key_and_mac[: -common.LAMBDA]
    stored_mac = key_and_mac[-common.LAMBDA :]

    if stored_mac != common.mac(passw_mac1, passw_mac2, encrypted_key):
        logging.error("Invalid password or corrupted key")
        exit(1)
    else:
        logging.debug("Key decrypted successfully")

    # Decrypt and check key
    combined_keys = common.decrypt(passw_key, encrypted_key)

    # Return the decrypted key
    return common.chunk_blocks(combined_keys)
