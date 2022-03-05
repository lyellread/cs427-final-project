import logging, os
from modules import common
import getpass


def keygen(keyfile):
    logging.debug(f"Creating key '{keyfile}'")

    # Check that we are not overwriting a key file
    assert not os.path.exists(keyfile)

    # Get user password input
    key_password = getpass.getpass(prompt="Password: ")

    # Calculate hash of user input
    password_hash = common.hash(key_password.encode())

    # Get Random Key, Append Hash of Key
    key = common.get_random_bytes(common.LAMBDA)
    key += common.hash(key)

    assert len(key) == 2 * common.LAMBDA

    # Encrypt key using hash of the user password
    encrypted_key = common.encrypt(password_hash, key)

    # Store encrypted key to file
    with open(keyfile, "w") as f:
        f.write(encrypted_key.hex())
