import getpass
import logging

import common
import keygen


def load_key(keyfile):
    """
    Decrypt the specified keyfile by asking for the user's password
    """

    passw = getpass.getpass(prompt="Passphrase for {keyfile}: ")
    return keygen.unlock_key(passw)  # TODO: replace with actual func


def dec(key, infile, outfile):
    logging.debug(f"decrypting '{infile}' to '{outfile}' with key '{key}'")


def enc(key, infile, outfile):
    logging.debug(f"encrypting '{infile}' to '{outfile}' with key '{key}'")

    print(common.xor(bytes(infile), bytes(outfile)))
