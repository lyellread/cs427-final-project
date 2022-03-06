#!/usr/bin/env python3

"""
noise - Nice 'Ol Interactive Stream Encryption

Usage:
    noise keygen [-v] KEYFILE
    noise encrypt --key=<keyfile> [-v] [INFILE] [OUTFILE]
    noise decrypt --key=<keyfile> [-v] [INFILE] [OUTFILE]
    noise --test

Options:
    -h --help           Show this help message.
    -t --test           Test internal Encrypt and Decrypt algorithms
    -v --verbose        Show debug output.

    keygen              Generate a new encryption key.
    encrypt, decrypt    Encrypt or decrypt INFILE to OUTFILE.
    -k --key KEYFILE    Key to use when encrypting or decrypting a file.

    With no FILEs specified, or when FILEs are -, use stdin/stdout.
"""

from docopt import docopt
import logging
import sys

from modules import encrypt, keygen

if __name__ == "__main__":

    ARGS = docopt(__doc__)

    if ARGS["--verbose"]:
        level = logging.DEBUG
    else:
        level = logging.WARN

    if ARGS["--test"]:
        from modules import test

        test.test_encrypt()
        test.test_hash()
        exit()

    logging.basicConfig(format="%(levelname)s: %(message)s", level=level)
    logging.debug(f"User-supplied command line arguments: {ARGS}")

    # stdin/out specified?
    if ARGS["INFILE"] == "-":
        ARGS["INFILE"] = sys.stdin.fileno()
    if ARGS["OUTFILE"] == "-":
        ARGS["OUTFILE"] = sys.stdout.fileno()

    # no files given?
    if ARGS["INFILE"] is None and ARGS["OUTFILE"] is None:
        ARGS["INFILE"] = sys.stdin.fileno()
    if ARGS["OUTFILE"] is None:
        ARGS["OUTFILE"] = sys.stdout.fileno()

    if ARGS["keygen"]:
        keygen.keygen(ARGS["KEYFILE"])
    elif ARGS["encrypt"]:
        encrypt.enc(ARGS["--key"], ARGS["INFILE"], ARGS["OUTFILE"])
    elif ARGS["decrypt"]:
        encrypt.dec(ARGS["--key"], ARGS["INFILE"], ARGS["OUTFILE"])
