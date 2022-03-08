#!/usr/bin/env python3

"""
noise - Nice 'Ol Interactive Stream Encryption

Usage:
    noise keygen [-v] [KEYFILE]
    noise encrypt --key=<keyfile> [-v] [INFILE] [OUTFILE]
    noise decrypt --key=<keyfile> [-v] [INFILE] [OUTFILE]
    noise --test [-v]

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

    logging.basicConfig(format="%(levelname)s: %(message)s", level=level)
    logging.debug(f"User-supplied command line arguments: {ARGS}")

    if ARGS["--test"]:
        from modules import test

        test.test_all()
        exit()

    # stdin/out specified?
    if ARGS["KEYFILE"] == "-" or ARGS["KEYFILE"] is None:
        ARGS["KEYFILE"] = sys.stdout.fileno()
    if ARGS["INFILE"] == "-" or ARGS["INFILE"] is None:
        ARGS["INFILE"] = sys.stdin.fileno()
    if ARGS["OUTFILE"] == "-" or ARGS["OUTFILE"] is None:
        ARGS["OUTFILE"] = sys.stdout.fileno()

    if ARGS["keygen"]:
        keygen.keygen(ARGS["KEYFILE"])
    elif ARGS["encrypt"]:
        encrypt.enc(ARGS["--key"], ARGS["INFILE"], ARGS["OUTFILE"])
    elif ARGS["decrypt"]:
        encrypt.dec(ARGS["--key"], ARGS["INFILE"], ARGS["OUTFILE"])
