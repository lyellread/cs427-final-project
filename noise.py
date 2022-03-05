#!/usr/bin/env python3

"""
noise - Nice 'Ol Interactive Stream Encryption

Usage:
    noise keygen KEYFILE [-v]
    noise encrypt INFILE OUTFILE --key=<keyfile> [-v]
    noise decrypt INFILE OUTFILE --key=<keyfile> [-v]

Options:
    -h --help           Show this help message.
    -v --verbose        Show debug output.

    keygen              Generate a new encryption key.
    encrypt, decrypt    Encrypt or decrypt <infile> to <outfile>.
                        Use - as the file for stdin and/or stdout.
    -k --key KEYFILE    Key to use when encrypting or decrypting a file.
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

    logging.debug(f"args: {ARGS}")

    # stdin/out specified?
    if ARGS["INFILE"] == "-":
        ARGS["INFILE"] = sys.stdin.fileno()
    # stdin/out specified?
    if ARGS["OUTFILE"] == "-":
        ARGS["OUTFILE"] = sys.stdout.fileno()

    if ARGS["keygen"]:
        keygen.keygen(ARGS["KEYFILE"])
    elif ARGS["encrypt"]:
        encrypt.enc(ARGS["--key"], ARGS["INFILE"], ARGS["OUTFILE"])
    elif ARGS["decrypt"]:
        encrypt.dec(ARGS["--key"], ARGS["INFILE"], ARGS["OUTFILE"])
