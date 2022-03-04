#!/usr/bin/env python3

"""
noise - Nice 'Ol Interactive Stream Encryption

Usage:
    noise keygen <keyfile> [-v]
    noise encrypt <infile> <outfile.noise> --key=<keyfile> [-v]
    noise decrypt <infile.noise> <outfile> --key=<keyfile> [-v]

Options:
    keygen            Generate a new encryption key
    encrypt           Encrypt the file <infile> to <outfile.noise>
    decrypt           Decrypt the file <infile.noise> to <outfile>
    -h --help         Show this help message
    -v --verbose      Show debug output
    -k --key KEYFILE  Key to use when encrypting or decrypting a file

"""

from docopt import docopt
import logging

from modules import enc, dec, keygen

if __name__ == "__main__":
    ARGS = docopt(__doc__)

    if ARGS["--verbose"]:
        level = logging.DEBUG
    else:
        level = logging.WARN

    logging.basicConfig(format="%(levelname)s: %(message)s", level=level)

    logging.debug(f"args: {ARGS}")

    if ARGS["keygen"]:
        keygen.keygen(ARGS["<keyfile>"])
    elif ARGS["encrypt"]:
        enc.enc(ARGS["<keyfile>"], ARGS["<infile>"], ARGS["<outfile.noise>"])
    elif ARGS["decrypt"]:
        dec.dec(ARGS["<keyfile>"], ARGS["<infile.noise>"], ARGS["<outfile>"])
