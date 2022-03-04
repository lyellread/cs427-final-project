import logging

import common


def dec(key, infile, outfile):
    logging.debug(f"decrypting '{infile}' to '{outfile}' with key '{key}'")


def enc(key, infile, outfile):
    logging.debug(f"encrypting '{infile}' to '{outfile}' with key '{key}'")

    print(common.xor(bytes(infile), bytes(outfile)))
