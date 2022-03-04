import logging


def dec(key, infile, outfile):
    logging.debug(f"decrypting '{infile}' to '{outfile}' with key '{key}'")
