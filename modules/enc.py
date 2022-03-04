import logging


def enc(key, infile, outfile):
    logging.debug(f"encrypting '{infile}' to '{outfile}' with key '{key}'")
