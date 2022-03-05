import logging
import sys

from modules import common, keygen


def enc(keyfile, infile, outfile):
    logging.debug(f"encrypting ./{infile}' to ./{outfile} with key ./{keyfile}")

    # stdin/out specified?
    if infile == "-":
        infile = sys.stdin.fileno()
    if outfile == "-":
        outfile = sys.stdout.fileno()

    with open(keyfile, "rb") as fkey, open(infile, "rb") as fin, open(outfile, "wb") as fout:
        pass


def dec(keyfile, infile, outfile):
    logging.debug(f"decrypting ./{infile}' to ./{outfile} with key ./{keyfile}")

    # stdin/out specified?
    if infile == "-":
        infile = sys.stdin.fileno()
    if outfile == "-":
        outfile = sys.stdout.fileno()

    with open(keyfile, "rb") as fkey, open(infile, "rb") as fin, open(outfile, "wb") as fout:
        pass
