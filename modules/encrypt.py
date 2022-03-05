import logging

from modules import common, keygen


def enc(keyfile, infile, outfile):
    logging.debug(f"encrypting {infile} to {outfile} with key {keyfile}")

    with open(keyfile, "rb") as fkey, open(infile, "rb") as fin, open(outfile, "wb") as fout:

        key = fkey.read()
        msg = fin.read()

        ctx = common.encrypt(key, msg)

        fout.write(ctx)


def dec(keyfile, infile, outfile):
    logging.debug(f"decrypting {infile} to {outfile} with key {keyfile}")

    with open(keyfile, "rb") as fkey, open(infile, "rb") as fin, open(outfile, "wb") as fout:

        key = fkey.read()
        msg = fin.read()

        ctx = common.decrypt(key, msg)

        fout.write(ctx)
