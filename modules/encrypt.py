import getpass
import logging
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def enc(keyfile, infile, outfile):
    logging.debug(f"encrypting ./{infile}' to ./{outfile} with key ./{keyfile}")

    with open(keyfile, "rb") as fkey, open(infile, "rb") as fin, open(outfile, "wb") as fout:

        key = fkey.read()
        iv = os.urandom(16)

        logging.debug(f"key: '{key}' ({len(key)})\niv: '{iv}' ({len(iv)})")

        cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
        encryptor = cipher.encryptor()

        msg = fin.read()
        ctx = encryptor.update(msg) + encryptor.finalize()

        fout.write(iv)
        fout.write(ctx)


def dec(keyfile, infile, outfile):
    logging.debug(f"decrypting ./{infile}' to ./{outfile} with key ./{keyfile}")

    with open(keyfile, "rb") as fkey, open(infile, "rb") as fin, open(outfile, "wb") as fout:

        iv = fin.read(16)
        key = fkey.read()

        logging.debug(f"key: '{key}' ({len(key)})\niv: '{iv}' ({len(iv)})")

        cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
        decryptor = cipher.decryptor()

        ctx = fin.read()
        msg = decryptor.update(ctx) + decryptor.finalize()

        fout.write(msg)
