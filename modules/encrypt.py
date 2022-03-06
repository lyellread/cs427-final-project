import logging

from modules import common, keygen


def enc(keyfile, infile, outfile):
    logging.debug(f"Encrypting {infile} to {outfile} with keyfile {keyfile}")

    # Prompt user to decrypt the key
    key = keygen.decrypt_key(keyfile)

    with open(infile, "rb") as fin, open(outfile, "wb") as fout:

        # Get message from file
        msg = fin.read()

        # Encrypt using the decrypted key
        ctx = common.encrypt(key, msg)

        # Write ciphertext to output file
        fout.write(ctx)


def dec(keyfile, infile, outfile):
    logging.debug(f"Decrypting {infile} to {outfile} with keyfile {keyfile}")

    with open(infile, "rb") as fin, open(outfile, "wb") as fout:

        # Prompt user to decrypt the key
        key = keygen.decrypt_key(keyfile)

        # Get ciphertext from file
        ctx = fin.read()

        # Decrypt using the decrypted key
        msg = common.decrypt(key, ctx)

        # Write the plaintext to the output file.
        fout.write(msg)
