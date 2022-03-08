import logging

from modules import common, keygen


def enc(keyfile, infile, outfile):
    logging.debug(f"Encrypting {infile} to {outfile} with keyfile {keyfile}")

    # Prompt user to decrypt the key
    k_enc, k_mac1, k_mac2 = keygen.decrypt_key(keyfile)

    with open(infile, "rb") as fin, open(outfile, "wb") as fout:

        # Get message from file
        msg = fin.read()

        # Encrypt using the decrypted key
        ctx = common.encrypt(k_enc, msg)

        # Append MAC tag
        ctx += common.mac(k_mac1, k_mac2, ctx)

        # Write ciphertext to output file
        fout.write(ctx)


def dec(keyfile, infile, outfile):
    logging.debug(f"Decrypting {infile} to {outfile} with keyfile {keyfile}")

    # Prompt user to decrypt the key
    k_enc, k_mac1, k_mac2 = keygen.decrypt_key(keyfile)

    with open(infile, "rb") as fin, open(outfile, "wb") as fout:

        # Get ciphertext from file
        ctx_mac = fin.read()

        # Verify MAC tag
        ctx = ctx_mac[: -common.LAMBDA]
        mac = ctx_mac[-common.LAMBDA :]

        # logging.debug(f"[DEC] Stored MAC: {mac.hex()}")
        # logging.debug(f"[DEC] Calc'd MAC: {common.mac(k_mac1, k_mac2, ctx).hex()}")

        assert mac == common.mac(k_mac1, k_mac2, ctx), "Invalid Input: invalid MAC tag"

        # Decrypt using the decrypted key
        msg = common.decrypt(k_enc, ctx)

        # Write the plaintext to the output file.
        fout.write(msg)
