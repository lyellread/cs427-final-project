import logging


def keygen(keyfile, passphrase=None):
    logging.debug(f"Creating key '{keyfile}' with passphrase '{passphrase}'")
