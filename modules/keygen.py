import logging

import common


def keygen(keyfile, passphrase=None):
    logging.debug(f"creating key '{keyfile}' with passphrase '{passphrase}'")
