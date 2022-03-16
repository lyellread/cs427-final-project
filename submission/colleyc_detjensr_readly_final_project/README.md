# NOISE: Nice 'Ol Interactive Stream Encryption

A CS427 Final Project

---

## Installation

Install dependencies with [Pipenv](https://github.com/pypa/pipenv):

```sh
pipenv install  # install deps from Pipfile
pipenv shell    # activate project venv
```

## Usage

See `noise.py -h`:

```
Usage:
    noise keygen [-v] KEYFILE
    noise encrypt --key=<keyfile> [-v] [INFILE] [OUTFILE]
    noise decrypt --key=<keyfile> [-v] [INFILE] [OUTFILE]
    noise --test

Options:
    -h --help           Show this help message.
    -t --test           Test internal Encrypt and Decrypt algorithms
    -v --verbose        Show debug output.

    keygen              Generate a new encryption key.
    encrypt, decrypt    Encrypt or decrypt INFILE to OUTFILE.
    -k --key KEYFILE    Key to use when encrypting or decrypting a file.
```
