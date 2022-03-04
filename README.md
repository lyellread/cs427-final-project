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
    noise keygen <keyfile> [-v]
    noise encrypt <infile> <outfile.noise> --key=<keyfile> [-v]
    noise decrypt <infile.noise> <outfile> --key=<keyfile> [-v]

Options:
    keygen            Generate a new encryption key
    encrypt           Encrypt the file <infile> to <outfile.noise>
    decrypt           Decrypt the file <infile.noise> to <outfile>
    -h --help         Show this help message
    -v --verbose      Show debug output
    -k --key KEYFILE  Key to use when encrypting or decrypting a file
```
