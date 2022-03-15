\pagebreak

# Program Usage

```docopt
noise - Nice 'Ol Interactive Stream Encryption

Usage:
    noise keygen [-v] [KEYFILE]
    noise encrypt --key=KEYFILE [-v] [INFILE] [OUTFILE]
    noise decrypt --key=KEYFILE [-v] [INFILE] [OUTFILE]
    noise --test [-v]

Options:
    -h --help           Show this help message.
    -t --test           Test internal Encrypt and Decrypt algorithms
    -v --verbose        Show debug output.

    keygen              Generate a new encryption key.
    encrypt, decrypt    Encrypt or decrypt INFILE to OUTFILE.
    -k --key KEYFILE    Key to use when encrypting or decrypting a file.

    With no FILEs specified, or when FILEs are -, use stdin/stdout.
```

## Help Menu

By invoking the program as follows, a user can access the command-line documentation for `NOISE` as shown above:

```sh
./noise.py --help
```

## `keygen`

`NOISE`'s `keygen` functionality permits the user to create a keyfile, encrypted with their master password. The user can either supply a path to where the keyfile should be created, or leave the argument blank (or enter `-`) to redirect the keyfile contents to `stdout`. To invoke this subroutine, call the program with:

```sh
./noise.py keygen <path_to_keyfile>
```

Optionally, a user can supply the verbose flag `-v` (or `--verbose`) to get details on the program's functioning and debug issues with the program.

## `encrypt`

`NOISE`'s `encrypt` functionality permits the user to encrypt an arbitrary amount of data. This data can be read from files whose paths are specified as arguments `INFILE` and `OUTFILE`, or the user can choose to use `stdin` and / or `stdout` by leaving these fields blank, or specifying `-`. The user must also supply a keyfile as an argument with `-k` (or `--key`). Invocation of this command is as follows:

```sh
./noise.py encrypt --key=<path_to_keyfile> <path_to_infile> <path_to_outfile>
```

Optionally, a user can supply the verbose flag `-v` (or `--verbose`) to get details on the program's functioning and debug issues with the program.

## `decrypt`

`NOISE`'s `decrypt` functionality permits the user to decrypt an arbitrary amount of data. This data can be read from files whose paths are specified as arguments `INFILE` and `OUTFILE`, or the user can choose to use `stdin` and / or `stdout` by leaving these fields blank, or specifying `-`. The user must also supply a keyfile as an argument with `-k` (or `--key`). Invocation of this command is as follows:

```sh
./noise.py decrypt --key=<path_to_keyfile> <path_to_infile> <path_to_outfile>
```

Optionally, a user can supply the verbose flag `-v` (or `--verbose`) to get details on the program's functioning and debug issues with the program.

## Test Suite

`NOISE` can be called such that it runs a set of self-tests to assure that the algorithms designed meet basic functional requirements. These tests can be invoked by calling the program as follows:

```sh
./noise.py --test
```
