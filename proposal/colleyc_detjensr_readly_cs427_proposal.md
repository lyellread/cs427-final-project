---
title: Final Project Proposal
author:
- Casey Colley
- Robert Detjens
- Lyell Read
date: Winter 2022 - CS427 Cryptography
---

# Summary

Our project will be the implementation of a basic key manager with a terminal interface. It will have three major
functions: `enc`, `dec`, and `keygen`. When not in use, the keys in the manager will be encrypted with a password in a
symmetric encryption scheme. Messages will be encrypted and decrypted through a block cipher. The utilities will pass
data via STDIN and STDOUT so that the user can take advantage of IO redirection. One password will be used for all of
the keys in the key manager which will be set up on first usage of the utilities. This password is used as the key that
then encrypts the store (a file perhaps) of keys. Upon usage of either the `enc` or `dec` functions, the utility will
prompt the user for a password. The provided password will be used to decrypt the store before the requested key is
taken (whether it was decrypted with the correct password is another story), and then re-encrypted with the provided
password.

# Provable Security

As implied, this file encryption tool uses cryptography to encrypt a file. A file encryptor would not be worth anything
if the encryption could be reversed without the key/secret, so this tool needs to use provably secure encryption
(correctly) in order for the encrypted file to not reveal anything about the original file.

The key generation will use a PRG with the system's random device to generate a key of a specified length, and will use
a PRF-based cipher off of the user's password to decrypt the key to encrypt the file.

# Division of Labor

| Team Member    | Responsibility                              |
|:---------------|:--------------------------------------------|
| Casey Colley   | Report/security proof writing               |
| Robert Detjens | Stream encryption / decryption via user key |
| Lyell Read     | Key generation & password encryption        |

## Justification

There are three distinct parts of this project, with each team member accepting a large workload in order to complete
this project. Casey will be mainly working on composing the documentation and making sure that the implementation
matches the specification. Robert will be designing a program that takes command line arguments and uses a block cipher
to get user input encrypted and written to a file. In addition, this program will prompt the user for a password
interactively but outside of the shell, or before handling any I/O redirection. Lyell will handle the key generation and
at-rest storage of keys, as well as the parsing of the keys into the programs that Robert will develop. Robert and Lyell
will both be responsible for ensuring that their implementations match the designed algorithms for their specific parts.

# Goals

This project allows us to demonstrate the knowledge gained from this course by balancing multiple implementations of
cryptography into a more real-world context. This is a rudimentary example of real tools used professionally. By
actually implementing the "abstract" cryptographic standards that we learn about in class, we learn how these protocols
are used in conjunction with each other to provide tangible security. Looking at one cryptographic standard at a time
works when learning them for the first time in class. But in reality, the applications of these standards is more
complicated. One such problem is, "how do we protect the key?" Our key manager project addresses that question.

# Deliverables

There will be three modes (either as separate binaries or modes of one) as part of this project:

- `keygen`
  - Creates the encryption keys using the system's RNG device
  - Writes key to file encrypted via user passphrase
- `enc`
  - Encrypts specified files into encrypted archive using a private key from `keygen`
- `dec`
  - Decrypts specified archive into original files using a private key from `keygen`
- Written report
    - Description of functionality
    - Cryptographic properties
    - Security proofs

# Project Impact

This program will absolutely benefit the wider community, should we be permitted to open-source it after the class. This
handy utility can be used with more ease than the existing GPG encryption tools to quickly encrypt data.

<<<<<<< Updated upstream
This will also
=======
This will also be a great project to demonstrate to possible employers or to list in a personal portfolio. While it is not a novel invention, per-se, it marginally improves the ease of use of in-terminal simple data encryption, while keeping the scope of this tool minimal in order to limit feature-creep. The thorough documentation of the project will compliment this, making the result a compelling simple example of work quality. 
>>>>>>> Stashed changes

In a similar manner, we plan to compose detailed documentation and document the code in-line such that it is simple for future cryptography students to use our code or algorithms as a basis for future projects or for learning about proving the security of block ciphers.

# Grading Expectations

Our project will merit a good grade if it meets the specifications laid out in this document. Specifically, these criteria can be broken down into the following categories:

- Project Documentation: A complete set of documentation for each component, algorithm and an explanation of the security threat models and guarantees for each. 
  - Documentation in-line within the code produced as part of this project
  - Documentation of `enc`, `dec` and `keygen` to explain command line arguments to end users.
- `enc`, `dec`: Encryption and decryption programs that make use of keys generated within `keygen` to encrypt or decrypt the contents of provided files, following the specifications and security guarantees laid out in the documentation.
- `keygen` generate keys, allowing the user to encrypt keys at rest with a password. These at-rest keys will be encrypted following the specifications in the documentation.

# Expected Resources

We are planning to build our program in Python, so we will likely be consulting the official Python documentation. We do
not think that we will need any special libraries for our project because we are implementing the cryptographic
protocols ourselves. So we will likely be working the most with byte objects, which are a native type to python.
