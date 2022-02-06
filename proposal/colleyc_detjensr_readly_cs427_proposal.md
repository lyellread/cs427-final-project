---
title: Final Project Proposal
author:
- Casey Colley
- Robert Detjens
- Lyell Read
date: Winter 2022 - CS427 Cryptography
---

# Summary

Briefly summarize your project topic. Feel free to share any reasons for your personal interest in this topic (i.e., it
involves an application of cryptography to my life's passion).

# Provable Security

As implied, this file encryption tool uses cryptography to encrypt a file. A file encryptor would not be worth anything
if the encryption could be reversed without the key/secret, so this tool needs to use provably secure encryption
(correctly) in order for the encrypted file to not reveal anything about the original file.

The key generation will use a PRG with the system's random device to generate a key of a specified length, and will use
a PRF-based cipher off of the user's password to decrypt the key to encrypt the file.

# Division of Labor

| Team Member    | Responsibility                              |
|----------------|---------------------------------------------|
| Lyell Read     | Key generation & password encryption        |
| Robert Detjens | Stream encryption / decryption via user key |
| Casey Colley   | Documentation & assistance                  |

## Justification

Justify the size of the team in terms of amount of work. Why is the project worth 25% of your grade?

# Goals

How will you demonstrate in-depth understanding that goes beyond what was studied in class?

# Deliverables

There will be three modes (either as separate binaries or modes of one) as part of this project:

- `keygen`
  - Creates the encryption keys using the system's RNG device
  - Writes key to file encrypted via user passphrase
- `enc`
  - Encrypts specified files into encrypted archive using a private key from `keygen`
- `dec`
  - Decrypts specified archive into original files using a private key from `keygen`

# Project Impact

Will you be able to use this project as part of your portfolio? Will the project benefit a wider community (e.g., other
students learning cryptography)?

# Expectations

How should I judge whether your project gets a high grade?

# Expected Resources

List resources/tools that you will likely use.
