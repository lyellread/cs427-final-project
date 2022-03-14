\pagebreak

# Abstract

As the final assessment for CS 427: Cryptography, we have developed and proved the security of a program named `NOISE` (`N`ice `O`l' `I`nteractive `S`tream `E`ncryption). `NOISE` is made up of two command line utilities. The key generation and storage tool, implemented as `noise keygen` and discussed in [this section][Key Generation and Storage], generates random keys and stores them to a file encrypted using a user-supplied password, and can also retrieve and decrypt those keys. The file encryption and decryption tools, implemented as `noise encrypt` and `noise decrypt` and discussed in [this section][Stream Encryption and Decryption], use those keys to encrypt and decrypt specified files via symmetric-key encryption.

This project is a culmination of the concepts presented throughout CS 427, notably including security standards and definitions, evaluations of cryptographic protocol weaknesses, understanding cryptographic threat models, and general ability to use and prove the security of systems built out of cryptographic building blocks.

# Notations and Terminology

Throughout this report, the standard notation from CS 427 will be used. This includes symbols such as "$\gets$" ("samples uniformly from") and the hybrid proof format. In addition, the scheme $\Sigma$ will be used throughout to encapsulate several cryptographic primitives that are used throughout the `NOISE` tools. Accessing these primitives will take the form $\sig{SubroutineName}$. See [Primitives] for a full definition of all constructions used. Other library subroutines that use these primitives will take the form $\subname{SubroutineName}$.

As a point of clarification, there are multiple subroutines with names that hint at Key Generation. The construction in [Key Generation and Storage], $\subname{KeyGeneration}$, should not be confused with the $\sig{KeyGen}$ primitive. While both perform similar actions, generating keys, $\subname{KeyGeneration}$ defines the full implementation of the `keygen` utility in `NOISE` which uses several primitives to perform a full procedure.
