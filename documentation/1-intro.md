\pagebreak

# Abstract

As the final assessment for CS 427: Cryptography, we have developed and proved the security of a program named `NOISE` (`N`ice `O`l' `I`nteractive `S`tream `E`ncryption). `NOISE` is made up of two command line utilities. [Key Generation and Storage]The former generates random keys and stores them to a file encrypted using a user-supplied password, and can also retrieve and decrypt those keys. [Stream Encryption and Decryption]The encryption and decryption tools use those keys to encrypt and decrypt files via symmetric-key encryption with a block cipher.

This project is a culmination of the concepts presented throughout CS 427, notably including security standards and definitions, evaluations of cryptographic protocol weaknesses, understanding cryptographic threat models, and general ability to use and prove the security of systems built out of cryptographic building blocks.

# Notations and Terminology

Through this report, the standard notations from CS 427 will be used. This includes symbols such as "$\gets$" ("samples uniformly from") and the hybrid proof format. In addition, the scheme $\Sigma$ will be used throughout to encapsulate several primitives that are referenced by `NOISE` constructions, accessing these subroutines will take the form $\sig{SubroutineName}$. See [Primitives] for a full definition of all constructions used.

As a point of clarification, there are multiple subroutines with names that hint at Key Generation. The construction in [Key Generation and Storage], $\subname{KeyGeneration}$, should not be confused with the $\sig{KeyGen}$ primitive. These functions do perform similar actions, however $\subname{KeyGeneration}$ follows the full implementation of the `keygen` utility in `NOISE` which uses multiple primitives to produce a useful result.
