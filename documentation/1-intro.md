\pagebreak

# Abstract

As the final assessment for CS 427: Cryptography, we developed and proved the security of a program named `NOISE` (`N`ice `O`l' `I`nteractive `S`tream `E`ncryption). `NOISE` is made up of two tools which are accessible using the command line: a [Key Generation and Storage] module, and tools to perform [Stream Encryption and Decryption]. The former can generate random keys, encrypt these for storage in a key file using a user-supplied password, and retrieve keys from key files. The encryption and decryption functions are able to accept file inputs or read from and to `stdin` and `stdout` depending on the usage.

This project is a culmination of the concepts presented throughout CS 427, notably including security standards and definitions, evaluations of cryptographic protocol weaknesses, understanding cryptographic threat models, and general ability to use and prove the security of systems built out of cryptographic building blocks.

# Notations and Terminology

Through this report, the standard notations from CS 427: Cryptography will be used. This includes symbols such as "$\gets$" ("samples uniformly from") and the hybrid proof format. In addition, the scheme $\Sigma$ will be used throughout to encapsulate several primitives that are referenced by `NOISE` constructions, accessing these subroutines will take the form $\sig{SubroutineName}$.

As a point of clarification, there are multiple subroutines with names that hint at Key Generation. Specifically, at first glance, the construction in [Key Generation and Storage] might be confused with $\sig{KeyGen}$, however this abstraction of $\sig{KeyGen}$ into the set of primitives in [Primitives] represents an attempt at mirroring the way that `NOISE` is programmed.
