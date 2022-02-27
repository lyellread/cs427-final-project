---
title: CS427 Final Project - Key Manager
author:
- Casey Colley
- Robert Detjens
- Lyell Read
date: Winter 2022
---

# Summary

420 cash money

\newpage

# Cryptographic Properties

why r u gae

\newpage

# Specification

## Primitives

Our PRP F will be the AES block cipher with a 256 bit key (the hash that comes from SHA-256)

Our symmetric encryption mode will be CTR mode.

## Password/Key Generation and Storage

\begin{center}



\end{center}

k := KeyGen()   // not stored
s := KeyGen()
H := Pass2Key()
K := EncKey(h, k)

KEYGEN():
  k \gets {0, 1}}^{klen}
  return k

PASS2KEY():
  p := get_passphrase()
  h := SHA256(p||s)
  return h

ENCKEY():
  h := PASS2KEY()
  if h != H:
    return err
  K = CTR mode encryption of k using F(h, k)

DECKEY():
    h := PASS2KEY()
    if h != H:
      return err
    k = CTR mode decryption of K using F(h, K)

Here we define a library of functions that will handle the generation and storage of the Master Key that will be used to encrypt and decrypt the stored keys in the manager. The Master Key is generated with function `KeyGen`, which samples a string of length `klen`. This sampling will come from the machine's built-in random device, such as `/dev/urandom`.

This Master Key will be stored on the machine, encrypted. The encryption and decryption of the Master Key will be done with a password and in the CTR mode, as shown in the remaining two functions, Pass2Key() and EncKey(). The correct, salted hash of the password will be stored alongside the encrypted Master Key. 

EncKey() begins with Pass2Key(), where it will prompt the user for the password, salt it, and then return the SHA256 hash.  EncKey will compare this hash with the stored, correct hash. If they do not match (it is the wrong password), then an error is returned. Otherwise, EncKey will call the CTR mode, using the hashed password as a key/seed to the PRP F. 

## Encryption and Decryption

hee ho

\newpage

# Security Proofs

gg

\newpage
