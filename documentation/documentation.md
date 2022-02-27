---
title: CS427 Final Project - Stream File Encryption & Key Management
author:
  - Casey Colley
  - Robert Detjens
  - Lyell Read
date: CS 427,  Winter 2022
toc: true
toc-depth: 5
include-before:
- '`\vspace{4cm}`{=latex}'
urlcolor: blue
fontsize: 11pt
header-includes:
  - \include{macros.tex}
---

\pagebreak

# Abstract

placeholder

\pagebreak

# Stream Encryption and Decryption (`enc`, `dec`)

placeholder

## Primitives

Our design utilizes $F$, a Block Cipher (PRP). $F$ will be the AES block cipher with a 256-bit key. This key will be derived using a common hashing algorithm, $\subname{SHA-256}$ based on the text password entered by the user. 

- https://www.geeksforgeeks.org/advanced-encryption-standard-aes/
- https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf

\begin{center}
\fcodebox{
  \codebox {
    \> klen = 256 \\
    \> TODO: types declared here
  }
  \qquad
  \codebox{
    \underline{$F_{AES}(k, d)$:} \\
    \> TODO
  }
}
\end{center}

## Formal Scheme Definition

Our symmetric encryption mode will be CTR mode.

\begin{center}
\fcodebox{
  \codebox {
    \> blen = 256 \\
    \> TODO: types declared here
  }
  \qquad
  \codebox{
    \underline{$\subname{Enc}_{CTR}(k, m_1||...||m_l)$:} \\
    \> $r \gets \bits^{blen}$ \\
    \> $c_0 := r$ \\
    \> for $i = 1$ to $l$: \\
    \> \> $c_i := F(k, r) \oplus m_i$ \\
    \> \> $r := r + 1 \% 2^{blen}$ \\
    \> return $c_0 || ... || c_l$
  }
  \qquad
  \codebox{
    \underline{$\subname{Dec}_{CTR}(k, c_0||...||c_l)$:} \\
    \> TODO
  }
}
\end{center}

The hashing function we will use is SHA-256.

\begin{center}
\fcodebox{
  \codebox {
    \> klen = 256 \\
    \> TODO: types declared here
  }
  \qquad
  \codebox{
    \underline{$\subname{Hash}_{SHA-256}(m)$:} \\
    \> TODO
  }
}
\end{center}

## Main

```py
from getpass import getpass

klen, blen = 256

# Stored persistently, in file or otherwise
s = ''
K = ''
H = ''

Init():
  k = KeyGen()
  s = KeyGen()
  print("You will make a new password.")
  H = Pass2Key()
  print("You will enter the password again.")
  K = EncKey()
  print("Vault has been initialized.")

Main():
  if:
    Init()

  k = DecKey()
  # Decrypt vault with k
  print("Vault has been decrypted.")

  #Encryption and Decryption behavior here

  # Re-encrypt vault files with k
  # k is not persistant on shutdown

```

getpass: https://stackoverflow.com/questions/43673886/python-2-7-how-to-get-input-but-dont-show-keys-entered/43673912

## Security Proof and Reasoning

placeholder

\pagebreak

# Key Generation and Storage (`keygen`)

## Primitives

placeholder

## Formal Scheme Definition

\begin{center}
\fcodebox{
  \codebox{
    \> $k := DecKey()$ \\
    \> \\
    \> $s := KeyGen()$ \\
    \> $H := Pass2Key()$ \\
    \> $K := EncKey(h, k)$
  }
  \qquad
  \codebox{
    \underline{KeyGen():} \\
    \> $k \gets \bits^{klen}$ \\
    \> return $k$
  }
  \qquad
  \codebox{
    \underline{Pass2Key():} \\
    \> $p := get\_passphrase()$ \\
    \> $h := Hash_{SHA-256}(p||s)$ \\
    \> return $h$
  }
  \qquad
  \codebox{
    \underline{EncKey(k):} \\
    \> $h := H$ \\
    \> $K := Enc_{CTR}(h, k)$ \\
    \> return $K$
  }
}

\fcodebox{
  \codebox{
    \underline{DecKey(K):} \\
    \> $h := Pass2Key()$ \\
    \> if $h \neq H$: \\
    \> \> return $err$ \\
    \> $k = Dec_{CTR}(h, K)$ \\
    \> return $k$
  }
}
\end{center}

TODO: Define types and formalize scheme in tex

## Security Proof and Reasoning

Here we define a library of functions that will handle the generation and storage of the Master Key that will be used to encrypt and decrypt the stored keys in the manager. The Master Key is generated with function `KeyGen`, which samples a string of length `klen`. This sampling will come from the machine's built-in random device, such as `/dev/urandom`.

This Master Key will be stored on the machine, encrypted. The encryption and decryption of the Master Key will be done with a password and in the CTR mode, as shown in the remaining two functions, Pass2Key() and EncKey(). The correct, salted hash of the password will be stored alongside the encrypted Master Key.

EncKey() begins with Pass2Key(), where it will prompt the user for the password, salt it, and then return the SHA-256 hash.  EncKey will compare this hash with the stored, correct hash. If they do not match (it is the wrong password), then an error is returned. Otherwise, EncKey will call the CTR mode, using the hashed password as a key/seed to the PRP F.

# Conclusion and Discussion

placeholder