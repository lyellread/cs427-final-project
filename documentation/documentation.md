---
title: CS427 Final Project - Stream File Encryption & Key Management
author:
  - Casey Colley
  - Robert Detjens
  - Lyell Read

colorlinks: true
date: CS 427,  Winter 2022

toc: true
toc-depth: 5
urlcolor: blue
fontsize: 11pt

# add space between title & toc
include-before:
  - \vspace{4cm}

header-includes:
  - \include{macros.tex}
---

\pagebreak

# Abstract

placeholder

\pagebreak

# Stream Encryption and Decryption (`enc`, `dec`)

These define the Encryption and Decryption algorithms used by the program both to encrypt and decrypt the Master Key, and to encrypt and decrypt messages *with* the Master Key.

## Primitives

Our design utilizes a secure block cipher/PRP, $F$. $F$ will be the [AES block cipher](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf) with a 128-bit key. Our program utilizes a Python library for the AES block cipher implementation called [PyAES](https://github.com/ricmoo/pyaes#aes-block-cipher). 

\

\begin{center}
  \fcodebox{
    \codebox{
      \> klen = 128 \\
      \> \\
      \underline{$F_{AES}(k, d):$} \\
      \> BLACK BOX \\
      \> \\
      \underline{$F_{AES}^{-1}(k, d):$} \\
      \> BLACK BOX
    }
  }
\end{center}

## Formal Scheme Definition

Our symmetric encryption mode will be a modified CTR mode. For the Decryption algorithm, we don't really need to have $r$ or $c_0$ as it's simply concatenated with $m_i$ but we have kept it in the definition to better show how our modification resembles true CTR mode. Additionally, $r$ could be used to verify that the decryption was successful, as the resulting block would be $m_i||r$.

\begin{center}
  \fcodebox{
    \codebox{
      \> blen = 128
    }
    \qquad
    \codebox{
      \underline{$\subname{Enc}_{CTR}(k, m_1||...||m_l)$:} \\
      \> $r \gets \bits^{blen}$ \\
      \> $c_0 := r$ \\
      \> for $i = 1$ to $l$: \\
      \> \> $c_i := F(k, m_i||r)$ \\
      \> \> $r := r + 1 \% 2^{blen}$ \\
      \> return $c_0 || ... || c_l$
    }
    \qquad
    \codebox{
      \underline{$\subname{Dec}_{CTR}(k, c_0||...||c_l)$:} \\
      \> $r := c_0$ \\
      \> for $i = 1$ to $l$: \\
      \> \> $m_i := F^{-1}(k, c_i)$ [blen:] \\
      \> \> $r := r + 1 \% 2^{blen}$ \\
      \> return $m_1||...||m_l$
    }
  }
\end{center}

## Security Proof and Reasoning

We will prove that the encryption scheme of our key manager, a modified CTR mode, has security against chosen ciphertext attacks. We assume that F is a secure PRP.

To prove that a scheme has CCA security, we must prove that two random plaintexts (L & R) cannot be distinguished from each other, including any partial information, like so:

\begin{center}
  \titlecodebox{$\lib{CCA-L}^\Sigma$}{
    \codebox{
      \> $k \gets \Sigma.\KeyGen$ \\
      \> $\Seen := \emptyset$ \\
      \> \\
      \underline{$\Eavesdrop(m_L, m_R):$} \\
      \> if $|m_L| \neq |m_R|$: \\
      \> \> return $\err$ \\
      \> $c:= \Sigma.\Enc(k, \mathhighlight{m_L})$ \\
      \> $\Seen := \Seen \union {c}$ \\
      \> return $c$ \\
      \> \\
      \underline{$\Decrypt(c):$} \\
      \> if $c \in S$ return \err \\
      \> return $\Sigma.\Dec(k, c)$
    }
  }
  $\indist$
  \titlecodebox{$\lib{CCA-R}^\Sigma$}{
    \codebox{
      \> $k \gets \Sigma.\KeyGen$ \\
      \> $\Seen := \emptyset$ \\
      \> \\
      \underline{$\Eavesdrop(m_L, m_R):$} \\
      \> if $|m_L| \neq |m_R|$: \\
      \> \> return $\err$ \\
      \> $c:= \Sigma.\Enc(k, \mathhighlight{m_R})$ \\
      \> $\Seen := \Seen \union {c}$ \\
      \> return $c$ \\
      \> \\
      \underline{$\Decrypt(c):$} \\
      \> if $c \in S$ return \err \\
      \> return $\Sigma.\Dec(k, c)$
    }
  }
\end{center}

\

From here, we will walk through the proof for the left library.

\

\begin{center}
  \titlecodebox{$\lib{CCA-L}^\Sigma$}{
    \codebox{
      \> $k \gets \Sigma.\KeyGen$ \\
      \> $\Seen := \emptyset$ \\
      \> \\
      \underline{$\Eavesdrop(m_L, m_R):$} \\
      \> if $|m_L| \neq |m_R|$: \\
      \> \> return $\err$ \\
      \> $c:= \Sigma.\Enc(k, \mathhighlight{m_{1L}||...||m_{lL}})$ \\
      \> $\Seen := \Seen \union {c}$ \\
      \> return $c$ \\
      \> \\
      \underline{$\Decrypt(c):$} \\
      \> if $c \in S$: \\
      \> \> return $\err$ \\
      \> return $\Sigma.\Dec(k, c)$
    }
  }
  $\link$
  \fcodebox{
    \underline{$\subname{Enc}_{CTR}(k, m_{1L}||...||m_{lL}):$} \\
    \> $r \gets \bits^{blen}$ \\
    \> $c_0 := r$ \\
    \> for $i = 1$ to $l$: \\
    \> \> $c_i := F(k, m_{iL}||r)$ \\
    \> \> $r := r + 1 \% 2^{blen}$ \\
    \> return $c_0 || ... || c_l$
  }
  $\indist$
  \titlecodebox{$\lib{CCA-R}^\Sigma$}{
    \codebox{
      \> " "
    }
  }
\end{center}

\

Next, we can turn our attention to the linked encryption scheme. Here we see that for each block, we calculate $F(k, m_i||r)$ for the corresponding ciphertext block. $r$ is sampled randomly, so the chance of collision is $\frac{1}{2^{blen}}$. However, we are doing counter mode, so $r$ for each subsequent block in the message is deterministic, for $l$ blocks in the message. Still, the rate of collision comes to $\frac{l}{2^{blen}}$. The $l$ increases much slower than the $2^{blen}$, which means the rate of collisions is still negligible.

Because $r$ is sampled randomly and has a neglible rate of collisions, $m_i||r$ also has a collision rate of $\frac{l}{2^{blen}}$ even when the same $m_i$ is inputted. It does not matter what $m_i$ is when we concatenate it with $r$ and put it through the PRP $F$. To illustrate this, we can apply the following transformation:

\

\begin{center}
  \titlecodebox{$\lib{CCA-L}^\Sigma$}{
    \codebox{
      \> $k \gets \Sigma.\KeyGen$ \\
      \> $\Seen := \emptyset$ \\
      \> \\
      \underline{$\Eavesdrop(m_L, m_R):$} \\
      \> if $|m_L| \neq |m_R|$: \\
      \> \> return $\err$ \\
      \> $c:= \Sigma.\Enc(k, m_{1L}||...||m_{lL})$ \\
      \> $\Seen := \Seen \union {c}$ \\
      \> return $c$ \\
      \> \\
      \underline{$\Decrypt(c):$} \\
      \> if $c \in S$: \\
      \> \> return $\err$ \\
      \> return $\Sigma.\Dec(k, c)$
    }
  }
  $\link$
  \fcodebox{
    \underline{$\subname{Enc}_{CTR}(k, m_{1L}||...||m_{lL}):$} \\
    \> $\mathhighlight{x} \gets \bits^{blen}$ \\
    \> $c_0 := r$ \\
    \> for $i = 1$ to $l$: \\
    \> \> $c_i := F(k, \mathhighlight{x})$ \\
    \> \> $r := r + 1 \% 2^{blen}$ \\
    \> return $c_0 || ... || c_l$
  }
  $\indist$
  \titlecodebox{$\lib{CCA-R}^\Sigma$}{
    \codebox{
      \> " "
    }
  }
\end{center}

\

Now, $m_{1L}||...||m_{lL}$ is not being used by the $Enc_{CTR}$ function; we can change it to some other name without disrupting the function of the encryption scheme. We can rename this to $m_{1R}||...||m_{lR}$ and inline it into the library.

\

\begin{center}
  \titlecodebox{$\lib{CCA-L}^\Sigma$}{
    \codebox{
      \> $k \gets \Sigma.\KeyGen$ \\
      \> $\Seen := \emptyset$ \\
      \> \\
      \underline{$\Eavesdrop(m_L, m_R):$} \\
      \> if $|m_L| \neq |m_R|$: \\
      \> \> return $\err$ \\
      \> $c:= \Sigma.\Enc(k, \mathhighlight{m_{1R}||...||m_{lR}})$ \\
      \> $\Seen := \Seen \union {c}$ \\
      \> return $c$ \\
      \> \\
      \underline{$\Decrypt(c):$} \\
      \> if $c \in S$: \\
      \> \> return $\err$ \\
      \> return $\Sigma.\Dec(k, c)$
    }
  }
  $\link$
  \fcodebox{
    \underline{$\subname{Enc}_{CTR}(k, \mathhighlight{m_{1R}||...||m_{lR}}):$} \\
    \> $x \gets \bits^{blen}$ \\
    \> $c_0 := r$ \\
    \> for $i = 1$ to $l$: \\
    \> \> $c_i := F(k, x)$ \\
    \> \> $r := r + 1 \% 2^{blen}$ \\
    \> return $c_0 || ... || c_l$
  }
  $\indist$
  \titlecodebox{$\lib{CCA-R}^\Sigma$}{
    \codebox{
      \> " "
    }
  }
\end{center}

\

Let's inline the whole linked function, and re-consider the right library.

\

\begin{center}
  \titlecodebox{$\lib{CCA-L}^\Sigma$}{
    \codebox{
      \> $k \gets \Sigma.\KeyGen$ \\
      \> $\Seen := \emptyset$ \\
      \> \\
      \underline{$\Eavesdrop(m_L, m_R):$} \\
      \> if $|m_L| \neq |m_R|$: \\
      \> \> return $\err$ \\
      \> $c:= \Sigma.\Enc(k, \mathhighlight{m_R})$ \\
      \> $\Seen := \Seen \union {c}$ \\
      \> return $c$ \\
      \> \\
      \underline{$\Decrypt(c):$} \\
      \> if $c \in S$ return \err \\
      \> return $\Sigma.\Dec(k, c)$
    }
  }
  $\indist$
  \titlecodebox{$\lib{CCA-R}^\Sigma$}{
    \codebox{
      \> $k \gets \Sigma.\KeyGen$ \\
      \> $\Seen := \emptyset$ \\
      \> \\
      \underline{$\Eavesdrop(m_L, m_R):$} \\
      \> if $|m_L| \neq |m_R|$: \\
      \> \> return $\err$ \\
      \> $c:= \Sigma.\Enc(k, \mathhighlight{m_R})$ \\
      \> $\Seen := \Seen \union {c}$ \\
      \> return $c$ \\
      \> \\
      \underline{$\Decrypt(c):$} \\
      \> if $c \in S$ return \err \\
      \> return $\Sigma.\Dec(k, c)$
    }
  }
\end{center}

Here we can see in this function, the left and right libraries are indistinguishable. For any calling program $A$, it will not be able to distinguish between the two libraries - aka, it will not be able to obtain any partial information from the scheme. Therefore, the scheme has CCA security, and by extension, has CPA security.

\pagebreak

# Key Generation and Storage (`keygen`)

These define the functions that handle generation and storage of the Master Key and the keys it protects. The Master Key is generated with function `KeyGen`, which samples a string of length `klen`. This sampling will come from the machine's built-in random device, such as `/dev/urandom`.

This Master Key will be stored on the machine, with a hash and encrypted. The encryption and decryption of the Master Key is done in through the modded CTR mode. The hash of the key will be appended before being encrypted, which ensures that it has not been tampered with and that the password was correct.

## Primitives

The primitives we need are the $F_{AES}$ block cipher that we identified earlier. The key to this block cipher will be derived by hashing the text password entered by the user (hence, it must have 128-bit output). The hash we will be using is a Davies-Meyer compression function with our same AES block cipher, $F$. A Davies-Meyer compression function functionally turns a block cipher into a hashing function. No key is needed by the scheme; the "keys" are the blocks of the message itself. The algorithm is defined below:

\

\begin{center}
  \fcodebox{
    \codebox{
      \> blen = 128 \\
      \> \\
      \underline{$\subname{Hash}_{D-M}(m_1||...||m_l$):} \\
      \> $h := \{0\}^{blen}$ \\
      \> for $i = 1$ to $l$: \\
      \> \> $h := F(m_i, h) \oplus h$ \\
      \> return $h$
    }
  }
\end{center}


## Formal Scheme Definition

The encrypted key and its hash will be kept in a file, and the decrypted key will be extracted and used internal to the program only. This is reflected below:

\

\begin{center}
  \fcodebox{
    \codebox{
      \> KeyFile := KeyGen()
    }
    \qquad
    \codebox{
      \underline{KeyGen():} \\
      \> $p :=$ getpass() \\
      \> $ph := \subname{Hash}_{D-M}(p)$ \\
      \> $k \gets \{0, 1\}^{\lambda}$ \\
      \> $k += \subname{Hash}_{D-M}(k)$ \\
      \> $E := \subname{Enc}_{CTR}(ph, k)$ \\
      \> return $E$
    }
    \qquad
    \codebox{
      \underline{DecryptKey():} \\
      \> $p :=$ getpass() \\
      \> $ph := \subname{Hash}_{D-M}(p)$ \\
      \> $k, kh := \subname{Dec}_{CTR}(h, KeyFile)$ \\
      \> $keyH := \subname{Hash}_{D-M}(k)$ \\
      \> if $kh \neq keyH$: \\
      \> \> return $\err$ \\
      \> return $k$
    }
  }
\end{center}

## Security Proof and Reasoning

There are a number of components to these functions. 

To transform the password into a key to use for encryption, we compute the Davies-Meyer hash of the password into 128-bit output. This we use as the key to encrypt our Master Key. 

This key is not stored anywhere, and so is not vulnerable to pass-the-hash attack. Instead to check that the password is correct, the Master Key has a hash created of itself, and then appended to itself. The Master Key and its hash are encrypted together, so that when the password-hash is used as a key to decrypt the KeyFile, we know the password was correct because the resultant hash matches the key preceding it. In this way, the hash-then-encrypt method functions like an HMAC, ensuring both that the password is correct and that the KeyFile has not been tampered with.

Additionally, we have already proved that our modified $\subname{ENC}_{CTR}$ has CCA security. If the password is ever changed on the Key Manager, this would mean that the "plaintext message" changes, and we are guaranteed that an attacker with access to the encrypted KeyFile couldn't obtain partial information about the Master Key.

# Conclusion and Discussion

placeholder
