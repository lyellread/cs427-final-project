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

Our design utilizes a secure block cipher/PRP, $F$. $F$ will be the [AES block cipher](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf) with a 128-bit key. Our program utilizes a Python library for the AES block cipher implementation called [PyAES](https://github.com/ricmoo/pyaes#aes-block-cipher). The key to the block cipher will be derived by hashing the text password entered by the user (hence, it must have 128-bit output).

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

\

The hash we will be using is a Davies-Meyer compression function with our AES block cipher, $F$. A Davies-Meyer compression function functionally turns a block cipher into a hashing function. No key is needed by the scheme; the "keys" are the blocks of the message itself. The algorithm is defined below:

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

## Primitives

placeholder

## Shoving this here for now sorry

\begin{center}
  \fcodebox{
    \codebox{
      $m_{1}||...||m_{l} :=$ DecStore \\
      $c_{0}||...||c_{l} :=$ EncStore
    }
    \qquad
    \codebox{
      \underline{EncStore (k):} \\
      \> $c_{0}||...||c_{l} := \subname{Enc}_{CTR}(k, m_{1}||...||m_{l})$ \\
      \> return $c_{0}||...||c_{l}$
    }
    \qquad
    \codebox{
      \underline{DecStore(k):} \\
      \> $m_{1}||...||m_{l} := \subname{Dec}_{CTR}(k, c_{0}||...||c_{l})$ \\
      \> return $m_{1}||...||m_{l}$
    }
  }
\end{center}

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
