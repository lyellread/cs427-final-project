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

<!-- 
TODO: Fix F name throughout and subname is always used
TODO: Check schemes for accuracy
TODO: Standardize keyfile / key file
TODO: Fix all references to reference Sigma, like \\K 
-->

\pagebreak

# Abstract


As the final assessment for CS 427: Cryptography, we developed and proved the security of a program named `NOISE` (`N`ice `O`l' `I`nteractive `S`tream `E`ncryption). `NOISE` is made up of two tools which are accessible using the command line: a [Key Generation and Storage] module, and tools to perform [Stream Encryption and Decryption]. The former can generate random keys, encrypt these for storage in a key file using a user-supplied password, and retrieve keys from key files. The encryption and decryption functions are able to accept file inputs or read from and to `stdin` and `stdout` depending on the usage. 

This project is a culmination of the concepts presented throughout CS 427, notably including security standards and definitions, evaluations of cryptographic protocol weaknesses, understanding cryptographic threat models, and general ability to use and prove the security of systems built out of cryptographic building blocks.

<!-- # Architecture

As mentioned, `NOISE` consists of two major parts: `Stream Encryption` and `Key Generation`. Each of these parts makes use of several primitives defined in [Primitives] in order to function. These two functions rely on each other, as `Stream Encryption` requires that the `Key Generation` module decrypt and extract the relevant keys from the keyfile, while `Key Generation` makes use of `Stream Encryption`'s encryption function to secure keyfiles. Each of these parts of the program are described in their respective sections: `Stream Encryption` is defined in [Stream Encryption and Decryption] and `Key Generation` is defined in [Key Generation and Storage]. -->

# Notations and Terminology

Through this report, the standard notations from CS 427: Cryptography will be used. This includes symbols such as "$\gets$" ("samples uniformly from") and the hybrid proof format. In addition, the scheme $\Sigma$ will be used throughout to encapsulate several primitives that are referenced by `NOISE` constructions, accessing these subroutines will take the form $\sig{SubroutineName}$. 

As a point of clarification, there are multiple subroutines with names that hint at Key Generation. Specifically, at first glance, the construction in [Key Generation and Storage] might be confused with $\sig{KeyGen}$, however this abstraction of $\sig{KeyGen}()$ into the set of primitives in [Primitives] represents an attempt at mirroring the way that `NOISE` is programmed.

TODO: no () on function calls

\pagebreak

# Primitives

TODO: set c in PBKDF
TODO: get a hash in PBKDF

Throughout `NOISE`, several primitives are used. These primitives are defined below as member subroutines to the scheme $\Sigma$.

\begin{center}
  \titlecodebox{$\Sigma$}{
    \codebox{
      $\K = \bits^{128}$ \\
      $\M = \bits^{128}$ \\
      $\C = \bits^{128}$ \\
      $\T = \bits^{128}$ \\
      $\Seen = \bits^{96}$ \\
      \\
      $\text{blen} := 128$ \comment{\#bits} \\
      $\text{klen} := 384$ \comment{\#bits} \\
      \\
      \underline{$\subname{KeyGen}()$:}\\
      \> $k \gets \K$ \\
      \> return $k \in \K$ \\
      \\
      \underline{$\subname{GetSalt}()$:}\\
      \> $s \gets \Seen$ \\
      \> return $s \in \Seen$ \\
      \\
      \underline{$\subname{Enc}_{\text{CTR}}(k \in \K, m_1 || \cdots || m_l \in \M)$:} \\
      \> $r \gets \bits^{\text{blen}}$ \\
      \> $c_0 := r$ \\
      \> for $i = 1$ to $l$: \\
      \> \> $c_i := \sig{F}(k, r) \oplus m_i$ \\
      \> \> $r := r + 1 \text{ mod } 2^{\text{blen}}$ \\
      \> return $c_0 || \cdots || c_l \in \C$\\
      \\
      \underline{$\subname{Dec}_{\text{CTR}}(k \in \K, c_0 || \cdots || c_l \in \C)$:} \\
      \> $r := c_0$ \\
      \> for $i = 1$ to $l$: \\
      \> \> $m_i := \sig{F}(k, r) \oplus c_i$\\
      \> \> $r := r + 1 \text{ mod } 2^{\text{blen}}$ \\
      \> return $m_1 || \cdots || m_l \in \M$ \\
      \\
      \underline{$\subname{F}_{\subname{AES-128}}^{-1}(k \in \K, c \in \C)$:} \\
      \> \comment{\# AES-128 Decryption} \\
      \> return $m \in \M$
    }
    \qquad
    \codebox{
      \underline{$\subname{F}_{\subname{AES-128}}(k \in \K, m \in \M)$:} \\
      \> \comment{\# AES-128 Encryption} \\
      \> return $c \in \C$\\
      \\
      \underline{$\subname{GetTag}(k_1 \in \K, k_2 \in \K, m_0 || \cdots || m_l \in \M)$:} \\
      \> $x := m_l$ \\
      \> $t := \bit{0}^{\text{blen}}$ \\
      \> for $i=0$ to $i = l-1$: \\
      \> \> $t := F(k_1, t \oplus m_i)$ \\
      \> $t := F(k_2, t \oplus x)$ \\
      \> return $t \in \T$ \\
      \\
      \underline{$\subname{CheckTag}(k_1 \in \K, k_2 \in \K, m_0 || \cdots || m_l \in \M, t \in \T)$:} \\
      \> return $t \qequiv \sig{GetTag}(k_1, k_2, m_0 || \cdots || m_l)$ \\
      \\
      \underline{$\subname{PBKDF2}(p \in \bits^*, s \in \Seen)$:} \\
      \> for $i = 1$ to $\frac{\text{klen}}{\text{blen}}$: \\
      \> \> $u_1 := \subname{F}_{\subname{AES-128}}(p, s || i)$ \\
      \> \> $t_i := u_1$ \\
      \> \> for $j = 2$ to $c$: \\
      \> \> \> $u_j := \subname{F}_{\subname{AES-128}}(p, u_{i-1}$) \\
      \> \> \> $t_i := t_i \oplus u_j$ \\
      \> $t := t_1 || \cdots || t_{\frac{\text{klen}}{\text{blen}}}$ \\
      \> return $t \in \bits^\text{klen}$ \\
      \\
      \underline{$\subname{Pad}(m)$:} \\
      \> $d = [\text{blen}-(\subname{BitLength}(m) \text{ mod blen})]/8$ \\
      \> $m := m || [\bit{0x00}_0 || \cdots || \bit{0x00}_{(d-1)} || \subname{HexByte}(\text{d})]$ \\
      \\
      \underline{$\subname{UnPad}(m)$:} \\
      \> $d = \subname{GetLastByte}(m)$ \\
      \> $m := m[:-d]$ \comment{\# Remove d bytes of padding}
    }
  }
\end{center}

\pagebreak

## Explanation of Primitive Choices

### Block Cipher

Our design utilizes an Block Cipher, $\sig{F}_{\subname{AES-128}}$. $\sig{F}_{\subname{AES-128}}$ is a [$\subname{AES-128}$ block cipher](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf) with a 128-bit key. We decided to make use of an existing $\subname{AES-128}$ implementation in the [`pyaes` library](https://github.com/ricmoo/pyaes#aes-block-cipher) as implementing $\subname{AES-128}$ from scratch would have been a project in itself. While the NIST standard lays out standard implementations for $\subname{AES-192}$ and $\subname{AES-256}$ as well, we opted to use $\subname{AES-128}$ as our Block Cipher in order to keep the key size and block sizes consistent throughout `NOISE`. This decision was made with the understanding that 128-bit security is relatively low compared with new schemes offering more security, however `NOISE` aims to be readable as an educational resource about cryptographic primitives in use, therefore maximum security was not the goal. This block cipher is not implemented above in the $\Sigma$ scheme, as the AES implementation is too long to include in this document.

### Block Cipher Mode

`NOISE` makes use of $\sig{Enc}_{\text{CTR}}$ and $\sig{Dec}_{\text{CTR}}$ subroutines to encrypt and decrypt data. We opted to use Counter (CTR) block cipher mode for this purpose as it provides CPA security and is simple to implement.

### Message Authentication Code

TODO: Add description of rationale for choosing ECBC-MAC.

These two functions define our MAC scheme, which is an ECBC-MAC. This relies on our AES block cipher internally, and takes two keys in its implementation.

### Password Based Key Derivation Function

To effectively turn a password into an encryption key, `NOISE` implements $\sig{PBKDF2}$. PBKDF2 is an established Key Derivation Function (KDF). This function repeatedly calls a PRF to generate each block of the key. After this key is generated, we will use it to decrypt the keyfile. 

One consideration might be: why use PBKDF2 instead of a more modern KDF like [scrypt](https://www.tarsnap.com/scrypt.html) or [Argon2](https://github.com/P-H-C/phc-winner-argon2#argon2)? These modern KDFs were designed to address the issue of older KDFs being vulnerable to GPU cracking. As mentioned previously, we designed `NOISE` because we're prioritizing an educational demonstration of cryptographic concepts over an implementation of maximum security. `scrypt` itself makes calls to PBKDF2 in its [algorithm](https://datatracker.ietf.org/doc/html/rfc7914#section-6). PBKDF2 is a suitable primitive for use with `NOISE`.

PBKDF2 requires a pseudorandom function as part of its algorithm. In [RFC8018](https://datatracker.ietf.org/doc/html/rfc8018#section-5.2), an example PRF given is an HMAC. Instead, the PRF we will be using is our AES block cipher $F_{AES}$ defined previously. A secure PRP is a also a secure PRF. We know this because to be a secure PRP, it has to be a secure PRF first, with additional requirements. Additionally, the proving of both PRPs and PRFs are the [exact same library proof](https://joyofcryptography.com/pdf/book.pdf#theorem.464). Therefore, our $\subname{F}_{AES}$ is a secure PRF upon which we can build PBKDF2.

A few parameters are seen in the above definition. $s$ is a salt that can be an arbitrary length. $\text{blen}$ is the fixed length of our PRF output. In this scheme, our PRF spits out 128-bit output. By using the same $\subname{F}_{AES}$ for both our PBKDF2 output and our encryption, we do constrict ourselves to specific input and output lengths throughout our program (namely, 128 bits). $c$ is the number of iterations that the PRF should be applied per block. This should be a very large number.

Lastly, $klen$ is the desired length of the key. While we are restricted to the key-lengths that our encryption algorithm can take (128 bits), we can still change this value. For our purposes of "Enc-then-MAC," we require three keys, which means we want a key of 384 bits that will be split later. A [NIST publication](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf)^["Recommendation for Key Derivation Functions Using Pseudorandom Functions", Section 7.3] allows this usage of generating more than one key per password, as long as the keys selected from the KDF output are disjoint.

\pagebreak

# Stream Encryption and Decryption

`NOISE` features constructions to permit the user in encrypting and decrypting streams of data to and from files of their choice using a specified key. This scheme is described in this section.

## Formal Scheme Definition

The purpose of the Stream Encryption and Decryption functions are to encrypt and decrypt large amounts of data in a secure fashion given a user supplied keyfile (generated with [Key Generation and Storage]). 

The $\subname{Enc}_{\text{Stream}}$ function makes use of the primitives:

- $\sig{Pad}$: A simple padding scheme, roughly implemented in [Primitives].
- $\sig{Enc}_{\text{CTR}}$: Counter (CTR) block cipher mode encryption with 128-bit key and 128-bit block cipher $\sig{F}_{\subname{AES-128}}$. This block cipher mode is implemented in [Primitives] and described in more depth in [Block Cipher Mode]. The choice to use AES-128 as our Block Cipher is discussed in [Block Cipher].
- $\sig{GetTag}_{\text{ECBC}}$: ECBC MAC, described further in [Message Authentication Code] and implemented in [Primitives].

The $\subname{Dec}_{\text{Stream}}$ function makes use of the primitives:

- $\sig{UnPad}$: The padding removal part of our simple padding scheme, roughly implemented in [Primitives].
- $\sig{Dec}_{\text{CTR}}$: Counter (CTR) block cipher mode decryption with 128-bit key and 128-bit block cipher $\sig{F}_{\subname{AES-128}}$. This block cipher mode is implemented in [Primitives] and described in more depth in [Block Cipher Mode]. The choice to use AES-128 as our Block Cipher is discussed in [Block Cipher].
- $\sig{CheckTag}_{\text{ECBC}}$: ECBC MAC check, described further in [Message Authentication Code] and implemented in [Primitives].

\begin{center}
  \codebox{
    \titlecodebox{$\texttt{\upshape NOISE}$}{
      define $k_\text{stream}, k_\text{mac1}, k_\text{mac2} \in \Sigma.\K$ \\
      \\
      \comment{\# Keys are read from file} \\
      $k_\text{stream}, k_\text{mac1}, k_\text{mac2} := \texttt{\upshape NOISE}.\subname{ReadKeys}$ \\
      \\
      \comment{\# Get message from user} \\
      define $m \in \bits^*$ \\
      \\
      \comment{\# Encrypt message} \\
      $c := \subname{Enc}_{\text{Stream}}(k_\text{stream}, k_{\text{mac1}}, k_{\text{mac2}}, m)$: \\
      \\
      \comment{\# Decrypt ciphertext} \\
      $m_1 := \subname{Dec}_{\text{Stream}}(k_\text{stream}, k_{\text{mac1}}, k_{\text{mac2}}, c)$: \\
      \\
      assert $m = m_1$
    }
    $\link$
    \titlecodebox{\lib{Stream}}{
      \codebox{
        \underline{$\subname{Enc}_{\text{Stream}}(k_\text{stream}, k_{\text{mac1}}, k_{\text{mac2}}, m \in \bits^*)$:} \\
        \> $m := \sig{Pad}(m)$ \\
        \> $c := \sig{Enc}_\text{CTR}(k_\text{stream}, m)$ \\
        \> $t := \sig{GetTag}_{\text{ECBC}}(k_\text{mac1}, k_\text{mac2}, c)$ \\
        \> return $c || t$\\
        \\
        \underline{$\subname{Dec}_{\text{Stream}}(k_\text{stream}, k_{\text{mac1}}, k_{\text{mac2}}, c || t \in \Sigma.\T)$:} \\
        \> if $\sig{CheckTag}_{\text{ECBC}}(k_\text{mac1}, k_\text{mac2}, c, t) = \bit{false}$: \\
        \> \> return $\bit{err}$ \\
        \> $m := \sig{Dec}_\text{CTR}(k_\text{stream}, c)$ \\
        \> $m := \sig{UnPad}(m)$ \\
        \> return $m$
      }
    }
  }
\end{center}

## Security Proof and Reasoning

TODO: Rewrite proof completely

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

From here, we will walk through the proof for the left library.

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
    \> $r \gets \bits^{\text{blen}}$ \\
    \> $c_0 := r$ \\
    \> for $i = 1$ to $l$: \\
    \> \> $c_i := F(k, m_{iL}||r)$ \\
    \> \> $r := r + 1 \% 2^{\text{blen}}$ \\
    \> return $c_0 || ... || c_l$
  }
  $\indist$
  \titlecodebox{$\lib{CCA-R}^\Sigma$}{
    \codebox{
      \> " "
    }
  }
\end{center}

Next, we can turn our attention to the linked encryption scheme. Here we see that for each block, we calculate $F(k, m_i||r)$ for the corresponding ciphertext block. $r$ is sampled randomly, so the chance of collision is $\frac{1}{2^{\text{blen}}}$. However, we are doing counter mode, so $r$ for each subsequent block in the message is deterministic, for $l$ blocks in the message. Still, the rate of collision comes to $\frac{l}{2^{\text{blen}}}$. The $l$ increases much slower than the $2^{\text{blen}}$, which means the rate of collisions is still negligible.

Because $r$ is sampled randomly and has a neglible rate of collisions, $m_i||r$ also has a collision rate of $\frac{l}{2^{\text{blen}}}$ even when the same $m_i$ is inputted. It does not matter what $m_i$ is when we concatenate it with $r$ and put it through the PRP $F$. To illustrate this, we can apply the following transformation:

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
    \> $\mathhighlight{x} \gets \bits^{\text{blen}}$ \\
    \> $c_0 := r$ \\
    \> for $i = 1$ to $l$: \\
    \> \> $c_i := F(k, \mathhighlight{x})$ \\
    \> \> $r := r + 1 \% 2^{\text{blen}}$ \\
    \> return $c_0 || ... || c_l$
  }
  $\indist$
  \titlecodebox{$\lib{CCA-R}^\Sigma$}{
    \codebox{
      \> " "
    }
  }
\end{center}

Now, $m_{1L}||...||m_{lL}$ is not being used by the $Enc_{CTR}$ function; we can change it to some other name without disrupting the function of the encryption scheme. We can rename this to $m_{1R}||...||m_{lR}$ and inline it into the library.

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
    \> $x \gets \bits^{\text{blen}}$ \\
    \> $c_0 := r$ \\
    \> for $i = 1$ to $l$: \\
    \> \> $c_i := F(k, x)$ \\
    \> \> $r := r + 1 \% 2^{\text{blen}}$ \\
    \> return $c_0 || ... || c_l$
  }
  $\indist$
  \titlecodebox{$\lib{CCA-R}^\Sigma$}{
    \codebox{
      \> " "
    }
  }
\end{center}

Let's inline the whole linked function, and re-consider the right library.

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

# Key Generation and Storage

<!-- These define the functions that handle generation and storage of keyfiles used by the program. These keyfiles are generated with the function `KeyGen`, which samples a string of length `klen`. This sampling will come from the machine's built-in random device, such as `/dev/urandom`.

These keyfiles are stored encrypted with a password that varies per keyfile. This "password encryption" is implemented by way of Password-Based Key Derivation Function 2 (PBKDF2). This will be expanded upon in the Primitives section.

The keyfiles are also encrypted with a MAC on them. This verifies that if the keyfile was maliciously modified, that this would be detected and you would be unable to use it. Using it would cause errors to the proper encryption and decryption. Of course, using a MAC requires additional keys, and we're only using one password. This is handled by having PBKDF2 ouput a much longer "key". This can then be subdivided into several keys. More on the security properties of this are discussed later.
 -->

`NOISE` features a user-accessible function for key generation ($\lib{KeyGen}$'s function$\subname{KeyGen}$, not to be confused with $\sig{KeyGen}$). This function is responsible for using a user-supplied master password to encrypt new, randomly-generated keys. `NOISE` also features a function named $\subname{GetKeys}$, which is program-internal, and is responsible for retrieving the keys from the keyfile the user has specified, decrypting them with the user's password before returning them to the program.

## Formal Scheme Definition

The Key Generation and Storage part of `NOISE` is fundamentally responsible for properly creating, storing and retrieving cryptographic keys. 

The $\subname{KeyGen}$ function makes use of the primitives:

- $\sig{GetSalt}$: A simple function that randomly samples from the set of all possible salt values, implemented in [Primitives].
- $\sig{PBKDF2}$: Password Based Key Derivation Function which uses several operations to derive keys from password values. This ensures that the computational requirements of brute forcing the password are more significant than simply hashing the master password. This function is implemented in [Primitives] and described further in [Password Based Key Derivation Function].
- $\sig{Enc}_{\text{CTR}}$: Counter (CTR) block cipher mode encryption with 128-bit key and 128-bit block cipher $\sig{F}_{\subname{AES-128}}$. This block cipher mode is implemented in [Primitives] and described in more depth in [Block Cipher Mode]. The choice to use AES-128 as our Block Cipher is discussed in [Block Cipher].
- $\sig{GetTag}_{\text{ECBC}}$: ECBC MAC, described further in [Message Authentication Code] and implemented in [Primitives].

The $\subname{GetKeys}$ function makes use of the primitives:

- $\sig{PBKDF2}$: Password Based Key Derivation Function which uses several operations to derive keys from password values. This ensures that the computational requirements of brute forcing the password are more significant than simply hashing the master password. This function is implemented in [Primitives] and described further in [Password Based Key Derivation Function].
- $\sig{Dec}_{\text{CTR}}$: Counter (CTR) block cipher mode decryption with 128-bit key and 128-bit block cipher $\sig{F}_{\subname{AES-128}}$. This block cipher mode is implemented in [Primitives] and described in more depth in [Block Cipher Mode]. The choice to use AES-128 as our Block Cipher is discussed in [Block Cipher].
- $\sig{CheckTag}_{\text{ECBC}}$: ECBC MAC Check, described further in [Message Authentication Code] and implemented in [Primitives].

\begin{center}
  \codebox{
    \titlecodebox{$\texttt{\upshape NOISE}$}{
      \comment{\# Generate keys} \\
      $k_{\text{stream}}, k_{\text{mac1}}, k_{\text{mac2}} := \subname{KeyGen}()$ \\
      \\
      \comment{\# Get keys from file} \\
      $k_{\text{stream}}, k_{\text{mac1}}, k_{\text{mac2}} := \subname{KeyGen}()$
    }
    $\link$
    \titlecodebox{\lib{KeyGen}}{
      \codebox{
        \underline{$\subname{KeyGen}()$:} \\
        \> $p := \texttt{\upshape NOISE}.\subname{GetPassword}$ \\
        \> $s \gets \sig{GetSalt}$ \\
        \> $k_{\text{stream-temp}} || k_{\text{mac1-temp}} || k_{\text{mac2-temp}} := \sig{PBKDF2}(p, s)$ \\
        \> $k_{\text{stream}}, k_{\text{mac1}}, k_{\text{mac2}} \gets \sig{KeyGen}$ \\
        \> $k_a := k_{\text{stream}} || k_{\text{mac1}} || k_{\text{mac2}}$ \\
        \> $c_k := \sig{Enc}_\text{CTR}(k_{\text{stream-temp}}, k_a) $ \\
        \> $t := \sig{GetTag}_{\text{ECBC}}(k_\text{mac1-temp}, k_{\text{mac2-temp}}, c_k)$ \\
        \> $\texttt{\upshape NOISE}.\subname{WriteToKeyFile}(c_k || t || s)$\\
        \> return $(k_{\text{stream}}, k_{\text{mac1}}, k_{\text{mac2}})$ \\
        \\
        \underline{$\subname{GetKeys}()$:} \\
        \> $p := \texttt{\upshape NOISE}.\subname{GetPassword}$ \\
        \> $c_k || t || s := \texttt{\upshape NOISE}.\subname{ReadFromKeyFile}()$\\
        \> $k_{\text{stream-temp}} || k_{\text{mac1-temp}} || k_{\text{mac2-temp}} := \sig{PBKDF2}(p, s)$ \\
        \> if $\sig{CheckTag}(k_{\text{mac1-temp}}, k_{\text{mac2-temp}}, c_k, t) = \bit{false}$: \\
        \> \> return $\bit{err}$ \\
        \> $k_{\text{stream}} || k_{\text{mac1}} || k_{\text{mac2}} := \sig{Dec}_\text{CTR}(k_{\text{stream-temp}}, c_k)$ \\
        \> return $(k_{\text{stream}}, k_{\text{mac1}}, k_{\text{mac2}})$
      }
    }
  }
\end{center}

## Security Proof and Reasoning

<!-- "Also we should just have to prove the parts of our primitives with pbkdf2 and we should be secure ig" -->

### Use of keyfile hashes

TODO: we no longer use keyfile hashes

The actual keyfile itself contains three keys, as described above. These three keys are concatenated together and then hashed through our Davies-Meyer function. This hash is used as a verification that a) the password is correct, and b) the keyfile is not corrupted. If either of these conditions does not hold, then the program will return an error instead of the correctly-decrypted keys. While a MAC would be ideal here, a MAC requires the use of an additional key. We are unable to do that while continuing use a password to encrypt the keyfile.

The usage (or not) of a MAC for the key storage functions is not important. It is important for the encryption and decryption of files, as those are intended to leave the computer, where eavesdroppers could corrupt and edit the files before they get to their destination. However, for the storage of keyfiles on a single computer, the risk for corruption is a lot lower, and it's not imperative that the keyfiles have MACs computed for them.

# Conclusion and Discussion

In this report, we have methodically gone through each component of our key manager, including the encryption scheme, the Master Key generation and storage, and how we apply our encryption and decryption schemes to the KeyFile in a way that ensures that an attacker cannot gain partial knowledge of either the Master Key, the keys in the key manager, or the messages sent be `NOISE`. 

\newpage

# Appendix A: Changelog

We submitted an initial draft for feedback. Our original design was a modified CTR mode for encryption, and our method for generating a key out of a password was with a simple hash function. We recieved feedback on both parts of this (see Appendix B). In short, our CTR mode was still not CCA-secure, and our password-to-key generation was not an optimal method of doing so. 

To combat these issues, we made a variety of changes. Firstly, we returned to normal CTR mode, and included a MAC, turning into an "Enc-then-MAC" scheme. The MAC we chose for this purpose was an ECBC-MAC. Next, we did further research in how password-generated keys are implemented in the industry. We chose to implement one of these methods, PBKDF2. This is a much more real and  sophisticated way of generating password-derived keys.

One thing that we got right in the initial design was quickly identifying AES as the block cipher / PRP we would use. This allowed us to easily reuse it in our ECBC-MAC and as a PRF in our implementation of PBKDF2.

# Appendix B: Draft Feedback

"Good progress so far. I think it would be helpful to be clearer about what specific problem you're trying to solve. It might help to differentiate your approach from other similar ones, and share design rationale. I admire your efforts to do a security proof but I see some bugs: 

1. if "r" is blen bits long then there is no space left for m 
2. decryption doesn't check r, nor does it separate m||r 
3. This cannot be CCA secure --> I can drop the last ciphertext block and the result is still a valid encryption 
4. It is a little bit more involved than you claim to derive the probability of collisions in r (since you care about collisions in r, r+1, .. r+L). If you are really using passwords rather than true encryption keys, then you should give more details about how the password is converted to a key. Just saying Davies-Meyer doesn't give me enough information (that's like saying "I use CTR mode" without saying what the block cipher is), and it is probably not the ideal way to derive a key from a password anyway." 