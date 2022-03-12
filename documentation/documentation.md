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

To demonstrate proficient Cryptographic knowledge gained from this course, our group designed a NOISE: Nice Ol' Interactive Stream Encryption. This is basically a key manager with built in encryption/decryption of messages with the keys within the manager. This project demonstrated: knowledge of the different definitions of security for different components (encryption schemes, pseudorandom permutations, and compression functions), ability to research further on what was taught in class (to find a suitable PRP, which ended up being AES), ability to write proofs for our cryptographic scheme, and ability to implement in code and test our cryptographic scheme. We wrote this program in Python and utilized a number of different libraries: PyAES, getpass, and docopt.

**NOTE:** Our Python scripts have a few small bugs that we were unable to iron out prior to submission, and will be broken if you try to run them. Please feel free to read through the code however! We started implementing our modified CTR but ran into complications. We have decided to use regular non-CCA secure CTR and add a MAC to ensure CCA security, but this has not been implemented yet.

\pagebreak

# Primitives

Throughout NOISE, several primitives are used. These primitives are defined below as member subroutines to the scheme $\Sigma$.

TODO: Fix F name throughout and subname is always used
TODO: Check schemes for accuracy

\begin{center}
  \titlecodebox{$\Sigma$}{
    \codebox{
      $\K = \bits^{128}$ \\
      $\M = \bits^{128}$ \\
      $\C = \bits^{128}$ \\
      $\T = \bits^{128}$ \\
      \\
      $\text{blen} := 128$ \comment{\#bits} \\
      \\
      \underline{$\subname{Enc}_{\text{CTR}}(k \in \K, m_1 || \cdots || m_l \in \M)$:} \\
      \> $r \gets \bits^{blen}$ \\
      \> $c_0 := r$ \\
      \> for $i = 1$ to $l$: \\
      \> \> $c_i := \Sigma.F(k, r) \oplus m_i$ \\
      \> \> $r := r + 1 \text{ mod } 2^{blen}$ \\
      \> return $c_0 || \cdots || c_l$\\
      \\
      \underline{$\subname{Dec}_{\text{CTR}}(k \in \K, c_0 || \cdots || c_l \in \C)$:} \\
      \> $r := c_0$ \\
      \> for $i = 1$ to $l$: \\
      \> \> $m_i := \Sigma.F(k, r) \oplus c_i$\\
      \> \> $r := r + 1 \text{ mod } 2^{blen}$ \\
      \> return $m_1 || \cdots || m_l$
    }
    \qquad
    \codebox{
      \underline{$F_{\subname{AES-128}}(k \in \K, m \in \M):$} \\
      \> \comment{\# AES-128 Encryption} \\
      \> return $c \in \C$\\
      \\
      \underline{$F_{\subname{AES-128}}^{-1}(k \in \K, c \in \C):$} \\
      \> \comment{\# AES-128 Decryption} \\
      \> return $m \in \M$\\
      \\
      \underline{$\subname{GetTag}(k_1 \in \K, k_2 \in \K, m_0 || \cdots || m_l \in \M):$} \\
      \> $x := m_l$ \\
      \> $t := \bit{0}^{blen}$ \\
      \> for $i=0$ to $i = l-1$: \\
      \> \> $t := F(k_1, t \oplus m_i)$ \\
      \> $t := F(k_2, t \oplus x)$ \\
      \> return $t$ \\
      \\
      \underline{$\subname{CheckTag}(k_1 \in \K, k_2 \in \K, m_0 || \cdots || m_l \in \M, t \in \T):$} \\
      \> return $t \qequiv \Sigma.\subname{GetTag}(k_1, k_2, m_0 || \cdots || m_l)$
      \\
    }
  }
\end{center}

## Explanation of Primitives

### Block Cipher

Our design utilizes a secure block cipher/PRP, $F$. $F$ will be the [AES block cipher](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf) with a 128-bit key. Our program utilizes a Python library for the AES block cipher implementation called [PyAES](https://github.com/ricmoo/pyaes#aes-block-cipher). 


\pagebreak

# Stream Encryption and Decryption (`enc`, `dec`)

These define the Encryption and Decryption algorithms used by the program both to encrypt and decrypt the Master Key, and to encrypt and decrypt messages *with* the Master Key.

## Formal Scheme Definition

TODO: add desc
TODO: add scheme library with keys sampled from random & uses Sigma

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

These define the functions that handle generation and storage of keyfiles used by the program. These keyfiles are generated with the function `KeyGen`, which samples a string of length `klen`. This sampling will come from the machine's built-in random device, such as `/dev/urandom`.

These keyfiles are stored encrypted with a password that varies per keyfile. This "password encryption" is implemented by way of Password-Based Key Derivation Function 2 (PBKDF2). This will be expanded upon in the Primitives section.

The keyfiles are also encrypted with a MAC on them. This verifies that if the keyfile was maliciously modified, that this would be detected and you would be unable to use it. Using it would cause errors to the proper encryption and decryption. Of course, using a MAC requires additional keys, and we're only using one password. This is handled by having PBKDF2 ouput a much longer key. This can then be subdivided into several keys. More on the security properties of this are discussed later.

## Password-Based Key Derivation Function 2 (PBKDF2)

PBKDF2 is an established Key Derivation Function that will be doing the heavy lifting in turning a keyfile's password into a usable "master key" to decrypt it. This function repeatedly calls a PRF to generate each block of the key. After this key is generated, we will use it to decrypt the keyfile.

PBKDF2 requires a pseudorandom function as part of its algorithm. In [RFC2898](https://datatracker.ietf.org/doc/html/rfc2898#appendix-B.1), an example PRF given is an HMAC. Isntead, the PRF we will be using is our AES block cipher $F_{AES}$ defined previously. A PRP is a suitable PRF (more discussion later), so it is the function we are choosing for PBKDF2

A few parameters are seen below. $s$ is a salt that can be an arbitrary length (as it will be hashed down). $blen$ is the fixed length of our PRF output. In this scheme, our PRF spits out 128-bit output. By using the same $\subname{F}_{AES}$ for both our PBKDF2 output and our encryption, we do constrict ourselves to specific input and output lengths throughout our program (namely, 128 bits). $c$ is the number of iterations that the PRF should be applied per block. This should be a very large number.

Lastly, $klen$ is the desired length of the key. While we are restricted to the key-lengths that our encryption algorithm can take (128 bits), we can still change this value. For our purposes of "Enc-then-MAC," we require three keys, which means we want a "key" of 384.

\

\begin{center}
  \fcodebox{
    \codebox{
      \> klen := 384 \\
      \> blen := 128 \\
      \> c := \\
      \underline{PBKDF2(p, s):} \\
      \> for i = 1 to (klen/blen): \\
      \> \> $U_1 := \subname{F}_{AES}(p, s || i)$ \\
      \> \> $T_i$ := $U_1$ \\
      \> \> for j = 2 to c: \\
      \> \> \> $U_j := \subname{F}_{AES}(p, U_{i-1}$) \\
      \> \> \> $T_i := T_i \oplus U_j$ \\
      \> \> $T_i := T_i$
      \> return $T$
    }
  }
\end{center}

\

## Formal Scheme Definition

Our program relies on three secret keys: a key for encryption and decryption of a file, and two keys to generate a MAC for the encrypted file's contents.

The encrypted (and MAC'ed!) keys will be kept in a file, and the decrypted keys will be extracted and used internally within the program only. This is reflected below:

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
      \> $s \gets \{0, 1\}^{\lambda}$ \\
      \> $K := \subname{PBKDF2}(p, s)$ \\
      \> $key \gets \{0, 1\}^{\lambda}$ \\
      \> $mac1 \gets \{0, 1\}^{\lambda}$ \\
      \> $mac2 \gets \{0, 1\}^{\lambda}$ \\
      \> $kh = \subname{Hash}_{DM}(k||mac||mac2)$ \\
      \> $E := \subname{Enc}_{CTR}(K, key||mac1||mac2||kh)$ \\
      \> return $E||s$
    }
    \qquad
    \codebox{
      \underline{DecryptKey():} \\
      \> $p :=$ getpass() \\
      \> $s := Keyfile[-\lambda :]$ \\
      \> $K := \subname{PBKDF2}(p, s)$ \\
      \> $k, mac1, mac2, H := \subname{Dec}_{CTR}(K, KeyFile[: -\lambda])$ \\
      \> $keyH := \subname{Hash}_{DM}(k||mac1||mac2)$ \\
      \> if $H \neq keyH$: \\
      \> \> return $\err$ \\
      \> return $k, mac1, mac2$
    }
  }
\end{center}

## Security Proof and Reasoning

### Deriving keys from passwords

We use the PBKDF2 algorithm to transform a keyfile's password into a 128-bit key used to decrypt the Keyfile. PBKDF2 uses our block cipher $\subname{F}{AES}$ for its PRF calls. We know that $\subname{F}{AES}$ is a secure PRP, and so, a secure PRF as well. We know this because to be a secure PRP, it has to be a secure PRF first, with additional requirements. Additionally, the proving of both PRPs and PRFs are the [exact same library proof](https://joyofcryptography.com/pdf/book.pdf#theorem.464). Therefore, our $\subname{F}_{AES}$ is a secure PRF upon which we can build our PBKDF2.

TODO: rest of PBKDF2 defense
https://www.tarsnap.com/scrypt.html
https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf 

### Use of keyfile hashes

The actual keyfile itself contains three keys, as described above. These three keys are concatenated together and then hashed through our Davies-Meyer function. This hash is used as a verification that a) the password is correct, and b) the keyfile is not corrupted. If either of these conditions does not hold, then the program will return an error instead of the correctly-decrypted keys. While a MAC would be ideal here, a MAC requires the use of an additional key. We are unable to do that while continuing use a password to encrypt the keyfile.

The usage (or not) of a MAC for the key storage functions is not important. It is important for the encryption and decryption of files, as those are intended to leave the computer, where eavesdroppers could corrupt and edit the files before they get to their destination. However, for the storage of keyfiles on a single computer, the risk for corruption is a lot lower, and it's not imperative that the keyfiles have MACs computed for them.

# Conclusion and Discussion

In this report, we have methodically gone through each component of our key manager, including the encryption scheme, the Master Key generation and storage, and how we apply our encryption and decryption schemes to the KeyFile in a way that ensures that an attacker cannot gain partial knowledge of either the Master Key, the keys in the key manager, or the messages sent be NOISE. 

# Appendix A: Changelog

Our draft was like this, we changed it to like this after recieving feedback.

# Appendix B: Feedback

> "Good progress so far. I think it would be helpful to be clearer about what specific problem you're trying to solve. It might help to differentiate your approach from other similar ones, and share design rationale. I admire your efforts to do a security proof but I see some bugs: 1. if "r" is blen bits long then there is no space left for m 2. decryption doesn't check r, nor does it separate m||r 3. This cannot be CCA secure --> I can drop the last ciphertext block and the result is still a valid encryption 4. It is a little bit more involved than you claim to derive the probability of collisions in r (since you care about collisions in r, r+1, .. r+L). If you are really using passwords rather than true encryption keys, then you should give more details about how the password is converted to a key. Just saying Davies-Meyer doesn't give me enough information (that's like saying "I use CTR mode" without saying what the block cipher is), and it is probably not the ideal way to derive a key from a password anyway." 