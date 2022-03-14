\pagebreak

# Primitives

## Specifications

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
      $\text{I}_{\text{pass-deriv}} := 2048$ \\
      \\
      \underline{$\subname{KeyGen}()$:}\\
      \> $k \gets \K$ \\
      \> return $k \in \K$ \\
      \\
      \underline{$\subname{Enc}_{\text{CTR}}(k \in \K, m_1 || \cdots || m_l \in \M)$:} \\
      \> $r \gets \bits^{\text{blen}}$ \\
      \> $c_0 := r$ \\
      \> for $i = 1$ to $l$: \\
      \> \> $c_i := \sig{F}_{\subname{AES-128}}(k, r) \oplus m_i$ \\
      \> \> $r := r + 1 \text{ mod } 2^{\text{blen}}$ \\
      \> return $c_0 || \cdots || c_l \in \C$\\
      \\
      \underline{$\subname{Dec}_{\text{CTR}}(k \in \K, c_0 || \cdots || c_l \in \C)$:} \\
      \> $r := c_0$ \\
      \> for $i = 1$ to $l$: \\
      \> \> $m_i := \sig{F}_{\subname{AES-128}}(k, r) \oplus c_i$\\
      \> \> $r := r + 1 \text{ mod } 2^{\text{blen}}$ \\
      \> return $m_1 || \cdots || m_l \in \M$ \\
      \\
      \underline{$\subname{F}_{\subname{AES-128}}(k \in \K, m \in \M)$:} \\
      \> \comment{\# full AES-128 implementation} \\
      \> \comment{\# not included due to size} \\
      \> return $c \in \C$\\
      \\
      \underline{$\subname{F}_{\subname{AES-128}}^{-1}(k \in \K, c \in \C)$:} \\
      \> \comment{\# full AES-128 implementation} \\
      \> \comment{\# not included due to size} \\
      \> return $m \in \M$
    }
    \qquad
    \codebox{
      \underline{$\subname{GetTag}_{\text{ECBC}}(k_1 \in \K, k_2 \in \K, m_0 || \cdots || m_l \in \M)$:} \\
      \> $x := m_l$ \\
      \> $t := \bit{0}^{\text{blen}}$ \\
      \> for $i=0$ to $i = l-1$: \\
      \> \> $t := \sig{F}_{\subname{AES-128}}(k_1, t \oplus m_i)$ \\
      \> $t := \sig{F}_{\subname{AES-128}}(k_2, t \oplus x)$ \\
      \> return $t \in \T$ \\
      \\
      \underline{$\subname{CheckTag}_{\text{ECBC}}(k_1 \in \K, k_2 \in \K,$} \\
      \> \hspace{6.5em} \underline{$m_0 || \cdots || m_l \in \M, t \in \T)$:} \\
      \> return $t \qequiv \sig{GetTag}(k_1, k_2, m_0 || \cdots || m_l)$ \\
      \\
      \underline{$\subname{PBKDF2}(p \in \bits^*, s \in \Seen)$:} \\
      \> $p := \sig{Hash}_{\text{D-M}}(p)$ \\
      \> for $i = 1$ to $\frac{\text{klen}}{\text{blen}}$: \\
      \> \> $u_1 := \sig{F}_{\subname{AES-128}}(p, s || i)$ \\
      \> \> $t_i := u_1$ \\
      \> \> for $j = 2$ to $\Sigma.\text{I}_{\text{pass-deriv}}$: \\
      \> \> \> $u_j := \sig{F}_{\subname{AES-128}}(p, u_{i-1}$) \\
      \> \> \> $t_i := t_i \oplus u_j$ \\
      \> $t := t_1 || \cdots || t_{\frac{\text{klen}}{\text{blen}}}$ \\
      \> return $t \in \bits^\text{klen}$ \\
      \\
      \underline{$\subname{Pad}(m \in \bits^*)$:} \\
      \> $d = [\text{blen}-(\subname{BitLength}(m) \text{ mod blen})]/8$ \\
      \> $m := m || [\bit{0x00}_0 || \cdots || \bit{0x00}_{(d-1)} || \subname{HexByte}(\text{d})]$ \\
      \> return $m \in \M^*$ \\
      \\
      \underline{$\subname{UnPad}(m \in \M^*)$:} \\
      \> $d = \subname{GetLastByte}(m)$ \\
      \> $m := m[:-d]$ \comment{\# Remove d bytes of padding}\\
      \> return $m \in \bits^*$\\
      \\
      \underline{$\subname{Hash}_{\text{D-M}}(m \in \bits^*)$:} \\
      \> $h := \bit{0}^{\text{blen}}$ \\
      \> $m_0 || \cdots || m_l := \sig{Pad}(m)$ \\
      \> for $i=0$ to $l$: \\
      \> \> $h := \sig{F}_{\subname{AES-128}}(m_i, h) \oplus h$ \\
      \> return $h \in \M$
    }
  }
\end{center}

\pagebreak

## Block Cipher

Our design utilizes a Block Cipher, $\sig{F}_{\subname{AES-128}}$. $\sig{F}_{\subname{AES-128}}$ is a [$\subname{AES-128}$ block cipher](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf) with a 128-bit key. We decided to make use of an existing $\subname{AES-128}$ implementation in the [`pyaes` library](https://github.com/ricmoo/pyaes#aes-block-cipher) as implementing $\subname{AES-128}$ from scratch would have been a project in itself. While the NIST standard lays out standard implementations for $\subname{AES-192}$ and $\subname{AES-256}$ as well, we opted to use $\subname{AES-128}$ as our Block Cipher in order to keep the key size and block sizes consistent throughout `NOISE`. This decision was made with the understanding that 128-bit security is relatively low compared with new schemes offering more security, however `NOISE` aims to be readable as an educational resource about cryptographic primitives in use, therefore maximum security was not the goal. This block cipher is not implemented above in the $\Sigma$ scheme, as the AES implementation is too long to include in this document.

## Block Cipher Mode

`NOISE` makes use of $\sig{Enc}_{\text{CTR}}$ and $\sig{Dec}_{\text{CTR}}$ subroutines to encrypt and decrypt data. We opted to use Counter (CTR) block cipher mode for this purpose as it provides CPA security and is simple to implement. Our CTR mode encryption and decryption use a block size $\text{blen} = 128$ bits, as well as a key of length 128 bits for use in the [Block Cipher].

## Message Authentication Code

TODO: Add description of rationale for choosing ECBC-MAC.

## Password-Based Key Derivation Function (PKBDF2)

To use a user-supplied password as a cryptographic key, `NOISE` implements $\sig{PBKDF2}$. $\sig{PBKDF2}$ is a Password Based Key Derivation Function which performs a large number of operations to derive a key from a password using a Pseudo Random Function (PRF). The output of this deterministic process is a key that has been derived based on the provided password.

$\sig{PBKDF2}$ takes as input a password bit string, supplied by the user. As well, it takes in a salt $s$. Globally, the number of iterations that $\sig{PBKDF2}$ uses is defined as $\Sigma.\text{I}_{\text{pass-deriv}}$ which is set to $2048$ iterations for our implementation, which is a reasonable value given the inefficiencies of our algorithms.

Notably, $\sig{PBKDF2}$ takes in an arbitrary user-supplied password which cannot be used as-is in $\sig{PBKDF2}$. For this reason, this password $p$ is hashed using $\sig{Hash}_{\text{D-M}}$ which returns a fixed-length value $h$ of length 128 bits.

By supplying a value of $\text{klen} = 384$ bits and a value of $\text{blen} = 128$, the key that is output by $\sig{PBKDF2}$ will be 384 bits, which becomes three keys of length 128 bits each. This permits `NOISE` to use $\sig{PBKDF2}$ to generate the three keys required ephemerally for encrypting and decrypting keyfiles (one key for the [Block Cipher Mode], two for the [Message Authentication Code]). The [NIST publication for Key Derivation Functions](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf)^[*Recommendation for Key Derivation Functions Using Pseudorandom Functions*, Section 7.3] allows Key Derivation Functions to derive multiple keys per password, as long as the keys selected from the Key Derivation Function output are disjoint.

### Considerations When Choosing KDF

When choosing the constructions to use as the building blocks for `NOISE`, we encountered several possible Key Derivation Functions (KDF). We opted to use $\sig{PBKDF2}$ instead of other KDFs like [`scrypt`](https://www.tarsnap.com/scrypt.html) or [`argon2`](https://github.com/P-H-C/phc-winner-argon2#argon2). This decision was made consciously as 'modern' KDFs like `argon2` and `scrypt` were designed to address vulnerabilities in older KDFs which allowed them to be more easily attacked with brute force using Graphical Processing Units (GPUs). In order to keep the primitives of `NOISE` readable and simple, we opted to implement a less secure (but simpler) KDF, $\sig{PBKDF2}$,to remain in keeping with our goal of making `NOISE` an educational demonstration of cryptographic concepts.

### Pseudo Random Function for PBKDF2

$\sig{PBKDF2}$ requires a pseudorandom function as part of its algorithm. In [RFC8018](https://datatracker.ietf.org/doc/html/rfc8018#section-5.2), $\subname{HMAC-SHA-1}$ is suggested as a PRF. Instead, we will be using is our AES Pseudo Random Permutation (PRP, described in [Block Cipher]), $\sig{F}_{\subname{AES-128}}$ defined in [Primitives]. By [Corollary 6.8 in The Joy of Cryptography](https://joyofcryptography.com/pdf/book.pdf#theorem.464), we can assert that our PRP $\sig{F}_{\subname{AES-128}}$ is a also a secure PRF. Therefore, our $\subname{F}_{AES}$ is a secure PRF upon which we can build $\sig{PBKDF2}$.

## Hashing Function

TODO: hashing function
