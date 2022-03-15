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
      $\text{blen} := 128$ \comment{// bits} \\
      $\text{klen} := 384$ \comment{// bits} \\
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
      \> \comment{// AES-128 implementation} \\
      \> \comment{// via pyaes omitted for size} \\
      \> return $c \in \C$\\
      \\
      \underline{$\subname{F}_{\subname{AES-128}}^{-1}(k \in \K, c \in \C)$:} \\
      \> \comment{// AES-128 implementation} \\
      \> \comment{// via pyaes omitted for size} \\
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
      \> $m := m[:-d]$ \comment{// Remove d bytes of padding}\\
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

Our design utilizes a Block Cipher, $\sig{F}_{\subname{AES-128}}$. $\sig{F}_{\subname{AES-128}}$ is an [AES block cipher](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)[^3.1] with a 128-bit key size. We decided to make use of an existing AES-128 implementation in the [`pyaes` library](https://github.com/ricmoo/pyaes#aes-block-cipher)[^3.2], as implementing AES from scratch would have been a project in itself. While the NIST standard lays out standard implementations for AES-192 and AES-256 as well, we opted to use AES-128 as our Block Cipher in order to keep the key size and block sizes consistent throughout `NOISE`. This decision was made with the understanding that 128-bit security is relatively low compared with new schemes offering more security, however `NOISE` aims to be readable as an educational resource about cryptographic primitives in use, not as a production-grade encryption tool; maximum security was not the goal. This block cipher implementation is not defined in the $\Sigma$ scheme above, as the AES implementation is very large and is also implemented in a third-party library, not by `NOISE`.

[^3.1]: NIST, *Federal Information Processing Standards Publication 192: Announcing the ADVANCED ENCRYPTION STANDARD (AES)*
[^3.2]: `pyaes` Library Documentation for the AES Block Cipher

## Block Cipher Mode

`NOISE` makes use of $\sig{Enc}_{\text{CTR}}$ and $\sig{Dec}_{\text{CTR}}$ subroutines to encrypt and decrypt data. We opted to use Counter (CTR) block cipher mode for this purpose as it provides CPA security and is simple to implement. Our CTR mode encryption and decryption use a block size $\text{blen} = 128$-bits, as well as a key of length 128-bits for use in the [Block Cipher].

## Message Authentication Code

`NOISE` uses an ECBC Message Authentication Code (MAC) ([Construction 10.7](https://joyofcryptography.com/pdf/book.pdf)[^3.3]) in order to generate MAC tags for messages with a variable number of blocks. [Theorem 10.8](https://joyofcryptography.com/pdf/book.pdf)[^3.4] says that ECBC-MAC is a secure MAC for messages of all block-lengths, given that our Block Cipher (Pseudo Random Permutation) $\sig{F}_{\subname{AES-128}}$ is a secure PRP. Given [Corollary 6.8](https://joyofcryptography.com/pdf/book.pdf#theorem.464)[^3.5], our PRP $\sig{F}_{\subname{AES-128}}$ is a also a secure PRF, which in turn makes ECBC-MAC a secure MAC.

This ECBC-MAC is used in [Key Generation and Storage] and [Stream Encryption and Decryption] in an "Enc-then-MAC" construction to derive a Chosen Ciphertext Attack (CCA)-secure scheme from a Chosen Plaintext Attack (CPA)-secure scheme. Pairing our CPA-secure [Block Cipher Mode] with ECBC-MAC in this way makes the resultant Enc-then-MAC construction CCA secure.

$\Sigma$ exposes two primitives related to ECBC-MAC. $\sig{GetTag}_{\text{ECBC}}$ exposes a method to return the MAC tag for a given message of 128-bit blocks under the two 128-bit keys supplied. The resultant tag $t$ is of length 128-bits. $\sig{CheckTag}_{\text{ECBC}}$ checks whether a supplied message and tag match by recalculating the tag internally under the two 128-bit keys provided. It returns $\bit{true}$ or $\bit{false}$ depending on whether the calculated tag matches the supplied tag.

[^3.3]: Rosulek, *The Joy of Cryptography*, Chapter 10.3
[^3.4]: Rosulek, *The Joy of Cryptography*, Chapter 10.3
[^3.5]: Rosulek, *The Joy of Cryptography*, Chapter 6.4

## Password-Based Key Derivation Function

To use a user-supplied password as a cryptographic key, `NOISE` implements the [PKBDF2 key-derivation algorithm](https://datatracker.ietf.org/doc/html/rfc8018#section-5.2)[^3.6] as $\sig{PBKDF2}$. PKBDF2 is a password-based key derivation function which performs a large number of operations to derive an arbitrary-length key from a password using a Pseudo-Random Function (PRF). The output of this deterministic process is a key that has been derived based on the provided password but is indistinguishable from a random sample.

$\sig{PBKDF2}$ takes as input a user-supplied password $p$ and a salt $s$. Globally, the number of iterations that $\sig{PBKDF2}$ uses is defined as $\Sigma.\text{I}_{\text{pass-deriv}}$, set to $2048$ iterations for our implementation. Notably, $\sig{PBKDF2}$ takes in a user-supplied password of arbitrary length which cannot be used as-is in $\sig{PBKDF2}$. This password needs to be compressed to a single block to be used in our PRF $\sig{F}_{\subname{AES-128}}$. For this reason, this password $p$ is hashed using $\sig{Hash}_{\text{D-M}}$ which returns a fixed-length value $h$ of length 128-bits.

By supplying a value of $\text{klen} = 384$-bits and a value of $\text{blen} = 128$, the key that is output by $\sig{PBKDF2}$ will be 384-bits, which becomes three keys of length 128-bits each. This permits `NOISE` to use $\sig{PBKDF2}$ to generate the three keys required ephemerally for encrypting and decrypting keyfiles (one key for the [Block Cipher Mode], two for the [Message Authentication Code]). The [NIST publication covering Key Derivation Functions](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf)[^3.7] allows Key Derivation Functions to derive multiple keys per password, as long as the keys selected from the Key Derivation Function output are disjoint.

[^3.6]: IETF, *Password-Based Cryptography Specification Version 2.1*, Section 5.2
[^3.7]: NIST, *NIST Special Publication 800-108: Recommendation for Key Derivation Functions Using Pseudorandom Functions*, Section 7.3

### Considerations When Choosing KDF

When choosing the constructions to use as the building blocks for `NOISE`, we encountered several possible Key Derivation Functions (KDF). We opted to use PKBDF2 instead of other KDFs like [`scrypt`](https://www.tarsnap.com/scrypt.html) or [`argon2`](https://github.com/P-H-C/phc-winner-argon2#argon2). These 'modern' KDFs were designed to address vulnerabilities in older KDFs which were susceptible to brute-force attacks using GPU compute or specialized ASIC/FPGA hardware. We opted to implement the less secure PKBDF2 KDF in `NOISE` to keep the primitives simple and readable, in keeping with our goal of making `NOISE` an educational demonstration of cryptographic concepts.

Additionally, the iteration count chosen for $\sig{PBKDF2}$ ($\Sigma.\text{I}_{\text{pass-deriv}} = 2048$) is lower than the [NIST recommendation of over 10,000 iterations](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecretver) or the [modern recommendation of over 300,000 iterations](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html). This value was chosen to generate the keys in a reasonable amount of time (~1 second) given the inefficiencies of our implementation language. While this iteration count is lower than recommended for modern practices, `NOISE` is meant to be an educational demonstration of cryptographic concepts, not to be a production-grade encryption tool.

### Pseudo Random Function for PBKDF2

$\sig{PBKDF2}$ requires a pseudorandom function as part of its algorithm. In [RFC8018](https://datatracker.ietf.org/doc/html/rfc8018#section-5.2)[^3.9], $\subname{HMAC-SHA-1}$ is suggested as a PRF. Instead, we will be using is our AES Pseudo-Random Permutation (PRP), described in [Block Cipher] and defined in [Primitives] as $\sig{F}_{\subname{AES-128}}$. By [Corollary 6.8](https://joyofcryptography.com/pdf/book.pdf#theorem.464)[^3.10], we can assert that our PRP $\sig{F}_{\subname{AES-128}}$ is a also a secure PRF. Therefore, our $\sig{F}_{\subname{AES-128}}$ is a secure PRF upon which we can build $\sig{PBKDF2}$.

[^3.9]: IETF, *Password-Based Cryptography Specification Version 2.1*, Section 5.2
[^3.10]: Rosulek, *The Joy of Cryptography*, Chapter 6.4

## Hashing Function

The hashing construction used in `NOISE` is a Davies-Meyer compression function design. The choice was made to use the Davies-Meyer construction as it makes use of a secure [Block Cipher], which we have already defined to be $\sig{F}_{\subname{AES-128}}$. The hashing subroutine $\sig{Hash}_{\text{D-M}}$ takes in a message of any length, and outputs a message in $\M$, of 128-bits.

The Davies-Meyer construction was chosen over Merkle-Damg$\aa$rd construction because of the [susceptibility of the latter to length-extension attacks](https://eprint.iacr.org/2004/304.pdf)[^3.11]. It is notable that the Davies-Meyer construction also has flaws, however these are not known to be exploitable in exponential time.

[^3.11]: Kelsey, Schneier, *Second Preimages on n-bit Hash Functions for Much Less than $2^n$ Work*
