\pagebreak

# Stream Encryption and Decryption

`NOISE` features constructions to permit the user in encrypting and decrypting streams of data to and from files of their choice using a specified key. This scheme is described in this section.

## Formal Scheme Definition

The purpose of the Stream Encryption and Decryption functions are to encrypt and decrypt large amounts of data in a secure fashion given a user supplied keyfile (generated with [Key Generation and Storage]). Formally, the stream encryption and decryption scheme is specified as follows:

\begin{center}
  \titlecodebox{$\texttt{\upshape NOISE}$}{
    define $k_\text{stream}, k_\text{mac1}, k_\text{mac2} \in \Sigma.\K$ \\
    \\
    \comment{// Keys are read from file} \\
    $k_\text{stream}, k_\text{mac1}, k_\text{mac2} := \texttt{\upshape NOISE}.\subname{GetKeys}$ \\
    \\
    \comment{// Get message from user} \\
    define $m \in \bits^*$ \\
    \\
    \comment{// Encrypt message} \\
    $c := \subname{Enc}_{\text{Stream}}(k_\text{stream}, k_{\text{mac1}}, k_{\text{mac2}}, m)$: \\
    \\
    \comment{// Decrypt ciphertext} \\
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
\end{center}

The $\subname{Enc}_{\text{Stream}}$ function makes use of the primitives:

- $\sig{Pad}$: A simple padding scheme, roughly implemented in [Primitives].
- $\sig{Enc}_{\text{CTR}}$: Counter (CTR) block cipher mode encryption with 128-bit key and 128-bit block cipher $\sig{F}_{\subname{AES-128}}$. This block cipher mode is implemented in [Primitives] and described in more depth in [Block Cipher Mode]. The choice to use AES-128 as our Block Cipher is discussed in [Block Cipher].
- $\sig{GetTag}_{\text{ECBC}}$: ECBC MAC, described further in [Message Authentication Code] and implemented in [Primitives].

The $\subname{Dec}_{\text{Stream}}$ function makes use of the primitives:

- $\sig{UnPad}$: The padding removal part of our simple padding scheme, roughly implemented in [Primitives].
- $\sig{Dec}_{\text{CTR}}$: Counter (CTR) block cipher mode decryption with 128-bit key and 128-bit block cipher $\sig{F}_{\subname{AES-128}}$. This block cipher mode is implemented in [Primitives] and described in more depth in [Block Cipher Mode]. The choice to use AES-128 as our Block Cipher is discussed in [Block Cipher].
- $\sig{CheckTag}_{\text{ECBC}}$: ECBC MAC check, described further in [Message Authentication Code] and implemented in [Primitives].

## Security Reasoning {#stream-reasoning}

[Claim 10.10 and its associated proof](https://joyofcryptography.com/pdf/book.pdf)[^5.1] show that an Encrypt-then-MAC scheme has CCA\$-security if and only if the scheme has CPA-security and the MAC used is a secure MAC.

Thus, for the Encrypt-then-MAC scheme that `NOISE` implements to be CCA\$-secure, $\sig{Enc/Dec}_{\text{CTR}}$ must be CPA-secure and $\sig{Get/CheckTag}_{\text{ECBC}}$ must be a secure MAC. The CTR-mode block cipher has CPA-security, as defined in [Chapter 8](https://joyofcryptography.com/pdf/book.pdf)[^5.2]. The ECBC-MAC implemented in $\sig{Get/CheckTag}_{\text{ECBC}}$ is a secure MAC for any input as a multiple of the block length (which $\sig{Pad}$ ensures), as defined by [Theorem 10.8](https://joyofcryptography.com/pdf/book.pdf)[^5.3].

[^5.1]: Rosulek, *The Joy of Cryptography*, Chapter 10
[^5.2]: Rosulek, *The Joy of Cryptography*, Chapter 8
[^5.3]: Rosulek, *The Joy of Cryptography*, Chapter 10
