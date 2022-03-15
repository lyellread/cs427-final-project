\pagebreak

# Stream Encryption and Decryption

`NOISE` features constructions to permit the user in encrypting and decrypting streams of data to and from files of their choice using a specified key. This scheme is described in this section.

## Formal Scheme Definition

The purpose of the Stream Encryption and Decryption functions are to encrypt and decrypt large amounts of data in a secure fashion given a user supplied keyfile (generated with [Key Generation and Storage]). Formally, the stream encryption and decryption scheme is specified as follows:

\begin{center}
  \codebox{
    \titlecodebox{$\texttt{\upshape NOISE}$}{
      define $k_\text{stream}, k_\text{mac1}, k_\text{mac2} \in \Sigma.\K$ \\
      \\
      \comment{// Keys are read from file} \\
      $k_\text{stream}, k_\text{mac1}, k_\text{mac2} := \texttt{\upshape NOISE}.\subname{ReadKeys}$ \\
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

## Security Proof and Reasoning

Under the following assertions, we can conclude that $\lib{Stream}$, and its member functions $\subname{Enc}_{\text{Stream}}$ and $\subname{Enc}_{\text{Stream}}$ are secure against chosen ciphertexts (in this case keyfiles), and the best attack against this scheme is to brute force the three 128-bit keys used to encrypt or decrypt and tag the data being manipulated. This results in it being necessary for an attacker to brute force 384 bits of security.

### $\subname{Enc}_{\text{Stream}}$

We find it reasonable to conclude that $\lib{Stream}$'s $\subname{Enc}_{\text{Stream}}$ is secure, based on the assertion that $\sig{Enc}_\text{CTR}$ with $\sig{GetTag}_{\text{ECBC}}$ is a CCA secure Enc-then-MAC scheme, implying that it is also CPA secure. Given this, this scheme is secure against adversarially chosen ciphertexts and plaintexts.

### $\subname{Dec}_{\text{Stream}}$

We find it reasonable to conclude that $\lib{Stream}$'s $\subname{Dec}_{\text{Stream}}$ is secure, based on the assertion that $\sig{Dec}_\text{CTR}$ with $\sig{CheckTag}_{\text{ECBC}}$ is the inverse of our CCA secure Enc-then-MAC scheme, implying that it is also CPA secure. Therefore, this scheme is secure against adversarially chosen ciphertexts and plaintexts.