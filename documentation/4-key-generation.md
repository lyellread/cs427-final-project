
\pagebreak

# Key Generation and Storage

`NOISE` features a user-accessible function for key generation ($\lib{KeyGen}$'s function$\subname{KeyGen}$, not to be confused with $\sig{KeyGen}$). This function is responsible for using a user-supplied master password to encrypt new, randomly-generated keys. `NOISE` also features a function named $\subname{GetKeys}$, which is program-internal, and is responsible for retrieving the keys from the keyfile the user has specified, decrypting them with the user's password before returning them to the program.

## Formal Scheme Definition

The Key Generation and Storage part of `NOISE` is fundamentally responsible for properly creating, storing and retrieving cryptographic keys. Formally, the key generation and storage scheme is specified as follows:

\begin{center}
  \codebox{
    \titlecodebox{$\texttt{\upshape NOISE}$}{
      \comment{// Generate keys} \\
      $k_{\text{stream}}, k_{\text{mac1}}, k_{\text{mac2}} := \subname{KeyGen}()$ \\
      \\
      \comment{// Get keys from file} \\
      $k_{\text{stream}}, k_{\text{mac1}}, k_{\text{mac2}} := \subname{KeyGen}()$
    }
    $\link$
    \titlecodebox{\lib{KeyGen}}{
      \codebox{
        \underline{$\subname{KeyGeneration}()$:} \\
        \> $p := \texttt{\upshape NOISE}.\subname{GetPassword}$ \\
        \> $s \gets \Seen$ \\
        \> $k_{\text{stream-pass}} || k_{\text{mac1-pass}} || k_{\text{mac2-pass}} := \sig{PBKDF2}(p, s)$ \\
        \> $k_{\text{stream}}, k_{\text{mac1}}, k_{\text{mac2}} \gets \sig{KeyGen}$ \\
        \> $k_a := k_{\text{stream}} || k_{\text{mac1}} || k_{\text{mac2}}$ \\
        \> $c_k := \sig{Enc}_\text{CTR}(k_{\text{stream-pass}}, k_a) $ \\
        \> $t := \sig{GetTag}_{\text{ECBC}}(k_\text{mac1-pass}, k_{\text{mac2-pass}}, c_k)$ \\
        \> $\texttt{\upshape NOISE}.\subname{WriteToKeyFile}(s || c_k || t)$\\
        \> return $(k_{\text{stream}}, k_{\text{mac1}}, k_{\text{mac2}})$ \\
        \\
        \underline{$\subname{GetKeys}()$:} \\
        \> $p := \texttt{\upshape NOISE}.\subname{GetPassword}$ \\
        \> $s || c_k || t := \texttt{\upshape NOISE}.\subname{ReadFromKeyFile}()$\\
        \> $k_{\text{stream-pass}} || k_{\text{mac1-pass}} || k_{\text{mac2-pass}} := \sig{PBKDF2}(p, s)$ \\
        \> if $\sig{CheckTag}(k_{\text{mac1-pass}}, k_{\text{mac2-pass}}, c_k, t) = \bit{false}$: \\
        \> \> return $\bit{err}$ \\
        \> $k_{\text{stream}} || k_{\text{mac1}} || k_{\text{mac2}} := \sig{Dec}_\text{CTR}(k_{\text{stream-pass}}, c_k)$ \\
        \> return $(k_{\text{stream}}, k_{\text{mac1}}, k_{\text{mac2}})$
      }
    }
  }
\end{center}

The $\subname{KeyGeneration}$ function makes use of the primitives:

- $\sig{PBKDF2}$: Password-Based Key Derivation Function which uses many operations to derive keys from password values. This ensures that the computational requirements of brute forcing the password are more significant than simply hashing the master password. This function is implemented in [Primitives] and described further in [Password-Based Key Derivation Function].
- $\sig{Enc}_{\text{CTR}}$: Counter (CTR) block cipher mode encryption with 128-bit key and 128-bit block cipher $\sig{F}_{\subname{AES-128}}$. This block cipher mode is implemented in [Primitives] and described in more depth in [Block Cipher Mode]. The choice to use AES-128 as our Block Cipher is discussed in [Block Cipher].
- $\sig{GetTag}_{\text{ECBC}}$: ECBC MAC, described further in [Message Authentication Code] and implemented in [Primitives].

The $\subname{GetKeys}$ function makes use of the primitives:

- $\sig{PBKDF2}$: Password-Based Key Derivation Function which uses many operations to derive keys from password values. This ensures that the computational requirements of brute forcing the password are more significant than simply hashing the master password. This function is implemented in [Primitives] and described further in [Password-Based Key Derivation Function].
- $\sig{Dec}_{\text{CTR}}$: Counter (CTR) block cipher mode decryption with 128-bit key and 128-bit block cipher $\sig{F}_{\subname{AES-128}}$. This block cipher mode is implemented in [Primitives] and described in more depth in [Block Cipher Mode]. The choice to use AES-128 as our Block Cipher is discussed in [Block Cipher].
- $\sig{CheckTag}_{\text{ECBC}}$: ECBC MAC Check, described further in [Message Authentication Code] and implemented in [Primitives].

## Security Reasoning

$\subname{KeyGeneration}$ makes use of two sets of three keys:

- The user's keys: $(k_{\text{stream}}, k_{\text{mac1}}, k_{\text{mac2}})$
- The master-password-based keys: $(k_{\text{stream-pass}}, k_{\text{mac1-pass}}, k_{\text{mac2-pass}})$

The usage of these keys is demonstrated in detail in the implementation of library $\lib{KeyGen}$, in [Formal Scheme Definition]. The master-password-based keys are generated from the password the user supplies, and are used ephemerally to decrypt the keyfile in which the user's keys reside. These keys are then returned to be used for encryption and decryption. Using these three extra keys for master-password-based keyfile encryption, we are able to also use ECBC MAC on the keyfile, which permits us to claim Chosen Ciphertext Attack security against the keyfile itself.

We find it reasonable to conclude that $\lib{KeyGen}$'s $\subname{KeyGen}$ is secure, based on the following assertions about it's component parts. 

- Assertion: $\sig{PBKDF2}$ is secure given that the underlying PRF ($\sig{F}_{\text{AES-128}}$) is a secure PRF. This means that it is hard for an attacker to determine the output keys without knowledge of the user's master password. This assertion is made with the understanding that the function of $\sig{PBKDF2}$ is twofold: deriving a key from a password, as well as increasing the difficulty of guessing passwords in a brute force manner. These two functions are justified to be secure in this implementation as follows:
  1. The derivation of multiple keys based on a single master password using $\sig{PBKDF2}$ has been shown to be a secure, valid use-case for PBKDF2 as described in NIST SP 800-108, which details: *"any segment of the derived keying material having the required length can be specified for use as a key, subject to the following restriction: When multiple keys [...] are obtained from the derived keying material, they shall be selected from disjoint (i.e., non-overlapping) segments of the KDF output."*[^5.1] This indicates that $\sig{PBKDF2}$ may be used to derive three keys from a single password, as long as these keys are not overlapping *"segments of the KDF output"*.
  2. $\sig{PBKDF2}$ also serves the purpose of increasing the computational difficulty of computing the ephemeral master-password-based keys that are used to decrypt the keyfiles. $\sig{PBKDF2}$ does this by requiring many iterations of a subroutine to run in order to generate the proper keys, requiring an increase in computational effort to try a given password. Often, this requirement is hardware and implementation specific, as an adversary must use the provided implementation and cannot speed their brute force operations up with dedicated hardware or additional compute resources. In this case, we opted to demonstrate the functionality of PBKDF as it would take place in a web server or other inaccessible computer system. Therefore, setting the iterations required internally by $\sig{PBKDF2}$ to $\Sigma.\text{I}_{\text{pass-deriv}} := 2048$ which takes about 1 second to compute lowers an adversary's guess per second rate[^5.2] to around a guess per second.
- Assertion: $\sig{KeyGen}$ supplies keys that are uniformly sampled from random, and are therefore unpredictable, and suitable for use as keys. This assertion relies on the understanding that the source of system randomness, in our case `/dev/urandom`, is as indistinguishable from random as technology will permit, thus is the best source of on-device randomness available.
- Assertion: $\sig{Enc}_\text{CTR}$ with $\sig{GetTag}_{\text{ECBC}}$ is a CCA secure Enc-then-MAC scheme, implying that it is also CPA secure. The reasoning for this is provided in [the security reasoning for Stream Encryption, above][stream-reasoning].

Under these assertions and conditions, we can conclude that $\lib{KeyGen}$'s functions $\subname{KeyGeneration}$ and $\subname{GetKeys}$ are secure against chosen ciphertexts (in this case keyfiles). Additionally, we conclude that the best attack against this scheme is to brute force the master password. Brute-forcing the password depends on the length and complexity of the password, however it is significantly hindered by the use of $\sig{PBKDF2}$ which raises the computational cost associated with brute forcing the master password. Another brute-force approach that an attacker might apply is to brute force the three 128-bit keys that encrypt and tag the stored keyfile at rest. Doing this requires brute forcing 384-bit security.

[^5.1]: NIST, *NIST Special Publication 800-108: Recommendation for Key Derivation Functions Using Pseudorandom Functions*, Section 7.3
[^5.2]: On the hardware on which we tested it, with the implementation in the provided source code archive. If re-implemented more efficiently and placed on more performant hardware, the password guess per second rate could be significantly increased.


