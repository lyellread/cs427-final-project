
\pagebreak

# Key Generation and Storage

`NOISE` features a user-accessible function for key generation ($\lib{KeyGen}$'s function$\subname{KeyGen}$, not to be confused with $\sig{KeyGen}$). This function is responsible for using a user-supplied master password to encrypt new, randomly-generated keys. `NOISE` also features a function named $\subname{GetKeys}$, which is program-internal, and is responsible for retrieving the keys from the keyfile the user has specified, decrypting them with the user's password before returning them to the program.

## Formal Scheme Definition

The Key Generation and Storage part of `NOISE` is fundamentally responsible for properly creating, storing and retrieving cryptographic keys.

The $\subname{KeyGen}$ function makes use of the primitives:

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
      \comment{// Generate keys} \\
      $k_{\text{stream}}, k_{\text{mac1}}, k_{\text{mac2}} := \subname{KeyGen}()$ \\
      \\
      \comment{// Get keys from file} \\
      $k_{\text{stream}}, k_{\text{mac1}}, k_{\text{mac2}} := \subname{KeyGen}()$
    }
    $\link$
    \titlecodebox{\lib{KeyGen}}{
      \codebox{
        \underline{$\subname{KeyGen}()$:} \\
        \> $p := \texttt{\upshape NOISE}.\subname{GetPassword}$ \\
        \> $s \gets \S$ \\
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

## Security Proof and Reasoning

<!-- "Also we should just have to prove the parts of our primitives with pbkdf2 and we should be secure ig" -->

TODO: Casey Proof:

$\subname{KeyGen}$ makes use of two sets of three keys:

- The user's keys: $(k_{\text{stream}}, k_{\text{mac1}}, k_{\text{mac2}})$
- The master password-based keys: $(k_{\text{stream-pass}}, k_{\text{mac1-pass}}, k_{\text{mac2-pass}})$

The usage of these keys is demonstrated in detail in [Formal Scheme Definition]. The master password-based keys are generated from the password the user supplies, and are used ephemerally to decrypt the keyfile in which the user's keys reside. These keys are then returned to be used for encryption and decryption. Using these three extra keys for master password-based keyfile encryption, we are able to also use $\sig{MAC}_{\text{ECBC}}$ on the keyfile, which permits us to claim Chosen Ciphertext Attack security against the keyfile itself.

TODO: Casey, verify this is accurate. ^
