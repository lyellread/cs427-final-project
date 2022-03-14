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
