\pagebreak

# Appendix

## Appendix A: Changelog

We submitted an initial draft for feedback. Our original design was a modified CTR mode for encryption, and our method for generating a key out of a password was with a simple hash function. We received feedback on both parts of this (see [Appendix B][Appendix B: Draft Feedback]). In short, our CTR mode was not CCA-secure, and our password-to-key generation was sub-optimal.

To improve from this feedback, we made a variety of changes. Firstly, we returned to normal CTR mode and included a MAC, creating a CCA-secure "Enc-then-MAC" scheme. The MAC we chose for this purpose was ECBC-MAC to allow tagging of arbitrary-length messages. Next, we did further research on how to properly generate keys from a password. We chose to implement one of these methods, PBKDF2. This is a more sophisticated and secure method of generating password-derived keys compared to our previous $k := \sig{Hash}(password)$.

One thing that we got right in the initial design was to choose AES as the block cipher / PRP we would use. By choosing this known-secure (or rather, known-not-insecure) algorithm as our PRP/PRF, this allowed us to construct secure constructions using AES, such as our ECBC-MAC and PBKDF2.

## Appendix B: Draft Feedback

We received the following feedback on our initial draft submission:

```md
Good progress so far. I think it would be helpful to be clearer about what
specific problem you're trying to solve. It might help to differentiate your
approach from other similar ones, and share design rationale. I admire your
efforts to do a security proof but I see some bugs:

1. if "r" is blen bits long then there is no space left for m
2. decryption doesn't check r, nor does it separate m||r
3. This cannot be CCA secure --> I can drop the last ciphertext block and the
   result is still a valid encryption
4. It is a little bit more involved than you claim to derive the probability of
   collisions in r (since you care about collisions in r, r+1, .. r+L). If you
   are really using passwords rather than true encryption keys, then you should
   give more details about how the password is converted to a key. Just saying
   Davies-Meyer doesn't give me enough information (that's like saying "I use
   CTR mode" without saying what the block cipher is), and it is probably not
   the ideal way to derive a key from a password anyway.
```
