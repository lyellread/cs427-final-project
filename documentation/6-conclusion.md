\pagebreak

# Conclusion and Discussion

During this project, we got the chance to design and implement our own cryptographic scheme `NOISE`, based on several common cryptographic primitives defined in [Primitives]. Our final result is a moderately-secure (insecure by modern, cutting-edge standards), functional and simple program that can encrypt streams of data using user-created and user-specified keyfiles which are stored encrypted using a user-specified Master Password.

## Lessons Learned

During the design and implementation of `NOISE`, several lessons were learned which are listed below.

- Ideally, the design would be sketched out as the implementation is being designed and begun, such that any modifications to the scheme design to match constraints in implementation can be made before the documentation is finalized.
- Implementation in modern languages like `python` is simpler and quicker than documentation. Labor should have been distributed commensurately.
- Many `python` libraries that advertise to have methods for AES are implementations of standard Block Cipher Modes that use Block Cipher AES. Therefore, finding a library that implemented just the AES-128 Block Cipher was more complicated than expected.
