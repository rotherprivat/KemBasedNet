# PqCrypto

This project provides a .NET implementation of the Post Quantum Crypto algorithm "CompositeMLKem" and a hybrid public- / private-key algorithm for encrypting and decrypting data, 
based on key exchange algorithms.

The current implementation specially of the "CompositeMLKem" algorithm is in draft state, interfaces 
behavior and the encoding of the keys may change in future, depending on the changes of the [IETF draft](https://lamps-wg.github.io/draft-composite-kem/draft-ietf-lamps-pq-composite-kem.html) 
and the development of the Post Quantum Cryptography algorithm in the .NET SDK.

See:
- **Overview:** [Doc](docs/readme.md)
- **API Description:** [API](xref:Rotherprivat.PqCrypto.Cryptography)
