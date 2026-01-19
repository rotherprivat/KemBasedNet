# PqCrypto

This project provides a .NET implementation of the Post Quantum Crypto algorithm "CompositeMLKem" and a hybrid public- / private-key algorithm for encrypting and decrypting data, based on key exchange algorithms.

## Disclaimer

**.NET** is a trademark of Microsoft Corporation.

## CompositeMLKem

The "CompositMLKem" algorithm is specified by the [IETF draft](https://lamps-wg.github.io/draft-composite-kem/draft-ietf-lamps-pq-composite-kem.html) and the implementation and interfaces are aligned to the [.NET ML-KEM implementation "System.Security.Cryptograpy.MLKem"](https://learn.microsoft.com/de-de/dotnet/api/system.security.cryptography.mlkem).
It implements a composition of the Post Quantum ML-KEM algorithm and a traditional KEM algorithm.

Classes:
- CompositMLKem
- CompositeMLKemAlgorithm

### Motivation

The .NET version 10.0.2 (SDK 10.0.102) provides implementations of the major Post Quantum Cryptography 
algorithms recommended by NIST:

| Purpose | Algorithm |
| --- | --- |
| Key exchange | ["ML-KEM" FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) |
| Digital signature | ["ML-DSA" FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) |

As well as the "CompositeMLDsa" algorithm according to the IETF specification, which is a composition of 
the "ML-DSA"- and a traditional digital signing algorithm.

A composite variant of the "ML-KEM" algorithm is not available.

**Why do we need composite algorithms?**

The Post Quantum Algorithms are very young and not totally trusted and not field proven, therefore it 
is considered risky to switch totally to new algorithms. Using a composition of Post Quantum and 
traditional algorithms in the phase of transition will reduce this risk, an attacker needs to break both 
algorithms, so things won’t get worse.

Some more readings to this on [postquantum.com]( https://postquantum.com/post-quantum/hybrid-cryptography-pqc/#why-hybrid-cryptography-ensuring-security-through-transition).

### Restrictions

This version only provides the following algorithm combinations:

| Composite KEM | ML-KEM | Traditional | Combiner |
| --- | --- | --- | --- |
| MLKEM768-ECDH-P256-SHA3-256 | ML-KEM-768 | ECDH, secp256r1 | SHA3-256 |
| MLKEM768-ECDH-P384-SHA3-256 | ML-KEM-768 | ECDH, secp384r1 | SHA3-256 |
| MLKEM1024-ECDH-P384-SHA3-256 | ML-KEM-1024 | ECDH, secp384r1 | SHA3-256 |
| MLKEM1024-ECDH-P521-SHA3-256 | ML-KEM-1024 | ECDH, secp521r1 | SHA3-256 |


### How to use

The "CompositMLKem" class will be used in the same way as the .NET MLKem calss.

- Alice: Initiator of communication
- Bob: Communication partner

1. Alice: Generate the key material according to the required combined algorithm (Alice). The private key should be handled confidentially by Alice.
2. Provide Bob, your communication partner, with the encapsulation key (public key)
3. Bob: Generate the local copy of the shared secret and a ciphertext (Encapsulation). The shared key should be handled confidentially by Bob.
4. Forward the ciphertext to Alice.
5. Alice: Generate the local copy of the shared secret by Decapsulating the ciphertext from Bob.
6. Alice and Bob can use the shared secret to encrypt and decrypt exchanged messages.

```C#
var algorithm = CompositeMLKemAlgorithm.KMKem1024WithECDhP521Sha3;
using var alice = CompositeMLKem.GenerateKey(algorithm);

var derPublicKey = alice.ExportSubjectPublicKeyInfo();

// Forward derPublicKeyto Bob
using var bob = CompositeMLKem.ImportSubjectPublicKeyInfo(derPublicKey);

bob.Encapsulate(out var ciphertext, out var bobsSecret);
// Bob will use bobsSecret

// Forward ciphertext to Bob
var aliceSecret = alice.Decapsulate(ciphertext);
// Alice will use aliceSecret
```

C# code example

## HybridMlKem

### Motivation

### Description

### Restrictions

### How to use

## Tests

## Examples
