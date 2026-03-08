# Tests

## KemBasedNetTest.Cryptography

See folder &lt;KemBased&gt;/KemBasedNetTest/Cryptography

### TestCompositeMLKem

Tests for CompositeMLKem class and implementation. Not all methods tests can be covered by test vectors, 
but we can verify key-import, -export and Decapsulate by test vectors, the remaining functionality 
is tested by round trips (Encapsulate - Decapsulate => Compare the shared secrets).

| Test | Verifys |
| --- | --- |
| _00_IsSupported | - IsSupported (PQC-Algorithms supported by platform) |
| _01_DecapsulateByTestVectors | - ImportPrivateKey<br>- Combining algorithm<br>- Decapsulate |
| _02_ExportPkcs8PrivateKeyByTestVectors | - ExportPkcs8PrivateKey |
| _03_ImportPkcs8PrivateKeyByTestVectors | - ImportPkcs8PrivateKey |
| _04_ExportEncapsulationKeyByVectors | - ExportEncapsulationKey<br>- ExportSubjectPublicKeyInfo<br>- ExportSubjectPublicKeyInfoPem |
| _05_RoundtripVectors | - ImportEncapsulationKey<br>- Encapsulate<br>- Decapsulate |
| _06_RoundtripExchangeKeyPkcs8Der | - Encapsulate<br>- ImportSubjectPublicKeyInfo |
| _07_RoundtripExchangeKeyPkcs8EncryptedPem | - ImportFromPem<br>- ExportEncryptedPkcs8PrivateKey<br>- ImportEncryptedPkcs8PrivateKey |

### TestHybridMlKem

Assuming the Key-Exchange algorithms "MLKem" and "CompositeMLKem" as well as the encryption algorithm "AES-GCM" are 
working well, it should be sufficient to verify key-import/-export and Encapsulate-/Decapsulate-calls are 
forwarded to the correct key exchange implementation, the CipherData class and the "AES-GCM" parameter are properly
assigned.

| Test | Verifys |
| --- | --- |
| _00_IsSupported | - IsSupported (PQC-Algorithms supported by platform) |
| _01_Export&lt;...&gt; | - ExportPrivateKey<br>- ExportPkcs8PrivateKey<br>- ExportEncapsulationKey<br>- ExportSubjectPublicKeyInfo<br>- ExportSubjectPublicKeyInfoPem |
| _02_Import&lt;...&gt; | - ImportPrivateKey<br>- ImportPkcs8PrivateKey<br>- ImportEncapsulationKey<br>- ImportSubjectPublicKeyInfo<br>- ImportSubjectPublicKeyInfoPem |
| _03_CipherData | - HybridMlKemCipherData, Serialize/Deserialize<br>- Encrypt, "HybridMlKemCipherData" parameter assignment |
| _04_RoundTrip&lt;...&gt; | - Decrypt |

