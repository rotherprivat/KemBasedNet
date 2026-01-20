# Tests

## PQTest.Cryptography

### TestCompositeMLKem

Tests for CompositeMLKem class and implementation. Not all methods tests can be covered by test vectors, 
but we can verify Key-Import, -Export and Decapsulation by test vectors, the remaining functionality 
is tested by round trips (Encapsulate - Decapsulate => Compare the shared secres).

| Test | Verifys |
| --- | --- |
| _01_DecapsulateByTestVectors | - ImportPrivateKey<br>- Combining algorithm<br>- Decapsulate |
| _02_ExportPkcs8PrivateKeyByTestVectors | - ExportPkcs8PrivateKey |
| _03_ImportPkcs8PrivateKeyByTestVectors | - ImportPkcs8PrivateKey |
| _04_ExportEncapsulationKeyByVectors | - ExportEncapsulationKey<br>- ExportSubjectPublicKeyInfo<br>- ExportSubjectPublicKeyInfoPem |
| _05_RoundtripVectors | - ImportEncapsulationKey<br>- Encapsulate<br>- Decapsulate |
| _06_RoundtripExchangeKeyPkcs8Der | - Encapsulate<br>- ImportSubjectPublicKeyInfo |
| _07_RoundtripExchangeKeyPkcs8EncryptedPem | - ImportFromPem<br>- ExportEncryptedPkcs8PrivateKey<br>- ImportEncryptedPkcs8PrivateKey |
