using System.Text;
using System.Security.Cryptography;
using Rotherprivat.KemBasedNet.Cryptography;


namespace Rotherprivat.KemBasedNetTest.Cryptography
{
    [TestClass]
    public sealed class TestHybridMlKem
    {
        private static IEnumerable<object[]> MlKemAlgorithms => TestAlgorithms.MlKemAlgorithms;
        private static IEnumerable<object[]> CompositeMlKemAlgorithms => TestAlgorithms.CompositeMlKemAlgorithms;

        [TestMethod]
        public void _00_IsSupported()
        {
            Assert.IsTrue(HybridMLKem.IsSupported, "PQC-Algorithms not supported by your platform.");
        }

        [TestMethod]
        [DynamicData(nameof(CompositeMlKemAlgorithms))]
        public void _01_ExportComposite(CompositeMLKemAlgorithm algorithm)
        {
            byte[] expectedBuffer;
            byte[] actualBuffer;

            // Generate ML-Kem Key
            using var kem = CompositeMLKem.GenerateKey(algorithm);

            using var hybridMlKem = new HybridMLKem(kem, true);

            expectedBuffer = kem.ExportPrivateKey();
            actualBuffer = hybridMlKem.ExportPrivateKey();
            Assert.AreEqual(expectedBuffer, actualBuffer, ByteArrayComparer.Comparer, $"{algorithm.Name}: ExportPrivateKey failed.");

            expectedBuffer = kem.ExportPkcs8PrivateKey();
            actualBuffer = hybridMlKem.ExportPkcs8PrivateKey();
            Assert.AreEqual(expectedBuffer, actualBuffer, ByteArrayComparer.Comparer, $"{algorithm.Name}: ExportPkcs8PrivateKey failed");

            expectedBuffer = kem.ExportEncapsulationKey();
            actualBuffer = hybridMlKem.ExportEncapsulationKey();
            Assert.AreEqual(expectedBuffer, actualBuffer, ByteArrayComparer.Comparer, $"{algorithm.Name}: ExportEncapsulationKey failed");

            expectedBuffer = kem.ExportSubjectPublicKeyInfo();
            actualBuffer = hybridMlKem.ExportSubjectPublicKeyInfo();
            Assert.AreEqual(expectedBuffer, actualBuffer, ByteArrayComparer.Comparer, $"{algorithm.Name}: ExportSubjectPublicKeyInfo failed");

            var expectedPem = kem.ExportSubjectPublicKeyInfoPem();
            var actualPem = hybridMlKem.ExportSubjectPublicKeyInfoPem();
            Assert.AreEqual(expectedPem, actualPem, $"{algorithm.Name}: ExportSubjectPublicKeyInfoPem failed");
        }

        [TestMethod]
        [DynamicData(nameof(MlKemAlgorithms))]
        public void _01_ExportMlKem(MLKemAlgorithm algorithm)
        {
#pragma warning disable SYSLIB5006
            byte[] expectedBuffer;
            byte[] actualBuffer;

            // Generate ML-Kem Key
            using var kem = MLKem.GenerateKey(algorithm);

            using var hybridMlKem = new HybridMLKem(kem, true);

            expectedBuffer =  kem.ExportPrivateSeed();
            actualBuffer = hybridMlKem.ExportPrivateKey();
            Assert.AreEqual(expectedBuffer, actualBuffer, ByteArrayComparer.Comparer, $"{algorithm.Name}: ExportPrivateKey failed.");

            expectedBuffer = kem.ExportPkcs8PrivateKey();
            actualBuffer = hybridMlKem.ExportPkcs8PrivateKey();
            Assert.AreEqual(expectedBuffer, actualBuffer, ByteArrayComparer.Comparer, $"{algorithm.Name}: ExportPkcs8PrivateKey failed");

            expectedBuffer = kem.ExportEncapsulationKey();
            actualBuffer = hybridMlKem.ExportEncapsulationKey();
            Assert.AreEqual(expectedBuffer, actualBuffer, ByteArrayComparer.Comparer, $"{algorithm.Name}: ExportEncapsulationKey failed");

            expectedBuffer = kem.ExportSubjectPublicKeyInfo();
            actualBuffer = hybridMlKem.ExportSubjectPublicKeyInfo();
            Assert.AreEqual(expectedBuffer, actualBuffer, ByteArrayComparer.Comparer, $"{algorithm.Name}: ExportSubjectPublicKeyInfo failed");

            var expectedPem = kem.ExportSubjectPublicKeyInfoPem();
            var actualPem = hybridMlKem.ExportSubjectPublicKeyInfoPem();
            Assert.AreEqual(expectedPem, actualPem, $"{algorithm.Name}: ExportSubjectPublicKeyInfoPem failed");
#pragma warning restore SYSLIB5006
        }

        [TestMethod]
        [DynamicData(nameof(CompositeMlKemAlgorithms))]
        public void _02_ImportComposite(CompositeMLKemAlgorithm algorithm)
        {
            byte[] expectedBuffer;
            byte[] actualBuffer;
            byte[] buffer;

            // Generate ML-Kem Key
            using var kem = CompositeMLKem.GenerateKey(algorithm);

            // Private key
            expectedBuffer = kem.ExportPrivateKey();
            using (var hybrid = HybridMLKem.ImportPrivateKey(algorithm, expectedBuffer))
            {
                actualBuffer = hybrid.ExportPrivateKey();
            }
            Assert.AreEqual(expectedBuffer, actualBuffer, ByteArrayComparer.Comparer, $"{algorithm.Name}: ImportPrivateKey failed");

            buffer = kem.ExportPkcs8PrivateKey();
            using (var hybrid = HybridMLKem.ImportPkcs8PrivateKey(buffer))
            {
                actualBuffer = hybrid.ExportPrivateKey();
            }
            Assert.AreEqual(expectedBuffer, actualBuffer, ByteArrayComparer.Comparer, $"{algorithm.Name}: ImportPkcs8PrivateKey failed");

            // Public key
            expectedBuffer = kem.ExportEncapsulationKey();
            using (var hybrid = HybridMLKem.ImportEncapsulationKey(algorithm, expectedBuffer))
            {
                actualBuffer = hybrid.ExportEncapsulationKey();
            }
            Assert.AreEqual(expectedBuffer, actualBuffer, ByteArrayComparer.Comparer, $"{algorithm.Name}: ImportEncapsulationKey failed");

            buffer = kem.ExportSubjectPublicKeyInfo();
            using (var hybrid = HybridMLKem.ImportSubjectPublicKeyInfo(buffer))
            {
                actualBuffer = hybrid.ExportEncapsulationKey();
            }
            Assert.AreEqual(expectedBuffer, actualBuffer, ByteArrayComparer.Comparer, $"{algorithm.Name}: ImportSubjectPublicKeyInfo failed");

            var pem = kem.ExportSubjectPublicKeyInfoPem();
            using (var hybrid = HybridMLKem.ImportFromPem(pem))
            {
                actualBuffer = hybrid.ExportEncapsulationKey();
            }
            Assert.AreEqual(expectedBuffer, actualBuffer, ByteArrayComparer.Comparer, $"{algorithm.Name}: ImportFromPem failed");
        }

        [TestMethod]
        [DynamicData(nameof(MlKemAlgorithms))]
        public void _02_ImportMlKem(MLKemAlgorithm algorithm)
        {
#pragma warning disable SYSLIB5006
            byte[] expectedBuffer;
            byte[] actualBuffer;
            byte[] buffer;

            // Generate ML-Kem Key
            using var kem = MLKem.GenerateKey(algorithm);

            // Private key
            expectedBuffer = kem.ExportPrivateSeed();
            using (var hybrid = HybridMLKem.ImportPrivateKey(algorithm, expectedBuffer))
            {
                actualBuffer = hybrid.ExportPrivateKey();
            }
            Assert.AreEqual(expectedBuffer, actualBuffer, ByteArrayComparer.Comparer, $"{algorithm.Name}: ImportPrivateKey failed");

            buffer = kem.ExportPkcs8PrivateKey();
            using (var hybrid = HybridMLKem.ImportPkcs8PrivateKey(buffer))
            {
                actualBuffer = hybrid.ExportPrivateKey();
            }
            Assert.AreEqual(expectedBuffer, actualBuffer, ByteArrayComparer.Comparer, $"{algorithm.Name}: ImportPkcs8PrivateKey failed");

            // Public key
            expectedBuffer = kem.ExportEncapsulationKey();
            using (var hybrid = HybridMLKem.ImportEncapsulationKey(algorithm, expectedBuffer))
            {
                actualBuffer = hybrid.ExportEncapsulationKey();
            }
            Assert.AreEqual(expectedBuffer, actualBuffer, ByteArrayComparer.Comparer, $"{algorithm.Name}: ImportEncapsulationKey failed");

            buffer = kem.ExportSubjectPublicKeyInfo();
            using (var hybrid = HybridMLKem.ImportSubjectPublicKeyInfo(buffer))
            {
                actualBuffer = hybrid.ExportEncapsulationKey();
            }
            Assert.AreEqual(expectedBuffer, actualBuffer, ByteArrayComparer.Comparer, $"{algorithm.Name}: ImportSubjectPublicKeyInfo failed");

            var pem = kem.ExportSubjectPublicKeyInfoPem();
            using (var hybrid = HybridMLKem.ImportFromPem(pem))
            {
                actualBuffer = hybrid.ExportEncapsulationKey();
            }
            Assert.AreEqual(expectedBuffer, actualBuffer, ByteArrayComparer.Comparer, $"{algorithm.Name}: ImportFromPem failed");
#pragma warning restore SYSLIB5006
        }

        [TestMethod]
        public void _03_CipherData()
        {
            string message = "The quick brown fox jumps over the lazy dog.";
            var messageBytes = Encoding.UTF8.GetBytes(message);


            // generate key material
            // Only  tested for one ML-KEM algorithm
            // there is no different code path for ML-KEM CompositeMLKem algorithm, or specific algorithm
            // and the size of ciphertext is well known for ML-KEM
            var algorithm = MLKemAlgorithm.MLKem1024;

            using var hybrid = HybridMLKem.GenerateKey(algorithm);
            var cipher = hybrid.Encrypt(messageBytes);

            Assert.IsNotNull(cipher, "Encrypt failed.");

            // Test field assignment
            Assert.AreEqual(algorithm.CiphertextSizeInBytes, cipher.CipherText.Length, "Unexpected cipher field length.");
            Assert.AreEqual(12, cipher.GcmNonce.Length, "Unexpected cipher field length.");
            Assert.AreEqual(16, cipher.GcmTag.Length, "Unexpected cipher field length.");
            Assert.AreEqual(messageBytes.Length, cipher.EncryptedPlainText.Length, "Unexpected cipher field length.");

            var buffer = cipher.Serialize();
            
            // Serialize / Deserialize and compare
            var actualCipher = HybridMLKemCipherData.Deserialize(buffer);

            Assert.AreEqual(cipher.CipherText, actualCipher.CipherText, ByteArrayComparer.Comparer, "CipherText differs.");
            Assert.AreEqual(cipher.GcmNonce, actualCipher.GcmNonce, ByteArrayComparer.Comparer, "GcmNonce differs.");
            Assert.AreEqual(cipher.GcmTag, actualCipher.GcmTag, ByteArrayComparer.Comparer, "GcmTag differs.");
            Assert.AreEqual(cipher.EncryptedPlainText, actualCipher.EncryptedPlainText, ByteArrayComparer.Comparer, "CipherText differs.");
        }

        [TestMethod]
        [DynamicData(nameof(CompositeMlKemAlgorithms))]
        public void _04_RoundTripComposite(CompositeMLKemAlgorithm algorithm)
        {
            string message = "The quick brown fox jumps over the lazy dog.";
            byte[] pkcs8Key;
            string pemPublicKey;

            using (var key = HybridMLKem.GenerateKey(algorithm))
            {
                pkcs8Key = key.ExportEncryptedPkcs8PrivateKey("secret", new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 210000));
                pemPublicKey = key.ExportSubjectPublicKeyInfoPem();
            }

            using var bob = HybridMLKem.ImportFromPem(pemPublicKey);
            var cipher = bob.Encrypt(Encoding.UTF8.GetBytes(message));

            Assert.IsNotNull(cipher, $"{algorithm.Name}: Encrypt failed.");

            using var alice = HybridMLKem.ImportEncryptedPkcs8PrivateKey("secret", pkcs8Key);


            var decryptedBytes = alice.Decrypt(cipher);
            var decryptedMessage = Encoding.UTF8.GetString(decryptedBytes);

            Assert.AreEqual(message, decryptedMessage, $"{algorithm.Name}: Original and decrypted message are different.");
        }

        [TestMethod]
        [DynamicData(nameof(MlKemAlgorithms))]
        public void _04_RoundTripMlKem(MLKemAlgorithm algorithm)
        {
            string message = "The quick brown fox jumps over the lazy dog.";
            byte[] pkcs8Key;
            string pemPublicKey;

            using (var key = HybridMLKem.GenerateKey(algorithm))
            {
                pkcs8Key = key.ExportEncryptedPkcs8PrivateKey("secret", new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 210000));
                pemPublicKey = key.ExportSubjectPublicKeyInfoPem();
            }

            using var bob = HybridMLKem.ImportFromPem(pemPublicKey);
            var cipher = bob.Encrypt(Encoding.UTF8.GetBytes(message));

            Assert.IsNotNull(cipher, $"{algorithm.Name}: Encrypt failed.");

            using var alice = HybridMLKem.ImportEncryptedPkcs8PrivateKey("secret", pkcs8Key);


            var decryptedBytes = alice.Decrypt(cipher);
            var decryptedMessage = Encoding.UTF8.GetString(decryptedBytes);

            Assert.AreEqual(message, decryptedMessage, $"{algorithm.Name}: Original and decrypted message are different.");
        }
    }
}
