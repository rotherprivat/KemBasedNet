using Rotherprivat.PqCrypto.Cryptography;
using System;
using System.Collections.Generic;
using System.Text;

namespace Rotherprivat.PqTest.Examples
{
    [TestClass]
    public sealed class TestReadmeExamples
    {
        [TestMethod]
        public void CompositeMLKemExample()
        {
            // Generate the key material
            var algorithm = CompositeMLKemAlgorithm.KMKem1024WithECDhP521Sha3;
            using var alice = CompositeMLKem.GenerateKey(algorithm);

            var derPublicKey = alice.ExportSubjectPublicKeyInfo();

            // Forward derPublicKey to Bob
            using var bob = CompositeMLKem.ImportSubjectPublicKeyInfo(derPublicKey);

            bob.Encapsulate(out var ciphertext, out var bobsSecret);
            // Bob will use bobsSecret

            // Forward ciphertext to Alice
            var aliceSecret = alice.Decapsulate(ciphertext);
            // Alice will use aliceSecret

            // Verify secrets
            Assert.IsTrue(bobsSecret.SequenceEqual(aliceSecret), "Key exchange failed, the shared secrets are different");
        }

        [TestMethod]
        public void HybridMLKemExample()
        {
            string message = "The quick brown fox jumps over the lazy dog.";

            // Generate the key material
            var algorithm = CompositeMLKemAlgorithm.KMKem1024WithECDhP521Sha3;
            using var alice = HybridMLKem.GenerateKey(algorithm);

            var derPublicKey = alice.ExportSubjectPublicKeyInfo();

            // Forward derPublicKey to Bob
            using var bob = HybridMLKem.ImportSubjectPublicKeyInfo(derPublicKey);

            // Encrypt message by using public key
            var encryptedDataBlock = bob.Encrypt(Encoding.UTF8.GetBytes(message))?.Serialize();

            Assert.IsNotNull(encryptedDataBlock, "Encryption failed.");

            // Forward encryptedDataBlock (encrypted message and parameters for decryption) to Alice

            // Decrypt message by using private key
            var decryptedBuffer = alice.Decrypt(HybridMLKemCipherData.Deserialize(encryptedDataBlock));
            var decryptedMessage = Encoding.UTF8.GetString(decryptedBuffer);

            Assert.AreEqual(message, decryptedMessage, "original and decrypted message are different");
        }

    }
}
