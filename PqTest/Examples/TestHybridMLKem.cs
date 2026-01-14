using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Rotherprivat.PqCrypto.Cryptography;
using System.Text;

namespace Rotherprivat.PqTest.Examples
{
    [TestClass]
    public sealed class TestHybridMLKem
    {
        [TestMethod]
        public void HybridMLKemEncryptDecrypt_MLKem1024()
        {
            string message = "The quick brown fox jumps over the lazy dog.";
            var algorithm = MLKemAlgorithm.MLKem1024;

            using var decryptor = HybridMlKem.GenerateKey(algorithm);

            var cipher = decryptor.Encrypt(Encoding.UTF8.GetBytes(message));

            Assert.IsNotNull(cipher);

            var decryptedPlaintextBytes = decryptor.Decrypt(cipher);
            var plaintext = Encoding.UTF8.GetString(decryptedPlaintextBytes);

            Assert.AreEqual(message, plaintext);
        }

        [TestMethod]
        public void HybridMLKemEncryptDecrypt_CompositeMLKem()
        {
            string message = "The quick brown fox jumps over the lazy dog.";
            var algorithm = CompositeMLKemAlgorithm.KMKem1024WithECDhP521Sha3;

            using var decryptor = HybridMlKem.GenerateKey(algorithm);

            var cipher = decryptor.Encrypt(Encoding.UTF8.GetBytes(message));

            Assert.IsNotNull(cipher);

            var decryptedPlaintextBytes = decryptor.Decrypt(cipher);
            var plaintext = Encoding.UTF8.GetString(decryptedPlaintextBytes);

            Assert.AreEqual(message, plaintext);
        }
    }
}
