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

            // generate key material
            var algorithm = MLKemAlgorithm.MLKem1024;
            using var keys = MLKem.GenerateKey(algorithm);
            // you could also use: HybridMlKem.GenerateKey(algorithm);

#pragma warning disable SYSLIB5006
            var alicePrivateKey = keys.ExportPkcs8PrivateKey();
            var alicePublicKey = keys.ExportSubjectPublicKeyInfo();
#pragma warning restore SYSLIB5006

            // bob encrypts a message using alice public key
            var encryptedMessageBytes = BobEncryptText(alicePublicKey, message);

            // send encrypted message to alice

            // alice decrypts the message using her private key
            var plaintext = AliceDecryptText(alicePrivateKey, encryptedMessageBytes);

            Assert.AreEqual(message, plaintext);
        }

        [TestMethod]
        public void HybridMLKemEncryptDecrypt_CompositeMLKem()
        {
             string message = "The quick brown fox jumps over the lazy dog.";
            
            // generate key material
            var algorithm = CompositeMLKemAlgorithm.KMKem1024WithECDhP521Sha3;

            using var keys = CompositeMLKem.GenerateKey(algorithm);
            // you could also use: HybridMlKem.GenerateKey(algorithm);

            var alicePrivateKey = keys.ExportPkcs8PrivateKey();
            var alicePublicKey = keys.ExportSubjectPublicKeyInfo();

            // bob encrypts a message using alice public key
            var encryptedMessageBytes = BobEncryptText(alicePublicKey, message);

            // send encrypted message to alice

            // alice decrypts the message using her private key
            var plaintext = AliceDecryptText(alicePrivateKey, encryptedMessageBytes);

            Assert.AreEqual(message, plaintext);
        }

        private static byte[] BobEncryptText(byte[] derPublicKey, string message)
        {
            using var bob = HybridMLKem.ImportSubjectPublicKeyInfo(derPublicKey);
            var cipher = bob.Encrypt(Encoding.UTF8.GetBytes(message));
            Assert.IsNotNull(cipher);

            return cipher.Serialize(); 
        }

        private static string AliceDecryptText(byte[] pkcs8PrivateKey, byte[] encryptedMessageBytes)
        {
            using var alice = HybridMLKem.ImportPkcs8PrivateKey(pkcs8PrivateKey);

            var decryptedPlaintextBytes = alice.Decrypt(HybridMLKemCipherData.Deserialize(encryptedMessageBytes));
            return Encoding.UTF8.GetString(decryptedPlaintextBytes);
        }
    }
}
