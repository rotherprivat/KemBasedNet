using Rotherprivat.KemBasedNet.Cryptography;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace Rotherprivat.KemBasedNetTest.Cryptography
{
    [TestClass]
    public class TestHybridMLKemAuthEnveloped
    {
        private static IEnumerable<object[]> MlKemAlgorithms => TestAlgorithms.MlKemAlgorithms;
        private static IEnumerable<object[]> CompositeMlKemAlgorithms => TestAlgorithms.CompositeMlKemAlgorithms;

        private TestVector? _TestVector;

        [TestInitialize]
        public void Init()
        {
            var strTestVector = File.ReadAllText(@"./Cryptography/testvectors.json");
            _TestVector = JsonSerializer.Deserialize<TestVector>(strTestVector);
        }

        [TestMethod]
        public void _00_IsSupported()
        {
            Assert.IsTrue(HybridMLKemAuthEnveloped.IsSupported, "PQC-Algorithms not supported by your platform.");
        }

        [TestMethod]
        public void _01_Roundtrip()
        {
            if (null == _TestVector)
                throw new InvalidOperationException("NoTestData");

            string message = "The quick brown fox jumps over the lazy dog.";

            var testData = _TestVector.tests["id-MLKEM1024-ECDH-P521-SHA3-256"] ??
                    throw new InvalidOperationException("requested TestData missing");
            var dk_pkcs8 = Convert.FromBase64String(testData.dk_pkcs8);
            using var rootCa = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(_TestVector.cacert));
            using var cer = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(testData.x5c));

            var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(rootCa);
            // add store for intermediate certificates
            // chain.ChainPolicy.ExtraStore.Add(..);

            bool isValid = chain.Build(cer);
            Assert.IsTrue(isValid, "Certificate Chain is not valid");

            using var r1keypair = CompositeMLKem.GenerateKey(CompositeMLKemAlgorithm.KMKem1024WithECDhP521Sha3);
            using var r2keypair = MLKem.GenerateKey(MLKemAlgorithm.MLKem1024);

            byte[] buffer = r1keypair.ExportSubjectPublicKeyInfo();
            using var r1public = CompositeMLKem.ImportSubjectPublicKeyInfo(buffer);

#pragma warning disable SYSLIB5006
            buffer = r2keypair.ExportSubjectPublicKeyInfo();
            using var r2public = MLKem.ImportSubjectPublicKeyInfo(buffer);
#pragma warning restore SYSLIB5006

            var enc = new HybridMLKemAuthEnveloped
            {
                Content = Encoding.UTF8.GetBytes(message)
            };

            var recipients = new List<HybridMLKemRecipient>
            {
                new(r1public),
                new(r2public),
                new(cer)
            };

            enc.Encrypt(recipients);
            var encData = enc.Encode();


            var dec1 = new HybridMLKemAuthEnveloped();
            dec1.Decode(encData);
            dec1.Decrypt(r1keypair);

            string? decryptedMessage = Encoding.UTF8.GetString(dec1.Content);
            Assert.AreEqual(message, decryptedMessage, $"Original and decrypted message are different.");

            var dec2 = new HybridMLKemAuthEnveloped();
            dec2.Decode(encData);
            dec2.Decrypt(r2keypair);

            decryptedMessage = Encoding.UTF8.GetString(dec2.Content);
            Assert.AreEqual(message, decryptedMessage, $"Original and decrypted message are different.");

            using var r3keypair = CompositeMLKem.ImportPkcs8PrivateKey(dk_pkcs8);
            var dec3 = new HybridMLKemAuthEnveloped(); ;
            dec3.Decode(encData);
            dec3.Decrypt(r3keypair);

            decryptedMessage = Encoding.UTF8.GetString(dec3.Content);
            Assert.AreEqual(message, decryptedMessage, $"Original and decrypted message are different.");

            using var r4keypair = MLKem.GenerateKey(MLKemAlgorithm.MLKem1024);
            var dec4 = new HybridMLKemAuthEnveloped();
            dec4.Decode(encData);
            Assert.ThrowsExactly<CryptographicException>(() => dec4.Decrypt(r4keypair));
        }
    }
}
