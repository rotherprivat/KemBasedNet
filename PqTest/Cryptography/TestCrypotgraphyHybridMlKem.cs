using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using Rotherprivat.PqCrypto.Cryptography;


namespace Rotherprivat.PqTest.Cryptography
{
    [TestClass]
    public sealed class TestCryptographyHybridMlKem
    {
        private static IEnumerable<object[]> MlKemAlgorithms => TestAlgorithms.MlKemAlgorithms;

        [TestMethod]
        [DynamicData(nameof(MlKemAlgorithms))]
        public void TestExportPublicKeyPlainMlKem(MLKemAlgorithm algorithm)
        {
#pragma warning disable SYSLIB5006
            using var alice = HybridMlKem.GenerateKey(algorithm);
            var aliceKey = alice.ExportSubjectPublicKeyInfo();

            using var plainMlKem = MLKem.ImportSubjectPublicKeyInfo(aliceKey);

            // Same algorithm?
            Assert.AreEqual(algorithm.EncapsulationKeySizeInBytes, plainMlKem.Algorithm.EncapsulationKeySizeInBytes);

            // roundtrip
            var plainMlKemKey = plainMlKem.ExportSubjectPublicKeyInfo();

            Assert.IsTrue(plainMlKemKey.SequenceEqual(aliceKey), "public keys are different after import export roundtrip.");
            try
            {
                plainMlKem.ExportDecapsulationKey();
                Assert.Fail("plainMlKem instance must not have a private Key");
            }
            catch (AssertFailedException) { throw; }
            catch (CryptographicException) { }
            catch (Exception e)
            {
                Assert.Fail($"Unexpected exception:\n{e}");
            }
#pragma warning restore SYSLIB5006
        }

        [TestMethod]
        [DynamicData(nameof(MlKemAlgorithms))]
        public void TestExportPrivateKeyPlainMlKem(MLKemAlgorithm algorithm)
        {
#pragma warning disable SYSLIB5006
            using var alice = HybridMlKem.GenerateKey(algorithm);
            var aliceKey = alice.ExportPkcs8PrivateKey();

            using var plainMlKem = MLKem.ImportPkcs8PrivateKey(aliceKey);

            // Same algorithm?
            Assert.AreEqual(algorithm.DecapsulationKeySizeInBytes, plainMlKem.Algorithm.DecapsulationKeySizeInBytes);

            // roundtrip
            var plainMlKemKey = plainMlKem.ExportPkcs8PrivateKey();

            Assert.IsTrue(plainMlKemKey.SequenceEqual(aliceKey), "private keys are different after import export roundtrip.");

            var publicKey = plainMlKem.ExportEncapsulationKey();
            Assert.AreEqual(publicKey.Length, algorithm.EncapsulationKeySizeInBytes);
#pragma warning restore SYSLIB5006
        }

        [TestMethod]
        [DynamicData(nameof(MlKemAlgorithms))]
        public void TestImportPublicKeyPlainMlKem(MLKemAlgorithm algorithm)
        {
#pragma warning disable SYSLIB5006
            // generate a plain MLKem Key
            using var mlKem = MLKem.GenerateKey(algorithm);
            var mlKemPublicKey = mlKem.ExportSubjectPublicKeyInfo();


            using var alice = HybridMlKem.ImportSubjectPublicKeyInfo(mlKemPublicKey);

            // roundtrip
            var aliceKey = alice.ExportSubjectPublicKeyInfo();

            Assert.IsTrue(aliceKey.SequenceEqual(mlKemPublicKey), "public keys are different after import export roundtrip.");

            try
            {
                alice.ExportPkcs8PrivateKey();
                Assert.Fail("HybridMlKem instance must not have a private Key");
            }
            catch (AssertFailedException) { throw; }
            catch (CryptographicException) { }
            catch (Exception e)
            {
                Assert.Fail($"Unexpected exception:\n{e}");
            }

#pragma warning restore SYSLIB5006
        }

        [TestMethod]
        [DynamicData(nameof(MlKemAlgorithms))]
        public void TestImportPrivateKeyPlainMlKem(MLKemAlgorithm algorithm)
        {
#pragma warning disable SYSLIB5006
            // generate a plain MLKem Key
            using var mlKem = MLKem.GenerateKey(algorithm);
            var mlKemPrivateKey = mlKem.ExportPkcs8PrivateKey();


            using var alice = HybridMlKem.ImportPkcs8PrivateKey(mlKemPrivateKey);

            // roundtrip
            var aliceKey = alice.ExportPkcs8PrivateKey();

            Assert.IsTrue(aliceKey.SequenceEqual(mlKemPrivateKey), "public keys are different after import export roundtrip.");
#pragma warning restore SYSLIB5006
        }
    }
}
