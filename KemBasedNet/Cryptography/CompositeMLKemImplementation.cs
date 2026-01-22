using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Rotherprivat.KemBasedNet.Cryptography
{
    /// <exclude />
    public class CompositeMLKemImplementation : CompositeMLKem
    {
        private MLKem? _MLKem = null;
        private ECDiffieHellman? _ECDH = null;

        internal static CompositeMLKem GenerateKeyImplementation(CompositeMLKemAlgorithm algorithm)
        {
            return new CompositeMLKemImplementation(algorithm)
                {
                    _MLKem = MLKem.GenerateKey(algorithm.MLKemAlgorithm),
                    _ECDH = ECDiffieHellman.Create(algorithm.ECCurve)
                };
        }

        internal static CompositeMLKem ImportPrivateKeyImplementation(CompositeMLKemAlgorithm algorithm, ReadOnlySpan<byte> privateKey)
        {
            var mlKemSeed = privateKey[..algorithm.MLKemAlgorithm.PrivateSeedSizeInBytes];
            var mlKem = MLKem.ImportPrivateSeed(algorithm.MLKemAlgorithm, mlKemSeed);

            var ecdhPrivate = privateKey[algorithm.MLKemAlgorithm.PrivateSeedSizeInBytes..];

            var ecdh = ECDiffieHellman.Create();
            ecdh.ImportECPrivateKey(ecdhPrivate, out _);

            return new CompositeMLKemImplementation(algorithm)
            {
                _MLKem = mlKem,
                _ECDH = ecdh
            };
        }

        internal static CompositeMLKem ImportEncapsulationKeyImplementation(CompositeMLKemAlgorithm algorithm, ReadOnlySpan<byte> encapsulationKey)
        {
            var mlKemEncapsulationKey = encapsulationKey[..algorithm.MLKemAlgorithm.EncapsulationKeySizeInBytes];
            var ecDhPublicBytes = encapsulationKey[algorithm.MLKemAlgorithm.EncapsulationKeySizeInBytes..];

            var ecParams = ReadPublicECParameters(algorithm, ecDhPublicBytes);
            ecParams.Validate();

            return new CompositeMLKemImplementation(algorithm)
            {
                _MLKem = MLKem.ImportEncapsulationKey(algorithm.MLKemAlgorithm, mlKemEncapsulationKey),
                _ECDH = ECDiffieHellman.Create(ecParams)
            };

        }

        /// <summary>
        /// Hidden Constructor
        /// </summary>
        /// <param name="algorithm"></param>
        protected CompositeMLKemImplementation(CompositeMLKemAlgorithm algorithm)
        : base(algorithm)
        {
        }

        protected override void ExportPrivateKeyImplementation(Span<byte> privateKey)
        {
            EnsureValid();

            var mlKemSeed = privateKey[..Algorithm.MLKemAlgorithm.PrivateSeedSizeInBytes];
            _MLKem.ExportPrivateSeed(mlKemSeed);

            var ecPriv = _ECDH.ExportECPrivateKeyD();
            var p = privateKey[Algorithm.MLKemAlgorithm.PrivateSeedSizeInBytes..];
            ecPriv.CopyTo(p);
        }

        protected override void ExportEncapsulationKeyImplementation(Span<byte> keyBuffer)
        {
            EnsureValid();
            var p = keyBuffer[..Algorithm.MLKemAlgorithm.EncapsulationKeySizeInBytes];

            _MLKem.ExportEncapsulationKey(p);

            var ecdhParameters = _ECDH.ExportParameters(false);
            ecdhParameters.Validate();
            var tradPK = keyBuffer[Algorithm.MLKemAlgorithm.EncapsulationKeySizeInBytes..];
            tradPK[0] = 0x04;
            p = tradPK.Slice(1, Algorithm.ECPointValueSizeInBytes);
            ecdhParameters.Q.X.CopyTo(p);

            p = tradPK.Slice(Algorithm.ECPointValueSizeInBytes + 1, Algorithm.ECPointValueSizeInBytes);
            ecdhParameters.Q.Y.CopyTo(p);
        }

        protected override void EncapsulateImplementation(Span<byte> ciphertext, Span<byte> sharedSecret)
        {
            EnsureValid();
            
            // generate traditional ephemeral key and traditional shared secret
            using var ecEphemeralKey = ECDiffieHellman.Create(Algorithm.ECCurve);
            var ecKey = ecEphemeralKey.DeriveRawSecretAgreement(_ECDH.PublicKey);

            // ML-KEM get ciphertext and KL-KEM shared secret
            byte[] mlKemKey = new byte[Algorithm.MLKemAlgorithm.SharedSecretSizeInBytes];
            var p = ciphertext[..Algorithm.MLKemAlgorithm.CiphertextSizeInBytes];
            _MLKem.Encapsulate(p, mlKemKey);

            var ecParam = ecEphemeralKey.ExportParameters(false);

            // append to ciphertext tradCT = public part of ephemeral key 
            var tradCT = ciphertext[Algorithm.MLKemAlgorithm.CiphertextSizeInBytes..];
            tradCT[0] = 0x04;
            p = tradCT.Slice(1, Algorithm.ECPointValueSizeInBytes);
            ecParam.Q.X.CopyTo(p);
            p = tradCT.Slice(Algorithm.ECPointValueSizeInBytes + 1, Algorithm.ECPointValueSizeInBytes);
            ecParam.Q.Y.CopyTo(p);

            var ecdhParameters = _ECDH.ExportParameters(false);
            ecdhParameters.Validate();

            // combine ML-KEM- and traditional shared secret
            Combine(mlKemKey, ecKey, ecParam.Q, ecdhParameters.Q, Algorithm.Label).CopyTo(sharedSecret);
        }

        protected override void DecapsulateImplementation(ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret)
        {
            EnsureValid();

            // ML-KEM get  KL-KEM shared secret
            var mlKemCipherText = ciphertext[..Algorithm.MLKemAlgorithm.CiphertextSizeInBytes];
            var mlKemKey = new byte[Algorithm.MLKemAlgorithm.SharedSecretSizeInBytes];
            _MLKem.Decapsulate(mlKemCipherText, mlKemKey);


            // get traditional ephemeral key from ciphertext
            var tradCTbytes = ciphertext[Algorithm.MLKemAlgorithm.CiphertextSizeInBytes..];
            var tradCT = ReadPublicECParameters(Algorithm, tradCTbytes);
            tradCT.Validate();
            using var ecEphemeralKey = ECDiffieHellman.Create(tradCT);

            // get traditional shared secret
            var tradKey = _ECDH.DeriveRawSecretAgreement(ecEphemeralKey.PublicKey);
            var tradPK = _ECDH.ExportParameters(false);
            tradPK.Validate();

            // combine ML-KEM- and traditional shared secret
            Combine(mlKemKey, tradKey,tradCT.Q, tradPK.Q, Algorithm.Label).CopyTo(sharedSecret);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _MLKem?.Dispose();
                _ECDH?.Dispose();
            }
            _MLKem = null;
            _ECDH = null;
            base.Dispose(disposing);
        }


        [MemberNotNull(nameof(_MLKem), nameof(_ECDH))]
        private void EnsureValid()
        {
            if (_MLKem == null || _ECDH == null)
                throw new CryptographicException("Not initialized.");
        }

        private static byte[] Combine(byte[] mlkemKey, byte[] tradKey, ECPoint tradCT, ECPoint tradPK, byte[] label)
        {
            using var sha3 = SHA3_256.Create();
            sha3.TransformBlock(mlkemKey, 0, mlkemKey.Length, null, 0);
            sha3.TransformBlock(tradKey, 0, tradKey.Length, null, 0);
            TransformEcPoint(sha3, tradCT);
            TransformEcPoint(sha3, tradPK);
            sha3.TransformFinalBlock(label, 0, label.Length);

            return sha3.Hash ?? throw new CryptographicException("Failed to Combine Keys");
        }

        private static void TransformEcPoint(HashAlgorithm hash, ECPoint p)
        {
            hash.TransformBlock([0x04], 0, 1, null, 0);
            hash.TransformBlock(p.X!, 0, p.X!.Length, null, 0);
            hash.TransformBlock(p.Y!, 0, p.Y!.Length, null, 0);
        }

        private static ECParameters ReadPublicECParameters(CompositeMLKemAlgorithm algorithm, ReadOnlySpan<byte> tradPk)
        {
            if (tradPk[0] != 0x04)
                throw new CryptographicException("Invalid Ciphertext");

            var x = tradPk.Slice(1, algorithm.ECPointValueSizeInBytes);
            var y = tradPk.Slice(1+ algorithm.ECPointValueSizeInBytes, algorithm.ECPointValueSizeInBytes);

            return new ECParameters()
            {
                Curve = algorithm.ECCurve,
                D = null,
                Q = new ECPoint()
                {
                    X = x.ToArray(),
                    Y = y.ToArray()
                }
            };
        }
    }
}
