using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Rotherprivat.KemBasedNet.Cryptography
{
    /// <exclude />
    public class CompositeMLKemImplementation : CompositeMLKem
    {
        private MLKem? _MLKem = null;
        private ECDiffieHellman? _ECDH
        {
            get => _TraditionalKem?._ECDH;
            set => _TraditionalKem = new TraditionalECDH() { _ECDH = value };
        }
        private ITratditonalKem? _TraditionalKem = null;

        internal static CompositeMLKem GenerateKeyImplementation(CompositeMLKemAlgorithm algorithm)
        {
            return new CompositeMLKemImplementation(algorithm)
                {
                    _MLKem = MLKem.GenerateKey(algorithm.MLKemAlgorithm),
                    _TraditionalKem = TratditonalKemFactory.GenerateKey(algorithm)
                };
        }

        internal static CompositeMLKem ImportPrivateKeyImplementation(CompositeMLKemAlgorithm algorithm, ReadOnlySpan<byte> privateKey)
        {
            var mlKemSeed = privateKey[..algorithm.MLKemAlgorithm.PrivateSeedSizeInBytes];
            var mlKem = MLKem.ImportPrivateSeed(algorithm.MLKemAlgorithm, mlKemSeed);

            var ecdhPrivate = privateKey[algorithm.MLKemAlgorithm.PrivateSeedSizeInBytes..];

            return new CompositeMLKemImplementation(algorithm)
            {
                _MLKem = mlKem,
                _TraditionalKem = TratditonalKemFactory.ImportPrivateKey(algorithm, ecdhPrivate),
            };
        }

        internal static CompositeMLKem ImportEncapsulationKeyImplementation(CompositeMLKemAlgorithm algorithm, ReadOnlySpan<byte> encapsulationKey)
        {
            var mlKemEncapsulationKey = encapsulationKey[..algorithm.MLKemAlgorithm.EncapsulationKeySizeInBytes];
            var ecDhPublicBytes = encapsulationKey[algorithm.MLKemAlgorithm.EncapsulationKeySizeInBytes..];

            return new CompositeMLKemImplementation(algorithm)
            {
                _MLKem = MLKem.ImportEncapsulationKey(algorithm.MLKemAlgorithm, mlKemEncapsulationKey),
                _TraditionalKem = TratditonalKemFactory.ImportPublicKey(algorithm, ecDhPublicBytes)
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

            // append to ciphertext tradCT = public part of ephemeral key 
            var tradCT = ciphertext[Algorithm.MLKemAlgorithm.CiphertextSizeInBytes..];
            var tradPK = new byte[2* Algorithm.ECPointValueSizeInBytes +1];
            var tradSecret = _TraditionalKem.Encapsulate(tradPK, tradCT);
            
            // ML-KEM get ciphertext and KL-KEM shared secret
            byte[] mlKemKey = new byte[Algorithm.MLKemAlgorithm.SharedSecretSizeInBytes];
            var p = ciphertext[..Algorithm.MLKemAlgorithm.CiphertextSizeInBytes];
            _MLKem.Encapsulate(p, mlKemKey);

            // combine ML-KEM- and traditional shared secret
            Combine(mlKemKey, tradSecret, tradCT.ToArray(), tradPK, Algorithm.Label).CopyTo(sharedSecret);
        }

        protected override void DecapsulateImplementation(ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret)
        {
            EnsureValid();

            // ML-KEM get  KL-KEM shared secret
            var mlKemCipherText = ciphertext[..Algorithm.MLKemAlgorithm.CiphertextSizeInBytes];
            var mlKemKey = new byte[Algorithm.MLKemAlgorithm.SharedSecretSizeInBytes];
            _MLKem.Decapsulate(mlKemCipherText, mlKemKey);

            var tradCT = ciphertext[Algorithm.MLKemAlgorithm.CiphertextSizeInBytes..].ToArray();
            var tradPK = new byte[tradCT.Length];

            var tradKey = _TraditionalKem.Decapsulate(tradPK, tradCT);


            // combine ML-KEM- and traditional shared secret
            Combine(mlKemKey, tradKey,tradCT, tradPK, Algorithm.Label).CopyTo(sharedSecret);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _MLKem?.Dispose();
                _TraditionalKem?.Dispose();
            }
            _MLKem = null;
            base.Dispose(disposing);
        }


        [MemberNotNull(nameof(_MLKem), nameof(_ECDH))]
        private void EnsureValid()
        {
            if (_MLKem == null || _ECDH == null)
                throw new CryptographicException("Not initialized.");
        }

        private static byte[] Combine(byte[] mlkemKey, byte[] tradKey, byte[] tradCT, byte[] tradPK, byte[] label)
        {
            using var sha3 = SHA3_256.Create();
            sha3.TransformBlock(mlkemKey, 0, mlkemKey.Length, null, 0);
            sha3.TransformBlock(tradKey, 0, tradKey.Length, null, 0);
            sha3.TransformBlock(tradCT, 0, tradCT.Length, null, 0);
            sha3.TransformBlock(tradPK, 0, tradPK.Length, null, 0);
            sha3.TransformFinalBlock(label, 0, label.Length);

            return sha3.Hash ?? throw new CryptographicException("Failed to Combine Keys");
        }
    }
}
