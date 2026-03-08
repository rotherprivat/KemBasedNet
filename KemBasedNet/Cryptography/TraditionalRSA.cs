using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;

namespace Rotherprivat.KemBasedNet.Cryptography
{
    internal class TraditionalRSA : ITraditionalKem
    {
        private RSA? _traditionalRSA = null;
        public CompositeMLKemAlgorithm? Algorithm { get; set; } = null;

        public static ITraditionalKem GenerateKey(CompositeMLKemAlgorithm algorithm)
        {
            return new TraditionalRSA()
            {
                Algorithm = algorithm,
                _traditionalRSA = RSA.Create(algorithm.RSAKeySize)
            };
        }

        public static ITraditionalKem ImportPrivateKey(CompositeMLKemAlgorithm algorithm, ReadOnlySpan<byte> ecdhPrivate)
        {
            var rsa = RSA.Create();
            rsa.ImportRSAPrivateKey(ecdhPrivate, out _);

            return new TraditionalRSA()
            {
                Algorithm = algorithm,
                _traditionalRSA = rsa
            };

        }

        public static ITraditionalKem ImportPublicKey(CompositeMLKemAlgorithm algorithm, ReadOnlySpan<byte> traditionalPublic)
        {
            var rsa = RSA.Create();
            rsa.ImportRSAPublicKey(traditionalPublic, out _);

            return new TraditionalRSA()
            {
                Algorithm = algorithm,
                _traditionalRSA = rsa
            };

        }

        public byte[] ExportPublicKey()
        {
            EnsureValid();
            return _traditionalRSA.ExportRSAPublicKey();
        }

        public byte[] ExportPrivateKey()
        {
            EnsureValid();
            return _traditionalRSA.ExportRSAPrivateKey();
        }


        public byte[] Decapsulate(Span<byte> tradCT)
        {
            EnsureValid();
            var key = _traditionalRSA.Decrypt(tradCT, RSAEncryptionPadding.OaepSHA256);
            if (key.Length != 32)
                throw new CryptographicException("Traditional shared key is invalid.");

            return key;
        }


        public byte[] Encapsulate(Span<byte> tradCT)
        {
            EnsureValid();
            var tradKey = RandomNumberGenerator.GetBytes(32);
            _traditionalRSA.Encrypt(tradKey, tradCT, RSAEncryptionPadding.OaepSHA256);
            return tradKey;
        }

        [MemberNotNull(nameof(_traditionalRSA), nameof(Algorithm))]
        private void EnsureValid()
        {
            if (_traditionalRSA == null || Algorithm == null)
                throw new CryptographicException("Not initialized.");
        }


        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                _traditionalRSA?.Dispose();
            }
            _traditionalRSA = null;
            Algorithm = null;
        }


        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

    }
}
