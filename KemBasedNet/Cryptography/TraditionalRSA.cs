using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Rotherprivat.KemBasedNet.Cryptography
{
    public class TraditionalRSA : ITratditonalKem
    {
        private RSA? _traditionalRSA = null;
        public ECDiffieHellman? _ECDH { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public CompositeMLKemAlgorithm? Algorithm { get; set; } = null;

        public static ITratditonalKem GenerateKey(CompositeMLKemAlgorithm algorithm)
        {
            return new TraditionalRSA()
            {
                Algorithm = algorithm,
                _traditionalRSA = RSA.Create(algorithm.RSAKeySize)
            };
        }

        public static ITratditonalKem ImportPrivateKey(CompositeMLKemAlgorithm algorithm, ReadOnlySpan<byte> ecdhPrivate)
        {
            var rsa = RSA.Create();
            rsa.ImportRSAPrivateKey(ecdhPrivate, out _);

            return new TraditionalRSA()
            {
                Algorithm = algorithm,
                _traditionalRSA = rsa
            };

        }

        public static ITratditonalKem ImportPublicKey(CompositeMLKemAlgorithm algorithm, ReadOnlySpan<byte> traditionalPublic)
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
            return _traditionalRSA.ExportRSAPublicKey();
        }


        public byte[] Decapsulate(Span<byte> tradCT)
        {
            var key = _traditionalRSA.Decrypt(tradCT, RSAEncryptionPadding.OaepSHA256);
            return key;
        }


        public byte[] Encapsulate(Span<byte> tradCT)
        {

            throw new NotImplementedException();
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
