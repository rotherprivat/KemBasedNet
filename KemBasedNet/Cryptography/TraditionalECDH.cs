using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;

namespace Rotherprivat.KemBasedNet.Cryptography
{
    internal class TraditionalECDH : ITraditionalKem
    {
        private ECDiffieHellman? _traditionalECDH = null;
        public CompositeMLKemAlgorithm? Algorithm { get ;  set ; }

        public static ITraditionalKem GenerateKey(CompositeMLKemAlgorithm algorithm)
        {
            return new TraditionalECDH()
            {
                _traditionalECDH = ECDiffieHellman.Create(algorithm.ECCurve),
                Algorithm = algorithm
            };
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                _traditionalECDH?.Dispose();
            }
            _traditionalECDH = null;
            Algorithm = null;
        }

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        public static ITraditionalKem ImportPrivateKey(CompositeMLKemAlgorithm algorithm, ReadOnlySpan<byte> ecdhPrivate)
        {
            var ecdh = ECDiffieHellman.Create();
            ecdh.ImportECPrivateKey(ecdhPrivate, out _);

            return new TraditionalECDH()
            {
                _traditionalECDH = ecdh,
                Algorithm = algorithm
            };
        }

        public static ITraditionalKem ImportPublicKey(CompositeMLKemAlgorithm algorithm, ReadOnlySpan<byte> traditionalPublic)
        {
            var ecParams = ReadPublicECParameters(algorithm, traditionalPublic);
            ecParams.Validate();

            return new TraditionalECDH()
            {
                _traditionalECDH = ECDiffieHellman.Create(ecParams),
                Algorithm = algorithm
            };

        }

        public static ECParameters ReadPublicECParameters(CompositeMLKemAlgorithm algorithm, ReadOnlySpan<byte> tradPk)
        {
            if (tradPk[0] != 0x04)
                throw new CryptographicException("Invalid Ciphertext");

            var x = tradPk.Slice(1, algorithm.ECPointValueSizeInBytes);
            var y = tradPk.Slice(1 + algorithm.ECPointValueSizeInBytes, algorithm.ECPointValueSizeInBytes);

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

        public byte[] ExportPublicKey()
        {
            EnsureValid();
            var param = _traditionalECDH.ExportParameters(false);
            return param.ExportECPublicKeyBytes();
        }

        public byte[] Encapsulate(Span<byte> tradCT)
        {
            EnsureValid();
            using var ecEphemeralKey = ECDiffieHellman.Create(Algorithm.ECCurve);
            var ecKey = ecEphemeralKey.DeriveRawSecretAgreement(_traditionalECDH.PublicKey);
            var ecParam = ecEphemeralKey.ExportParameters(false);

            // append to ciphertext tradCT = public part of ephemeral key 
            tradCT[0] = 0x04;
            var p = tradCT.Slice(1, Algorithm.ECPointValueSizeInBytes);
            ecParam.Q.X.CopyTo(p);
            p = tradCT.Slice(Algorithm.ECPointValueSizeInBytes + 1, Algorithm.ECPointValueSizeInBytes);
            ecParam.Q.Y.CopyTo(p);

            return ecKey;
        }

        public byte[] Decapsulate(Span<byte> tradCT)
        {
            EnsureValid();
            // get traditional ephemeral key from ciphertext
            var ecEphemeralParams = ReadPublicECParameters(Algorithm, tradCT);
            ecEphemeralParams.Validate();
            using var ecEphemeralKey = ECDiffieHellman.Create(ecEphemeralParams);

            // get traditional shared secret
            var tradKey = _traditionalECDH.DeriveRawSecretAgreement(ecEphemeralKey.PublicKey);

            return tradKey;
        }

        public byte[] ExportPrivateKey()
        {
            EnsureValid();
            return _traditionalECDH.ExportECPrivateKeyD();
        }

        [MemberNotNull(nameof(_traditionalECDH), nameof(Algorithm))]
        private void EnsureValid()
        {
            if (_traditionalECDH == null || Algorithm == null)
                throw new CryptographicException("Not initialized.");
        }

    }
}
