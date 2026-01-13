using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Net.Http.Headers;
using System.Reflection.Emit;
using System.Runtime.Intrinsics.Arm;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Rotherprivat.PqCrypto.Cryptography
{
    /// <exclude />
    public class CompositeMLKemImplementation : CompositeMLKem
    {
        private MLKem? _MLKem = null;
        private ECDiffieHellman? _ECDh = null;

        internal static CompositeMLKem GenerateKeyImplementation(CompositeMLKemAlgorithm algorithm)
        {
            return new CompositeMLKemImplementation(algorithm)
                {
                    _MLKem = MLKem.GenerateKey(algorithm.MLKemAlgorithm),
                    _ECDh = ECDiffieHellman.Create(algorithm.ECCurve)
                };
        }

        internal static CompositeMLKem ImportPrivateKeyImplementation(CompositeMLKemAlgorithm algorithm, ReadOnlySpan<byte> privateKey)
        {
            var mlKemSeed = privateKey.Slice(0, algorithm.MLKemAlgorithm.PrivateSeedSizeInBytes);
            var mlKem = MLKem.ImportPrivateSeed(algorithm.MLKemAlgorithm, mlKemSeed);

            var ecdhPrivate = privateKey.Slice(algorithm.MLKemAlgorithm.PrivateSeedSizeInBytes);

            var ecdh = ECDiffieHellman.Create();
            ecdh.ImportECPrivateKey(ecdhPrivate, out _);

            return new CompositeMLKemImplementation(algorithm)
            {
                _MLKem = mlKem,
                _ECDh = ecdh
            };
        }

        internal static CompositeMLKem ImportPublicKeyImplementation(CompositeMLKemAlgorithm algorithm, ReadOnlySpan<byte> publicKey)
        {
            var mlKemEncapsulationKey = publicKey.Slice(0, algorithm.MLKemAlgorithm.EncapsulationKeySizeInBytes);
            var ecDhPublicBytes = publicKey.Slice(algorithm.MLKemAlgorithm.EncapsulationKeySizeInBytes);

            var ecParams = ReadECParameters(algorithm, ecDhPublicBytes);
            ecParams.Validate();

            return new CompositeMLKemImplementation(algorithm)
            {
                _MLKem = MLKem.ImportEncapsulationKey(algorithm.MLKemAlgorithm, mlKemEncapsulationKey),
                _ECDh = ECDiffieHellman.Create(ecParams)
            };

        }

        /// <summary>
        /// Hidden Cosntructor
        /// </summary>
        /// <param name="algorithm"></param>
        protected CompositeMLKemImplementation(CompositeMLKemAlgorithm algorithm)
        : base(algorithm)
        {
        }

        protected override void EncapsulateImplementation(Span<byte> ciphertext, Span<byte> sharedSecret)
        {
            EnsureValid();
            using var ecEphemeralKey = ECDiffieHellman.Create(Algorithm.ECCurve);
            var p = ciphertext.Slice(0, Algorithm.MLKemAlgorithm.CiphertextSizeInBytes);
//            var ecKey = ecEphemeralKey.DeriveKeyMaterial(_ECDh.PublicKey);
            var ecKey = ecEphemeralKey.DeriveRawSecretAgreement(_ECDh.PublicKey);

            byte[] mlKemKey = new byte[Algorithm.MLKemAlgorithm.SharedSecretSizeInBytes];
            _MLKem.Encapsulate(p, mlKemKey);
            var ecParam = ecEphemeralKey.ExportParameters(false);

            var tradCT = ciphertext.Slice(Algorithm.MLKemAlgorithm.CiphertextSizeInBytes);

            tradCT[0] = 0x04;

            p = tradCT.Slice(1, Algorithm.ECPointValueSizeInBytes);

            
            ecParam.Q.X.CopyTo(p);

            p = tradCT.Slice(Algorithm.ECPointValueSizeInBytes + 1, Algorithm.ECPointValueSizeInBytes);

            ecParam.Q.Y.CopyTo(p);

            var ecdhParameters = _ECDh.ExportParameters(false);

            ecdhParameters.Validate();

            Combine(mlKemKey, ecKey, ecParam.Q, ecdhParameters.Q, Algorithm.Label).CopyTo(sharedSecret);
        }
        protected override void DecapsulateImplementation(ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret)
        {
            EnsureValid();
            var mlKemCipherText = ciphertext.Slice(0, Algorithm.MLKemAlgorithm.CiphertextSizeInBytes);
            var tradCTbytes = ciphertext[Algorithm.MLKemAlgorithm.CiphertextSizeInBytes..];

            var tradCT = ReadECParameters(Algorithm, tradCTbytes);
            tradCT.Validate();

            var mlKemKey = new byte[Algorithm.MLKemAlgorithm.SharedSecretSizeInBytes];
            _MLKem.Decapsulate(mlKemCipherText, mlKemKey);


            using var ecEphemeralKey = ECDiffieHellman.Create(tradCT);

            //var tradKey = _ECDh.DeriveKeyMaterial(ecEphemeralKey.PublicKey);
            var tradKey = _ECDh.DeriveRawSecretAgreement(ecEphemeralKey.PublicKey);
            var tradPK = _ECDh.ExportParameters(false);
            tradPK.Validate();

            Combine(mlKemKey, tradKey,tradCT.Q, tradPK.Q, Algorithm.Label).CopyTo(sharedSecret);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _MLKem?.Dispose();
                _ECDh?.Dispose();
            }
            _MLKem = null;
            _ECDh = null;
            base.Dispose(disposing);
        }


        [MemberNotNull("_MLKem", "_ECDh")]
        private void EnsureValid()
        {
            if (_MLKem == null || _ECDh == null)
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

        private static ECParameters ReadECParameters(CompositeMLKemAlgorithm algorithm, ReadOnlySpan<byte> tradPk)
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

        protected override void ExportEncapsulationKeyImplementation(Span<byte> keyBuffer)
        {
            EnsureValid();
            var p = keyBuffer[..Algorithm.MLKemAlgorithm.EncapsulationKeySizeInBytes];

            _MLKem.ExportEncapsulationKey(p);

            var ecdhParameters = _ECDh.ExportParameters(false);
            ecdhParameters.Validate();
            var tradPK = keyBuffer[Algorithm.MLKemAlgorithm.EncapsulationKeySizeInBytes..];
            tradPK[0] = 0x04;
            p = tradPK.Slice(1, Algorithm.ECPointValueSizeInBytes);
            ecdhParameters.Q.X.CopyTo(p);

            p = tradPK.Slice(Algorithm.ECPointValueSizeInBytes + 1, Algorithm.ECPointValueSizeInBytes);
            ecdhParameters.Q.Y.CopyTo(p);
        }

        protected override void ExportPrvateKeyImplementation(Span<byte> privateKey)
        {
            EnsureValid();

            var mlKemSeed = privateKey[..Algorithm.MLKemAlgorithm.PrivateSeedSizeInBytes];
            _MLKem.ExportPrivateSeed(mlKemSeed);
            var ecParms = _ECDh.ExportParameters(true);

            var ecPriv = _ECDh.ExportECPrivateKeyD();
            var p = privateKey[Algorithm.MLKemAlgorithm.PrivateSeedSizeInBytes..];
            ecPriv.CopyTo(p);
        }
    }
}
