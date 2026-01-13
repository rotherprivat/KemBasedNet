using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics.Contracts;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Text;
using static System.Runtime.InteropServices.JavaScript.JSType;

// standards:
// doc: https://lamps-wg.github.io/draft-composite-kem/draft-ietf-lamps-pq-composite-kem.html
// git: https://github.com/lamps-wg/draft-composite-kem


namespace Rotherprivat.PqCrypto.Cryptography
{
    public abstract class CompositeMLKem : IDisposable
    {
        public CompositeMLKemAlgorithm  Algorithm { get; }

        public static CompositeMLKem GenerateKey(CompositeMLKemAlgorithm algorithm)
        {
            return CompositeMLKemImplementation.GenerateKeyImplementation(algorithm);
        }

        public static CompositeMLKem ImportPrivateKey(CompositeMLKemAlgorithm algorithm, byte[] privateKey)
        {
            return CompositeMLKemImplementation.ImportPrivateKeyImplementation(algorithm, privateKey);
        }

        public static CompositeMLKem ImportPkcs8PrivateKey(byte[] pkcs8)
        {
            // Requires ReadOnlMemory<T>
            var pckcs8Info = Pkcs8PrivateKeyInfo.Decode(pkcs8, out _);
            var oid = pckcs8Info?.AlgorithmId.Value;

            if (oid == null)
                throw new CryptographicException("Failed to parse PKCS#8.");

            var algorithm = CompositeMLKemAlgorithm.FromOid(oid);
            if (algorithm == null)
                throw new CryptographicException("Invalid algorithm ID.");

            var privateKey = pckcs8Info!.PrivateKeyBytes;

            return CompositeMLKemImplementation.ImportPrivateKeyImplementation(algorithm, privateKey.Span);
        }

        public static CompositeMLKem ImportPkcs8PrivateKey(ReadOnlySpan<byte> pkcs8)
        {
            // Copy to Array ...
            return ImportPkcs8PrivateKey(pkcs8.ToArray());
        }

        public static CompositeMLKem ImportEncryptedPkcs8PrivateKey(ReadOnlySpan<byte> passwordBytes, byte[] pkcs8)
        {
            var pckcs8Info = Pkcs8PrivateKeyInfo.DecryptAndDecode(passwordBytes, pkcs8, out _);
            var oid = pckcs8Info?.AlgorithmId.Value;

            if (oid == null)
                throw new CryptographicException("Failed to parse PKCS#8.");

            var algorithm = CompositeMLKemAlgorithm.FromOid(oid);
            if (algorithm == null)
                throw new CryptographicException("Invalid algorithm ID.");

            var privateKey = pckcs8Info!.PrivateKeyBytes;

            return CompositeMLKemImplementation.ImportPrivateKeyImplementation(algorithm, privateKey.Span);
        }

        public static CompositeMLKem ImportEncryptedPkcs8PrivateKey(ReadOnlySpan<char> password, byte[] pkcs8)
        {
            var pckcs8Info = Pkcs8PrivateKeyInfo.DecryptAndDecode(password, pkcs8, out _);
            var oid = pckcs8Info?.AlgorithmId.Value;

            if (oid == null)
                throw new CryptographicException("Failed to parse PKCS#8.");

            var algorithm = CompositeMLKemAlgorithm.FromOid(oid);
            if (algorithm == null)
                throw new CryptographicException("Invalid algorithm ID.");

            var privateKey = pckcs8Info!.PrivateKeyBytes;

            return CompositeMLKemImplementation.ImportPrivateKeyImplementation(algorithm, privateKey.Span);
        }

        public static CompositeMLKem ImportEncryptedPkcs8PrivateKey(string password, byte[] pkcs8)
        {
            var pckcs8Info = Pkcs8PrivateKeyInfo.DecryptAndDecode(password, pkcs8, out _);
            var oid = pckcs8Info?.AlgorithmId.Value;

            if (oid == null)
                throw new CryptographicException("Failed to parse PKCS#8.");

            var algorithm = CompositeMLKemAlgorithm.FromOid(oid);
            if (algorithm == null)
                throw new CryptographicException("Invalid algorithm ID.");

            var privateKey = pckcs8Info!.PrivateKeyBytes;

            return CompositeMLKemImplementation.ImportPrivateKeyImplementation(algorithm, privateKey.Span);
        }

        public static CompositeMLKem ImportPublicKey(CompositeMLKemAlgorithm algorithm, byte[] publicKey)
        {
            return CompositeMLKemImplementation.ImportPublicKeyImplementation(algorithm, publicKey);
        }

        public static CompositeMLKem ImportPublicKey(CompositeMLKemAlgorithm algorithm, ReadOnlySpan<byte> publicKey)
        {
            return CompositeMLKemImplementation.ImportPublicKeyImplementation(algorithm, publicKey);
        }

        public static CompositeMLKem ImportSubjectPublicKeyInfo(byte[] publicKey)
        {
            var asn1 = new AsnReader(publicKey, AsnEncodingRules.DER);
            var asnPk = asn1.ReadSequence();
            var ObjectId = asnPk.ReadSequence();
            var oid = ObjectId.ReadObjectIdentifier();
            if (ObjectId.HasData)
                ObjectId.ReadNull();

            var publicKeyBytes = asnPk.ReadBitString(out _);

            var algorithm = CompositeMLKemAlgorithm.FromOid(oid) ??
                throw new CryptographicException("Invalid Algorithm");


            return CompositeMLKemImplementation.ImportPublicKeyImplementation(algorithm, publicKeyBytes);
        }

        public static CompositeMLKem ImportSubjectPublicKeyInfo(ReadOnlySpan<byte> publicKey)
        {
            // Copy to Array ...
            return ImportSubjectPublicKeyInfo(publicKey.ToArray());
        }

        public static CompositeMLKem ImportFromPem(string publicKeyPem)
        {
            var pem = PemEncoding.Find(publicKeyPem);
            var label = publicKeyPem[pem.Label];
            if (label != PemLabels.PublicKey)
                throw new CryptographicException("Invalid PEM-Type");

            var base64Data = publicKeyPem[pem.Base64Data];

            var derData = Convert.FromBase64String(base64Data);

            return ImportSubjectPublicKeyInfo(derData);
        }

        public static CompositeMLKem ImportFromPem(ReadOnlySpan<char> publicKeyPem)
        {
            var pem = PemEncoding.Find(publicKeyPem);
            var label = publicKeyPem[pem.Label];
            if (label != PemLabels.PublicKey)
                throw new CryptographicException("Invalid PEM-Type");

            var base64Data = publicKeyPem[pem.Base64Data].ToString();

            var derData = Convert.FromBase64String(base64Data);


            return ImportSubjectPublicKeyInfo(derData);
        }

        public byte[] ExportPrivateKey()
        {
            var privateKey = new byte[Algorithm.MLKemAlgorithm.PrivateSeedSizeInBytes + Algorithm.ECPrivateKeyDSizeInBytes];
            ExportPrvateKeyImplementation(privateKey);
            return privateKey;
        }

        public void ExportPrivateKey(Span<byte> privateKey)
        {
            ExportPrvateKeyImplementation(privateKey);
        }

        public byte[] ExportPkcs8PrivateKey()
        {
            var privateKey = ExportPrivateKey();
            var pckcs8Info = new Pkcs8PrivateKeyInfo(new Oid(Algorithm.Oid), null, privateKey);
            return pckcs8Info.Encode();
        }

        public byte[] ExportEncryptedPkcs8PrivateKey(ReadOnlySpan<byte> passwordbytes, PbeParameters pbeParameters)
        {
            var privateKey = ExportPrivateKey();
            var pckcs8Info = new Pkcs8PrivateKeyInfo(new Oid(Algorithm.Oid), null, privateKey);
            return pckcs8Info.Encrypt(passwordbytes, pbeParameters);
        }

        public byte[] ExportEncryptedPkcs8PrivateKey(ReadOnlySpan<char> password, PbeParameters pbeParameters)
        {
            var privateKey = ExportPrivateKey();
            var pckcs8Info = new Pkcs8PrivateKeyInfo(new Oid(Algorithm.Oid), null, privateKey);
            return pckcs8Info.Encrypt(password, pbeParameters);
        }

        public byte[] ExportEncryptedPkcs8PrivateKey(string password, PbeParameters pbeParameters)
        {
            var privateKey = ExportPrivateKey();
            var pckcs8Info = new Pkcs8PrivateKeyInfo(new Oid(Algorithm.Oid), null, privateKey);
            return pckcs8Info.Encrypt(password, pbeParameters);
        }

        public byte[] ExportSubjectPublicKeyInfo()
        {
            return ExportSubjectPublicKeyInfoAsAsn().Encode();
        }

        public string ExportSubjectPublicKeyInfoPem()
        {
            var buffer = ExportSubjectPublicKeyInfo();
            return PemEncoding.WriteString(PemLabels.PublicKey, buffer);
        }
        
        public byte[] ExportEncapsulationKey()
        {
            int keyLength = Algorithm.ECPublicKeySizeInBytes +
                            Algorithm.MLKemAlgorithm.EncapsulationKeySizeInBytes;

            byte[] keyBuffer = new byte[keyLength];
            ExportEncapsulationKeyImplementation(keyBuffer);
            return keyBuffer;
        }

        public void ExportEncapsulationKey(Span<byte> keyBuffer)
        {
            int keyLength = Algorithm.ECPublicKeySizeInBytes +
                            Algorithm.MLKemAlgorithm.EncapsulationKeySizeInBytes;

            if (keyBuffer.Length < keyLength)
                throw new CryptographicException("Invalid buffer size.");

            ExportEncapsulationKeyImplementation(keyBuffer);
        }

        public void Encapsulate(out byte[] ciphertext, out byte[] sharedSecret)
        {
            var cipherTextLen = Algorithm.ECPublicKeySizeInBytes +
                                Algorithm.MLKemAlgorithm.CiphertextSizeInBytes;

            ciphertext = new byte[cipherTextLen];
            sharedSecret = new byte[SHA3_256.HashSizeInBytes];

            Encapsulate(ciphertext, sharedSecret);
        }

        public void Encapsulate(Span<byte> ciphertext, Span<byte> sharedSecret)
        {
            EncapsulateImplementation(ciphertext, sharedSecret);
        }

        public byte[] Decapsulate(byte[] ciphertext)
        {
            var sharedSecret = new byte[SHA3_256.HashSizeInBytes];
            Decapsulate(ciphertext, sharedSecret);
            return sharedSecret;
        }

        public void Decapsulate(ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret)
        {
            DecapsulateImplementation(ciphertext, sharedSecret);
        }

        /// <summary>
        /// Implementation of ExportPrvateKey logic in derived class
        /// </summary>
        /// <param name="privateKey"></param>
        /// <exclude/>
        protected abstract void ExportPrvateKeyImplementation(Span<byte> privateKey);

        /// <summary>
        /// Implementation of ExportEncapsulationKey logic in derived class
        /// </summary>
        /// <param name="keyBuffer"></param>
        /// <exclude/>
        protected abstract void ExportEncapsulationKeyImplementation(Span<byte> keyBuffer);

        /// <summary>
        /// Implementation of Encapsulate logic in derived class
        /// </summary>
        /// <param name="ciphertext"></param>
        /// <param name="sharedSecret"></param>
        /// <exclude/>
        protected abstract void EncapsulateImplementation(Span<byte> ciphertext, Span<byte> sharedSecret);

        /// <summary>
        /// Implementation of Decapsulate logic in derived class
        /// </summary>
        /// <param name="ciphertext"></param>
        /// <param name="sharedSecret"></param>
        /// <exclude/>
        protected abstract void DecapsulateImplementation(ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret);

        /// <summary>
        /// Hidden consturctor
        /// </summary>
        /// <param name="algorithm"></param>
        /// <exclude/>
        protected CompositeMLKem(CompositeMLKemAlgorithm algorithm)
        {
            Algorithm = algorithm;
        }

        private AsnWriter ExportSubjectPublicKeyInfoAsAsn()
        {
            int keyLength = Algorithm.ECPublicKeySizeInBytes +
                            Algorithm.MLKemAlgorithm.EncapsulationKeySizeInBytes;

            byte[] keyBuffer = new byte[keyLength];
            ExportEncapsulationKeyImplementation(keyBuffer);

            var asn1 = new AsnWriter(AsnEncodingRules.DER);
            using (asn1.PushSequence())
            {
                //AlgorithmIdentifier
                using (asn1.PushSequence())
                {
                    asn1.WriteObjectIdentifier(Algorithm.Oid);
                    //                    asn1.WriteNull();
                }

                asn1.WriteBitString(keyBuffer);
            }

            return asn1;
        }

        #region IDisposable
        private bool disposedValue;

        /// <exclude/>
        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    // TODO: dispose managed state (managed objects)
                }

                // TODO: free unmanaged resources (unmanaged objects) and override finalizer
                // TODO: set large fields to null
                disposedValue = true;
            }
        }

        // // TODO: override finalizer only if 'Dispose(bool disposing)' has code to free unmanaged resources
        // ~CompositeMLKem()
        // {
        //     // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        //     Dispose(disposing: false);
        // }

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
        #endregion
    }
}
