using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;

namespace Rotherprivat.PqCrypto.Cryptography
{
    public class HybridMlKem : IDisposable
    {
        private enum KemType
        {
            MLKem,
            CompositeMLKem
        };

        private HybridMlKem() { }
        public static HybridMlKem GenerateKey(MLKemAlgorithm mLKemAlgorithm)
        {
            return new HybridMlKem()
            {
                _PlainMlKem = MLKem.GenerateKey(mLKemAlgorithm)
            };
        }

        public static HybridMlKem GenerateKey(CompositeMLKemAlgorithm compositeMLKemAlgorithm)
        {
            return new HybridMlKem()
            {
                _CompositeMlKem = CompositeMLKem.GenerateKey(compositeMLKemAlgorithm)
            };
        }

        public static HybridMlKem ImportSubjectPublicKeyInfo(byte[] publicKey)
        {  
            switch (GetKemTypeFromSubjectPublicKeyInfo(publicKey))
            {
                case KemType.MLKem:
                    return new HybridMlKem()
                    {
#pragma warning disable SYSLIB5006
                        _PlainMlKem = MLKem.ImportSubjectPublicKeyInfo(publicKey)
#pragma warning restore SYSLIB5006
                    };
                case KemType.CompositeMLKem:
                    return new HybridMlKem()
                    {
                        _CompositeMlKem = CompositeMLKem.ImportSubjectPublicKeyInfo(publicKey)
                    };
                default:
                    throw new CryptographicException("Invalid public key");
            }
        }

        public static HybridMlKem ImportPkcs8PrivateKey(byte[] privateKey)
        {
            switch (GetKemTypeFromPkcs8PrivateKey(privateKey))
            {
                case KemType.MLKem:
                    return new HybridMlKem()
                    {
#pragma warning disable SYSLIB5006
                        _PlainMlKem = MLKem.ImportPkcs8PrivateKey(privateKey)
#pragma warning restore SYSLIB5006
                    };
                case KemType.CompositeMLKem:
                    return new HybridMlKem()
                    {
                        _CompositeMlKem = CompositeMLKem.ImportPkcs8PrivateKey(privateKey)
                    };
                default:
                    throw new CryptographicException("Invalid public key");
            }
        }

        public byte[] ExportSubjectPublicKeyInfo()
        {
            EnsureValid();

            if (_PlainMlKem != null)
            {
#pragma warning disable SYSLIB5006
                return _PlainMlKem.ExportSubjectPublicKeyInfo();
#pragma warning restore SYSLIB5006
            }

            if (_CompositeMlKem != null)
            {
                return _CompositeMlKem.ExportSubjectPublicKeyInfo();
            }

            throw new CryptographicException("Invalid key configuration"); 
        }

        public byte[] ExportPkcs8PrivateKey()
        {
            EnsureValid();

            if (_PlainMlKem != null)
            {
#pragma warning disable SYSLIB5006
                return _PlainMlKem.ExportPkcs8PrivateKey();
#pragma warning restore SYSLIB5006
            }

            throw new CryptographicException("Invalid key configuration");
        }

        public HybridMlKemCipherData? Encrypt(byte[] plaintext)
        {
            EnsureValid();

            // Encapsulate the symmetric key the cipherText is required for decryption
            Encapsulate(out byte[] cipherText, out byte[] key);

            // generate nonce and Encrypt the plaintext using AES-GCM
            var nonce = RandomNumberGenerator.GetBytes(12);
            var tag = new byte[16];
            var encryptedPlaintext = new byte[plaintext.Length];
            using var aes = new AesGcm(key, tag.Length);

            aes.Encrypt(nonce, plaintext, encryptedPlaintext, tag);

            return new HybridMlKemCipherData()
            {
                CipherText = cipherText,
                GcmNonce = nonce,
                EncryptedPlainText = encryptedPlaintext,
                GcmTag = tag
            };
        }

        public byte[] Decrypt(HybridMlKemCipherData cipherData)
        {
            EnsureValid();

            // Decapsulate the symmetric key
            var key = Decapsulate(cipherData.CipherText)
                ?? throw new CryptographicException("Decapsulate key failed");

            // decrypt the plaintext by AES-GCM using the parameters and EncryptedPayload from cipherData
            var plainText = new byte[cipherData.EncryptedPlainText.Length];

            using var aes = new AesGcm(key, cipherData.GcmTag.Length);

            aes.Decrypt(cipherData.GcmNonce, cipherData.EncryptedPlainText, cipherData.GcmTag, plainText);

            return plainText;
        }

        private void Encapsulate(out byte[] cipherText, out byte[] key)
        {
            cipherText = key = [];
            _PlainMlKem?.Encapsulate(out cipherText, out key);
            _CompositeMlKem?.Encapsulate(out cipherText, out key);
        }

        private byte[]? Decapsulate(byte[] ciphertext)
        {
            if (_PlainMlKem != null)
                return _PlainMlKem.Decapsulate(ciphertext);

            if (_CompositeMlKem != null)
                return _CompositeMlKem.Decapsulate(ciphertext);

            return null;
        }

        private static KemType GetKemTypeFromSubjectPublicKeyInfo(byte[] publicKey)
        {
            var asn1 = new AsnReader(publicKey, AsnEncodingRules.DER);
            var asnPk = asn1.ReadSequence();
            var ObjectId = asnPk.ReadSequence();
            var oid = ObjectId.ReadObjectIdentifier();

            if (CompositeMLKemAlgorithm.FromOid(oid) != null)
                return KemType.CompositeMLKem;
            else
                return KemType.MLKem;
        }

        private static KemType GetKemTypeFromPkcs8PrivateKey(byte[] pkcs8)
        {
            var pckcs8Info = Pkcs8PrivateKeyInfo.Decode(pkcs8, out _);
            var oid = pckcs8Info?.AlgorithmId.Value ??
                throw new CryptographicException("Invalid PKCS#8 data");

            if (CompositeMLKemAlgorithm.FromOid(oid) != null)
                return KemType.CompositeMLKem;
            else
                return KemType.MLKem;
        }


        private void EnsureValid()
        {
            if (_PlainMlKem == default && _CompositeMlKem == default)
                throw new CryptographicException("Not initialized");

            if (_PlainMlKem != default && _CompositeMlKem != default)
                throw new CryptographicException("Invalid key configuration");
        }

        private MLKem? _PlainMlKem  = default;
        private CompositeMLKem? _CompositeMlKem = default;

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                _PlainMlKem?.Dispose();
            }

            _PlainMlKem = null;
        }

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}
