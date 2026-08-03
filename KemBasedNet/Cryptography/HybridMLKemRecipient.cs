using Rotherprivat.KemBasedNet.Cryptography.Internal;
using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Rotherprivat.KemBasedNet.Cryptography
{
    /// <summary>
    /// Recipient for HybridMlKemAuthEnveloped encryption and decryption
    /// </summary>
    public class HybridMLKemRecipient
    {
        #region Public properties

        /// <summary>
        /// X509 SubjectKeyIdentifier SHA1 of public key (SubjectIPublicKeyInfo) used for key exchange
        /// </summary>
        public byte[]? SubjectKeyId { get; private set; }

        /// <summary>
        /// CipherText from KEM-Encapsulation
        /// </summary>
        public byte[]? CipherText { get; private set; }

        /// <summary>
        /// Content Encryption Key, wrapped / encrypted by KEK from KEM-Encapsulation
        /// </summary>
        public byte[]? EncryptedCek { get; private set; }
        #endregion

        #region Constructors

        /// <summary>
        /// Create recipient
        /// </summary>
        /// <param name="cer">
        /// X509 Certificate with ML-KEM or Composite-ML-KEM key material. 
        /// Make sure to validate the certificate according to the policies for your use case.
        /// </param>
        /// <exception cref="CryptographicException"></exception>

        public HybridMLKemRecipient(X509Certificate2 cer)
        {
            var publicKey = cer.ExportSubjectPublicKeyInfo();

            if (!IsPublicKeyValid(publicKey))
                throw new CryptographicException("Invalid public key.");

            Init(publicKey);
        }

        /// <summary>
        /// Create recipient
        /// </summary>
        /// <param name="key">Public key of ML-KEM</param>
        public HybridMLKemRecipient(MLKem key)
        {
#pragma warning disable SYSLIB5006
            var publicKey = key.ExportSubjectPublicKeyInfo();
#pragma warning restore SYSLIB5006
            Init(publicKey);
        }

        /// <summary>
        /// Create recipient
        /// </summary>
        /// <param name="key">Public key of Composite-ML-KEM</param>
        public HybridMLKemRecipient(CompositeMLKem key)
        {
            var publicKey = key.ExportSubjectPublicKeyInfo();
            Init(publicKey);
        }

        /// <summary>
        /// Create recipient
        /// </summary>
        /// <param name="subjectPublicKeyInfo">X509-SubjectPublicKeyInfo; DER-Encoded public key</param>
        /// <exception cref="CryptographicException"></exception>
        public HybridMLKemRecipient(byte[] subjectPublicKeyInfo)
        {
            if (!IsPublicKeyValid (subjectPublicKeyInfo))
                throw new CryptographicException("Invalid public key.");

            Init(subjectPublicKeyInfo);
        }
        #endregion

        #region Internal methods
        internal void Encrypt(ReadOnlySpan<byte> cek)
        {
            Encapsulate(out var cipherText, out var kek);
            CipherText = cipherText;

            EncryptedCek = Rfc3394.Wrap(kek, cek);
        }

        internal byte[]? Decrypt(MLKem privateKey)
        {
            if (CipherText == null ||
                EncryptedCek == null)
                throw new CryptographicException("Incomplete Recipient data.");

            var kek = privateKey.Decapsulate(CipherText);
            return Rfc3394.Unwrap(kek, EncryptedCek);
        }

        internal byte[]? Decrypt(CompositeMLKem privateKey)
        {
            if (CipherText == null ||
                EncryptedCek == null)
                throw new CryptographicException("Incomplete Recipient data.");

            var kek = privateKey.Decapsulate(CipherText);
            return Rfc3394.Unwrap(kek, EncryptedCek);
        }

        internal void Serialize(Stream s)
        {
            if (!s.CanWrite)
                throw new ArgumentException("stream not writeable");

            if (SubjectKeyId == null ||
                CipherText == null ||
                EncryptedCek == null)
                throw new CryptographicException("Incomplete Recipient data.");
              
            using var bw = new BinaryWriter(s, Encoding.UTF8, true);
            bw.Write(SubjectKeyId.Length);
            bw.Write(SubjectKeyId);
            bw.Write(CipherText.Length); 
            bw.Write(CipherText); 
            bw.Write(EncryptedCek.Length); 
            bw.Write(EncryptedCek);
        }

        internal static HybridMLKemRecipient Deserialize(Stream s)
        {
            if (!s.CanRead)
                throw new ArgumentException("stream not readable");

            var me = new HybridMLKemRecipient();

            using var br = new BinaryReader(s, Encoding.UTF8, true);
            int len = br.ReadInt32();
            me.SubjectKeyId = br.ReadBytes(len);

            len = br.ReadInt32();
            me.CipherText = br.ReadBytes(len);

            len = br.ReadInt32();
            me.EncryptedCek = br.ReadBytes(len);

            return me;
        }
        #endregion

        #region Hidden constructor
        private HybridMLKemRecipient() { }
        #endregion

        #region Private mehtods
        private void Init(byte[] subjectPublicKeyInfo)
        {
            _SubjectPublicKeyInfo = subjectPublicKeyInfo;
            SubjectKeyId = SHA1.HashData(subjectPublicKeyInfo);
        }

        private static bool IsPublicKeyValid(byte[] publicKey)
        {
            return KemTypeHelper.GetKemTypeFromSubjectPublicKeyInfo(publicKey) switch
            {
                KemType.MLKem or 
                KemType.CompositeMLKem 
                  => true,
                _ => false,
            };
        }

        private void Encapsulate(out byte[] cipherText, out byte[] key)
        {
            cipherText = key = [];
            if (_SubjectPublicKeyInfo == null)
                throw new CryptographicException("Invalid or missing Key");

#pragma warning disable SYSLIB5006
            switch (KemTypeHelper.GetKemTypeFromSubjectPublicKeyInfo(_SubjectPublicKeyInfo))
            {
                case KemType.MLKem:
                    {
                        using var kem = MLKem.ImportSubjectPublicKeyInfo(_SubjectPublicKeyInfo);
                        kem.Encapsulate(out cipherText, out key);
                    }
                    break;
                case KemType.CompositeMLKem:
                    {
                        using var kem = CompositeMLKem.ImportSubjectPublicKeyInfo(_SubjectPublicKeyInfo);
                        kem.Encapsulate(out cipherText, out key);
                    }
                    break;
                default:
                    throw new CryptographicException("Invalid or missing Key");
            }
#pragma warning restore SYSLIB5006
        }
        #endregion

        #region Private fields
        private byte[]? _SubjectPublicKeyInfo = default;
        #endregion
    }
}
