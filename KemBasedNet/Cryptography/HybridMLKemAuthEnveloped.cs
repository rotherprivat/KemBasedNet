using System;
using System.Collections.Generic;
using System.Data;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Rotherprivat.KemBasedNet.Cryptography
{
    /// <summary>
    /// Keys and algorithm implementation for encrypting and decrypting data,
    /// based on Post Quantum Key exchange algorithms. Intended for one to many use cases
    /// <list type="bullet">
    /// <item><description>ML-KEM: <a href="https://csrc.nist.gov/pubs/fips/203/final">FIPS 203</a></description></item>
    /// <item><description>CombinedMLKem: <a href="https://lamps-wg.github.io/draft-composite-kem/draft-ietf-lamps-pq-composite-kem.html">IETF draft</a></description></item>
    /// </list>
    /// </summary>
    public class HybridMLKemAuthEnveloped
    {
        #region Public properies
        /// <summary>
        /// Indicates if the algorithm supported by the current platform
        /// </summary>
        public static bool IsSupported => MLKem.IsSupported;

        /// <summary>
        /// Compatibility version, also identifies the encoding version
        /// </summary>
        public int Version { get; private set; } = 1;

        /// <summary>
        /// Custom IdTag e.g. a UUID (optional),  an identifier for the encoded data will be verified on decoding.
        /// </summary>
        public string IdTag { get; set; } = "8308160B-1B1F-429A-8D48-C9B67F8BD4AE"; // default IdTag

        /// <summary>
        /// List of recipients of the encrypted message
        /// </summary>
        public IList<HybridMLKemRecipient> Recipients { get; set; } = [];

        /// <summary>
        /// Plaintext data for encryption or after decryption
        /// </summary>
        public byte[] Content 
        {
            get => _Content ?? throw new CryptographicException("No Content data.");
            set => _Content = value;
        }

        #endregion

        #region Public methods
        /// <summary>
        /// Encrypt plaintext content for one recipient
        /// </summary>
        /// <param name="recipient">Recipient</param>
        public void Encrypt(HybridMLKemRecipient recipient)
        {
            var recipients = new List<HybridMLKemRecipient>
            {
                recipient
            };

            Encrypt(recipients);
        }

        /// <summary>
        /// Encrypt plaintext content for a list of recipients
        /// </summary>
        /// <param name="recipients">List of recipients</param>
        public void Encrypt(IList<HybridMLKemRecipient> recipients)
        {
            Span<byte> cek = stackalloc byte[32];
            RandomNumberGenerator.Fill(cek);

            foreach (var recipient in recipients)
            {
                recipient.Encrypt(cek);
                Recipients.Add(recipient);
            }

            EncryptContent(cek);

            // zero cek
            cek.Clear();
        }

        /// <summary>
        /// Decrypt encrypted data by a given private key. The key must 
        /// match to one of the public keys the content is encrypted with.
        /// The decrypted plaintext is assigned to the "Content" property.
        /// </summary>
        /// <param name="privateKey">ML-KEM Private key</param>
        /// <exception cref="CryptographicException"></exception>
        public void Decrypt(MLKem privateKey)
        {
#pragma warning disable SYSLIB5006
            var publicKey = privateKey.ExportSubjectPublicKeyInfo();
#pragma warning restore SYSLIB5006
            var subjectKeyId = SHA1.HashData(publicKey);

            var recipient = Recipients.Where(r => r.SubjectKeyId.SequenceEqual(subjectKeyId)).FirstOrDefault()
                    ?? throw new CryptographicException("No recipient with matching key.");

            var cek = recipient.Decrypt(privateKey);

            DecryptContent(cek);
        }

        /// <summary>
        /// Decrypt encrypted data by a given private key. The key must 
        /// match to one of the public keys the content is encrypted with.
        /// The decrypted plaintext is assigned to the "Content" property.
        /// </summary>
        /// <param name="privateKey">Composite-ML-KEM Private key</param>
        /// <exception cref="CryptographicException"></exception>
        public void Decrypt(CompositeMLKem privateKey)
        {
            var publicKey = privateKey.ExportSubjectPublicKeyInfo();
            var subjectKeyId = SHA1.HashData(publicKey);

            var recipient = Recipients.Where(r => r.SubjectKeyId.SequenceEqual(subjectKeyId)).FirstOrDefault()
                ?? throw new CryptographicException("No recipient with matching key");
            var cek = recipient.Decrypt(privateKey);

            DecryptContent(cek);
        }

        /// <summary>
        /// Write encrypted content and recipient info to buffer
        /// </summary>
        /// <returns>buffer containing encrypted content and recipient info</returns>
        /// <exception cref="CryptographicException"></exception>
        public byte[] Encode()
        {
            if (_EncryptedContent == null)
                throw new CryptographicException("No Data.");

            if (Recipients.Count == 0)
                throw new CryptographicException("No Recipients.");

            using var ms = new MemoryStream();
            using (var bw = new BinaryWriter(ms, Encoding.UTF8, true))
            {
                bw.Write(IdTag);

                bw.Write(Version);

                bw.Write(Recipients.Count);
            }

            foreach(var recipient in Recipients)
            {
                recipient.Serialize(ms);
            }

            _EncryptedContent.Serialize(ms);
            ms.Close();

            return ms.ToArray();
        }

        /// <summary>
        /// Decode the message from encodedMessage, verify Version and 
        /// </summary>
        /// <param name="encodedMessage">Message buffer</param>
        /// <exception cref="CryptographicException"></exception>
        public void Decode(byte[] encodedMessage)
        {
            int recipientsCount = 0;

            using var ms = new MemoryStream(encodedMessage);
            using (var br = new BinaryReader(ms, Encoding.UTF8, true))
            {
                var idTagOfMessage = br.ReadString();
                if (string.Compare(IdTag, idTagOfMessage, StringComparison.InvariantCulture) != 0)
                    throw new CryptographicException($"Identifier mismatch: {idTagOfMessage}.");

                var versionOfMessage = br.ReadInt32();
                if (versionOfMessage != 1)
                    throw new CryptographicException($"Version {versionOfMessage} not supported");

                Version = versionOfMessage;

                recipientsCount = br.ReadInt32();
            }
            for (int i = 0; i <recipientsCount; i++)
                Recipients.Add(HybridMLKemRecipient.Deserialize(ms));

            _EncryptedContent = HybridMLKemCipherData.Deserialize(ms);
        }
        #endregion

        #region Private methods
        private void EncryptContent(ReadOnlySpan<byte> cek)
        {
            if (_Content == null)
                throw new CryptographicException("No content Data.");

            // generate nonce and Encrypt the plaintext using AES-GCM
            var nonce = RandomNumberGenerator.GetBytes(12);
            var tag = new byte[16];
            var encryptedPlaintext = new byte[_Content.Length];
            using var aes = new AesGcm(cek, tag.Length);

            aes.Encrypt(nonce, _Content, encryptedPlaintext, tag);

            _EncryptedContent = new HybridMLKemCipherData()
            {
                GcmNonce = nonce,
                EncryptedPlainText = encryptedPlaintext,
                GcmTag = tag
            };
        }

        private void DecryptContent(ReadOnlySpan<byte> cek)
        {
            if (_EncryptedContent == null)
                throw new CryptographicException("No content Data.");
            var nonce = _EncryptedContent.GcmNonce;
            var tag = _EncryptedContent.GcmTag;

            _Content = new byte[_EncryptedContent.EncryptedPlainText.Length];

            using var aes = new AesGcm(cek, tag.Length);
            aes.Decrypt(nonce, _EncryptedContent.EncryptedPlainText, tag, _Content);
        }
        #endregion

        #region Private fields
        private HybridMLKemCipherData? _EncryptedContent = null;
        private byte[]? _Content = null;
        #endregion
    }
}