using System.Security.Cryptography;
using System.Text;
namespace Rotherprivat.PqCrypto.Cryptography
{
    /// <summary>
    /// Encrypted data and parameters for decryption
    /// </summary>
    public class HybridMlKemCipherData
    {
        #region Properties
        /// <summary>
        /// ML-KEM: CipherText
        /// </summary>
        public byte[] CipherText { get; set; } = [];

        /// <summary>
        /// AES-GCM: Nonce
        /// </summary>
        public byte[] GcmNonce { get; set; } = [];

        /// <summary>
        /// AES-GCM: Tag
        /// </summary>
        public byte[] GcmTag { get; set; } = [];

        /// <summary>
        /// Encrypted PlainText
        /// </summary>
        public byte[] EncryptedPlainText { get; set; } = [];
        #endregion

        #region Serialization / Deserialization
        /// <summary>
        /// Serialize as byte buffer
        /// </summary>
        /// <returns>serialized bytes</returns>
        public byte[] Serialize()
        {
            using var ms = new MemoryStream();
            Serialize(ms);
            ms.Close();
            return ms.ToArray();
        }

        /// <summary>
        /// Serialize to stream
        /// </summary>
        /// <param name="s">Writeable stream</param>
        /// <exception cref="ArgumentException"></exception>
        public void Serialize(Stream s)
        {
            if (!s.CanWrite)
                throw new ArgumentException("stream not writeable");

            using var bw = new BinaryWriter(s, Encoding.UTF8, true);
            bw.Write(CipherText.Length);
            bw.Write(CipherText);
            bw.Write(GcmNonce.Length);
            bw.Write(GcmNonce);
            bw.Write(GcmTag.Length);
            bw.Write(GcmTag);
            bw.Write(EncryptedPlainText.Length);
            bw.Write(EncryptedPlainText);
        }

        /// <summary>
        /// Deserialize from byte buffer
        /// </summary>
        /// <param name="buffer">byte buffer</param>
        /// <returns>CipherData object</returns>
        public static HybridMlKemCipherData  Deserialize(byte[] buffer)
        {
            using var ms = new MemoryStream(buffer);
            return Deserialize(ms);
        }

        /// <summary>
        /// Deserialize from stream
        /// </summary>
        /// <param name="s">Readable stream</param>
        /// <returns>CipherData object</returns>
        /// <exception cref="ArgumentException"></exception>
        public static HybridMlKemCipherData Deserialize(Stream s)
        {
            if (!s.CanRead)
                throw new ArgumentException("stream not readable");

            var me = new HybridMlKemCipherData();
            me.DeserializeImplementation(s);
            return me;
        }
        #endregion

        #region Private methods
        private void DeserializeImplementation(Stream s)
        {
            using var br = new BinaryReader(s, Encoding.UTF8, true);
            int len = br.ReadInt32();
            CipherText = br.ReadBytes(len);
            len = br.ReadInt32();
            GcmNonce = br.ReadBytes(len);
            len = br.ReadInt32();
            GcmTag = br.ReadBytes(len);
            len = br.ReadInt32();
            EncryptedPlainText = br.ReadBytes(len);
        }
        #endregion
    }
}
