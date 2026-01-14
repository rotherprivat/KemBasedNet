namespace Rotherprivat.PqCrypto.Cryptography
{
    /// <summary>
    /// Encrypted data and parameters for decryption
    /// </summary>
    public class HybridMlKemCipherData
    {
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
    }
}
