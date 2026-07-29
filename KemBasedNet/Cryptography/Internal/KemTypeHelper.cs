using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Text;

namespace Rotherprivat.KemBasedNet.Cryptography.Internal
{
    internal enum KemType
    {
        None,
        MLKem,
        CompositeMLKem
    };

    internal static class KemTypeHelper
    {
        internal static KemType GetKemTypeFromOid(string oid)
        {
            if (CompositeMLKemAlgorithm.FromOid(oid) != null)
                return KemType.CompositeMLKem;

            return oid switch
            {
                "2.16.840.1.101.3.4.4.1" or 
                "2.16.840.1.101.3.4.4.2" or 
                "2.16.840.1.101.3.4.4.3" => KemType.MLKem,

                _ => KemType.None
            };
        }

        internal static KemType GetKemTypeFromSubjectPublicKeyInfo(byte[] publicKey)
        {
            var asn1 = new AsnReader(publicKey, AsnEncodingRules.DER);
            var asnPk = asn1.ReadSequence();
            var ObjectId = asnPk.ReadSequence();
            var oid = ObjectId.ReadObjectIdentifier();

            return GetKemTypeFromOid(oid);
        }

        internal static KemType GetKemTypeFromPkcs8PrivateKey(byte[] pkcs8)
        {
            var pkcs8Info = Pkcs8PrivateKeyInfo.Decode(pkcs8, out _) ??
                throw new CryptographicException("Invalid PKCS#8 data");

            return GetKemTypeFromPkcs8Info(pkcs8Info);
        }

        internal static KemType GetKemTypeFromPkcs8PrivateKey(ReadOnlySpan<byte> passwordBytes, byte[] pkcs8)
        {
            var pkcs8Info = Pkcs8PrivateKeyInfo.DecryptAndDecode(passwordBytes, pkcs8, out _) ??
                throw new CryptographicException("Invalid PKCS#8 data");

            return GetKemTypeFromPkcs8Info(pkcs8Info);
        }

        internal static KemType GetKemTypeFromPkcs8PrivateKey(ReadOnlySpan<char> password, byte[] pkcs8)
        {
            var pkcs8Info = Pkcs8PrivateKeyInfo.DecryptAndDecode(password, pkcs8, out _) ??
                           throw new CryptographicException("Invalid PKCS#8 data");

            return GetKemTypeFromPkcs8Info(pkcs8Info);
        }

        internal static KemType GetKemTypeFromPkcs8Info(Pkcs8PrivateKeyInfo pkcs8Info)
        {
            var oid = pkcs8Info.AlgorithmId.Value ??
                throw new CryptographicException("Invalid PKCS#8 data");

            return GetKemTypeFromOid(oid);
        }

    }
}
