using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Rotherprivat.KemBasedNet.Cryptography
{
    public interface ITratditonalKem: IDisposable
    {
        public CompositeMLKemAlgorithm? Algorithm { get; set; }
        abstract static ITratditonalKem GenerateKey(CompositeMLKemAlgorithm algorithm);
        abstract static ITratditonalKem ImportPrivateKey(CompositeMLKemAlgorithm algorithm, ReadOnlySpan<byte> ecdhPrivate);
        abstract static ITratditonalKem ImportPublicKey(CompositeMLKemAlgorithm algorithm, ReadOnlySpan<byte> traditionalPublic);
        public byte[] Encapsulate(Span<byte> tradCT);
        public byte[] Decapsulate(Span<byte> tradCT);

        public byte[] ExportPublicKey();
        public byte[] ExportPrivateKey();
    }

    public abstract class TratditonalKemFactory
    {
        public static ITratditonalKem GenerateKey(CompositeMLKemAlgorithm algorithm)
        {
            if (algorithm.IsTraditionalECDH)
            {
                return TraditionalECDH.GenerateKey(algorithm);
            }
            else
            {
                return TraditionalRSA.GenerateKey(algorithm);
            }
        }

        public static ITratditonalKem ImportPrivateKey(CompositeMLKemAlgorithm algorithm, ReadOnlySpan<byte> ecdhPrivate)
        {
            if (algorithm.IsTraditionalECDH)
            {
                return TraditionalECDH.ImportPrivateKey(algorithm, ecdhPrivate);
            }
            else
            {
                return TraditionalRSA.ImportPrivateKey(algorithm, ecdhPrivate);
            }
        }

        public static ITratditonalKem ImportPublicKey(CompositeMLKemAlgorithm algorithm, ReadOnlySpan<byte> traditionalPublic)
        {
            if (algorithm.IsTraditionalECDH)
            {
                return TraditionalECDH.ImportPublicKey(algorithm, traditionalPublic);
            }
            else
            {
                return TraditionalRSA.ImportPublicKey(algorithm, traditionalPublic);
            }
        }

    }
}
