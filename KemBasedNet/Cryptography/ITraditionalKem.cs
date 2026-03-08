using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Rotherprivat.KemBasedNet.Cryptography
{
    internal interface ITraditionalKem: IDisposable
    {
        public CompositeMLKemAlgorithm? Algorithm { get; set; }
        abstract static ITraditionalKem GenerateKey(CompositeMLKemAlgorithm algorithm);
        abstract static ITraditionalKem ImportPrivateKey(CompositeMLKemAlgorithm algorithm, ReadOnlySpan<byte> ecdhPrivate);
        abstract static ITraditionalKem ImportPublicKey(CompositeMLKemAlgorithm algorithm, ReadOnlySpan<byte> traditionalPublic);
        public byte[] Encapsulate(Span<byte> tradCT);
        public byte[] Decapsulate(Span<byte> tradCT);

        public byte[] ExportPublicKey();
        public byte[] ExportPrivateKey();
    }

    internal abstract class TraditionalKemFactory
    {
        public static ITraditionalKem GenerateKey(CompositeMLKemAlgorithm algorithm)
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

        public static ITraditionalKem ImportPrivateKey(CompositeMLKemAlgorithm algorithm, ReadOnlySpan<byte> ecdhPrivate)
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

        public static ITraditionalKem ImportPublicKey(CompositeMLKemAlgorithm algorithm, ReadOnlySpan<byte> traditionalPublic)
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
