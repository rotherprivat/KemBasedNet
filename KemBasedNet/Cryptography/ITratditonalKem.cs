using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Rotherprivat.KemBasedNet.Cryptography
{
    public interface ITratditonalKem: IDisposable
    {
        // for development
        public ECDiffieHellman? _ECDH {  get; set; }

        public CompositeMLKemAlgorithm? Algorithm { get; set; }
        abstract static ITratditonalKem GenerateKey(CompositeMLKemAlgorithm algorithm);
        abstract static ITratditonalKem ImportPrivateKey(CompositeMLKemAlgorithm algorithm, ReadOnlySpan<byte> ecdhPrivate);
        abstract static ITratditonalKem ImportPublicKey(CompositeMLKemAlgorithm algorithm, ReadOnlySpan<byte> traditionalPublic);
        public byte[] Encapsulate(Span<byte> tradPK, Span<byte> tradCT);
        public byte[] Decapsulate(Span<byte> tradPK, Span<byte> tradCT);
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
                throw new NotImplementedException();
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
                throw new NotImplementedException();
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
                throw new NotImplementedException();
            }
        }

    }
}
