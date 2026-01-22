using Rotherprivat.KemBasedNet.Cryptography;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Rotherprivat.KemBasedNetTest.Cryptography
{
    public static class TestAlgorithms
    {
        public static IEnumerable<object[]> MlKemAlgorithms
        {
            get
            {
                return
                [
                    [MLKemAlgorithm.MLKem512],
                    [MLKemAlgorithm.MLKem768],
                    [MLKemAlgorithm.MLKem1024]
                ];
            }
        }
        public static IEnumerable<object[]> CompositeMlKemAlgorithms
        {
            get
            {
                return
                [
                    [CompositeMLKemAlgorithm.KMKem768WithECDhP256Sha3],
                    [CompositeMLKemAlgorithm.KMKem768WithECDhP384Sha3],
                    [CompositeMLKemAlgorithm.KMKem1024WithECDhP384Sha3],
                    [CompositeMLKemAlgorithm.KMKem1024WithECDhP521Sha3]
                ];
            }
        }

    }
}
