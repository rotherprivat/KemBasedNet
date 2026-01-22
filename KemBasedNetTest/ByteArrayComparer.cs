using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Rotherprivat.KemBasedNetTest
{
    internal class ByteArrayComparer : IEqualityComparer<byte[]>
    {
        private static readonly ByteArrayComparer Instance = new ();

        public bool Equals(byte[]? x, byte[]? y)
        {
            ArgumentNullException.ThrowIfNull(x);
            ArgumentNullException.ThrowIfNull(y);

            return x.SequenceEqual(y);
        }

        public int GetHashCode([DisallowNull] byte[] obj)
        {
            return Convert.ToBase64String(obj).GetHashCode();
        }

        public static ByteArrayComparer Comparer {  get { return Instance; } }
    }
}
