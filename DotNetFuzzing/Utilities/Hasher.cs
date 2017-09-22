using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotNetFuzzing.Utilities
{
    public static class Hasher
    {
        public const uint FnvPrime32 = 16777619;
        public const uint FnvOffset32 = 2166136261;
        public static uint Hash32(byte[] bytesToHash)
        {
            //this is the actual hash function; very simple
            uint hash = FnvOffset32;

            foreach (var chunk in bytesToHash)
            {
                hash ^= chunk;
                hash *= FnvPrime32;
            }

            return hash;
        }
    }
}
