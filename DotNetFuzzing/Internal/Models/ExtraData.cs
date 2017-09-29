using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotNetFuzzing.Fuzzing.Internal.Models
{
    public class ExtraData
    {
        public byte[] Data { get; set; } // Token data
        public int Length { get; set; }
        public int HitCount { get; set; } // Use count in the corpus
    }
}
