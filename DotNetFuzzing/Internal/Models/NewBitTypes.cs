using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotNetFuzzing.Internal.Models
{
    [Flags]
    public enum NewBitTypes
    {
        NoNewBits = 0x00,
        HitCount = 0x01,
        NewTuple = 0x02
    }
}
