using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotNetFuzzing.Common
{
    public enum RunOutcomes
    {
        FAULT_NONE,
        FAULT_TMOUT,
        FAULT_ERROR,
        FAULT_NOINST,
        FAULT_NOBITS,
        FAULT_CRASH,
        FAULT_STOPPING
    }
}
