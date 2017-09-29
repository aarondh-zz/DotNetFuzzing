using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotNetFuzzing.Common
{
    public interface IRunResult
    {
        RunOutcomes Outcome { get; }
        int Reason { get; }
        Exception Exception { get; }
    }
}
