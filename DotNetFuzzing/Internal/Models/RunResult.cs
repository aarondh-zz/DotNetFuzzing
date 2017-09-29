using DotNetFuzzing.Common;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotNetFuzzing.Fuzzing.Internal.Models
{
    public class RunResult : IRunResult
    {
        public RunResult(RunOutcomes outcome = RunOutcomes.FAULT_NONE, int reason = 0,Exception exception = null)
        {
            this.Outcome = outcome;
            this.Exception = exception;
        }
        public RunOutcomes Outcome { get; }
        public int Reason { get; }
        public Exception Exception { get; }

        public override string ToString()
        {
            return $"Outcome = {Outcome}, Exception = {Exception?.Message}";
        }
    }
}
