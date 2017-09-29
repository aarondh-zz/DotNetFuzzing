using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotNetFuzzing.Common.Implementation
{
    public class RunResult : IRunResult
    {
        public RunResult(RunOutcomes outcome = RunOutcomes.FAULT_NONE, int reason = 0, Exception exception = null)
        {
            this.Outcome = outcome;
            this.Reason = reason;
            this.Exception = exception;
        }
        public RunOutcomes Outcome { get; }
        public int Reason { get; }
        public Exception Exception { get; }

        public override string ToString()
        {
            return $"Outcome = {Outcome}, Reason = {Reason}, Exception = {Exception?.Message}";
        }
    }
}
