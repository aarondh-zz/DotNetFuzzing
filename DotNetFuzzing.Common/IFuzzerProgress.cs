using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotNetFuzzing.Common
{
    public interface IFuzzerProgress
    {
        int QueueCycle { get; }
        int QueueSize { get; }
        int QueueIndex { get; }
        string StageName { get; }
        string StageShortName { get; }
        int CurrentStageByte { get; }
        int CurrentStageValue { get; }
    }
}
