using DotNetFuzzing.Common;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotNetFuzzing.Fuzzing.Internal.Models
{
    public class FuzzerProgress : IFuzzerProgress
    {
        public int QueueCycle { get; set; }

        public int QueueSize { get; set; }

        public int QueueIndex { get; set; }

        public string StageName { get; set; }

        public string StageShortName { get; set; }

        public int CurrentStageByte { get; set; }

        public int CurrentStageValue { get; set; }
    }
}
