using DotNetFuzzing.Common;
using System;
using System.Collections.Generic;
using System.Text;

namespace DontNetFuzzing.Console
{
    public class ProgressListener : IProgressListener
    {
        private ILogger _logger;
        public ProgressListener( ILogger logger)
        {
            _logger = logger;
        }
        public void ReportProgress(IFuzzerProgress progress)
        {
            System.Console.Write($"Cycle {progress.QueueCycle}, Queue {progress.QueueIndex+1} of {progress.QueueSize}, {progress.StageName} step {progress.StageCurrent} of {progress.StageMax} byte[{progress.CurrentStageByte}] = 0X{(byte)progress.CurrentStageValue:X2}\r");
        }
    }
}
