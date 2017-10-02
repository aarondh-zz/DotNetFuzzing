using DotNetFuzzing.Common;
using System;
using System.Collections.Generic;
using System.Text;

namespace DontNetFuzzing.Console
{
    public class ProgressMonitor : IProgressMonitor
    {
        private ILogger _logger;
        public ProgressMonitor( ILogger logger)
        {
            _logger = logger;
        }
        public void ReportProgress(IFuzzerProgress progress)
        {
            System.Console.Write($"Cycle {progress.QueueCycle}, Queue {progress.QueueIndex} of {progress.QueueSize}, {progress.StageName} byte[{progress.CurrentStageByte}] = {progress.CurrentStageValue}\r");
        }
    }
}
