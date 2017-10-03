using DotNetFuzzing.Common;
using System;
using System.Collections.Generic;
using System.Text;

namespace DontNetFuzzing.Console
{
    public class StatisticsListener : IStatisticsListener
    {
        private ILogger _logger;
        public StatisticsListener( ILogger logger)
        {
            _logger = logger;
        }
        public void ReportStatistics(IFuzzerStatistics statistics)
        {
        }
    }
}
