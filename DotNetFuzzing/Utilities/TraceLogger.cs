using DotNetFuzzing.Common;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotNetFuzzing.Utilities
{
    public class TraceLogger : ILogger
    {
        public void Error(string messageTemplate, params object[] arguments)
        {
            Log(LogLevel.Error, messageTemplate, arguments);
        }

        public void Error(Exception exception, string messageTemplate, params object[] arguments)
        {
            Log(LogLevel.Error, messageTemplate, arguments);
        }

        public void Fatal(string messageTemplate, params object[] arguments)
        {
            Log(LogLevel.Fatal, messageTemplate, arguments);
        }

        public void Fatal(Exception exception, string messageTemplate, params object[] arguments)
        {
            Log(LogLevel.Fatal, messageTemplate, arguments);
        }

        public void Information(string messageTemplate, params object[] arguments)
        {
            Log(LogLevel.Information, messageTemplate, arguments);
        }

        public void Information(Exception exception, string messageTemplate, params object[] arguments)
        {
            Log(LogLevel.Information, messageTemplate, arguments);
        }

        public void Log(LogLevel level, string messageTemplate, params object[] arguments)
        {

        }

        public void Verbose(string messageTemplate, params object[] arguments)
        {
            Log(LogLevel.Verbose, messageTemplate, arguments);
        }

        public void Verbose(Exception exception, string messageTemplate, params object[] arguments)
        {
            Log(LogLevel.Verbose, messageTemplate, arguments);
        }

        public void Warning(string messageTemplate, params object[] arguments)
        {
            Log(LogLevel.Warning, messageTemplate, arguments);
        }

        public void Warning(Exception exception, string messageTemplate, params object[] arguments)
        {
            Log(LogLevel.Warning, messageTemplate, arguments);
        }
    }
}
