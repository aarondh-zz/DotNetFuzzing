using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotNetFuzzing.Common
{
    public interface ILogger
    {
        void Log(LogLevel level, string messageTemplate, params object[] arguments);
        void Fatal(string messageTemplate, params object[] arguments);
        void Fatal(Exception exception, string messageTemplate, params object[] arguments);
        void Error(string messageTemplate, params object[] arguments);
        void Error(Exception exception, string messageTemplate, params object[] arguments);
        void Warning(string messageTemplate, params object[] arguments);
        void Warning(Exception exception, string messageTemplate, params object[] arguments);
        void Information(string messageTemplate, params object[] arguments);
        void Information(Exception exception, string messageTemplate, params object[] arguments);
        void Verbose(string messageTemplate, params object[] arguments);
        void Verbose(Exception exception, string messageTemplate, params object[] arguments);
    }
}
