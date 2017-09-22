using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotNetFuzzing.Common
{
    public interface IFileInfo
    {
        DateTime LastWriteTime { get; }
        int Length { get; }
    }
}
