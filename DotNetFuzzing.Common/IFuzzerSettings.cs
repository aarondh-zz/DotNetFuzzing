using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotNetFuzzing.Common
{
    public interface IFuzzerSettings
    {
        string InputDirectory { get; }
        string OutputDirectory { get; }
        string DocumentationDirectory { get; }
        string ExtrasDirectory { get; }
        string MasterSyncId { get; }

        bool Single { get;}

        bool Multiple { get; }

        string SyncId { get; }

        string TargetFile { get; }

        TimeSpan? Timeout { get; }

        bool SkipTimeouts { get; }

        bool SkipCrashes { get; }

        long MemoryLimit { get; }

        bool SkipDeterministic { get; }
        bool UseSplicing { get; }
        /// <summary>
        /// This is a secret undocumented option! It is useful if you find
        /// an interesting test case during a normal fuzzing process, and want
        /// to mutate it without rediscovering any of the test cases already
        /// found during an earlier run.
        /// To use this mode, you need to point -B to the fuzz_bitmap produced
        /// by an earlier run for the exact same binary... and that's it.
        /// I only used this once or twice to get variants of a particular
        /// file, so I'm not making this an official setting.
        /// </summary>
        string FuzzBitmap { get;  }

        bool CrashMode { get; }
        bool DumbMode { get; }
        bool QueueMode { get; }
        string Banner { get; }

        bool NoForkServer { get; }

        bool NoCpuMeterRed { get; }

        bool NoArithmatic { get; }
        bool ShuffleQueue { get; }
        bool FactCalcuation { get; }
        string DumbForkServer { get; }
        string Preload { get; }

        TimeSpan? HangTimeout { get; }

        string QemuBinaryFile { get; }
        string OutFile { get; }

        ILogger Logger { get; }

        IFileSystem FileSystem { get; }
        long MaxFileSize { get; }

        LogLevel LogLevel { get; }
        bool ImportFirst { get; }
        int SyncInterval { get; }

        bool BenchJustOne { get; }

        bool IgnoreFinds { get; }
        int StatsUpdateFrequency { get; set; }
        bool RunOver10M { get; }

        bool ResumeFuzzing { get; }
        bool ResumeInplace { get; }

        bool FastCal { get; }
        bool SimpleFiles { get; }
    }
}
