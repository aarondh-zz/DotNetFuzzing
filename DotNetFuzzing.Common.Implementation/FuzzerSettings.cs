using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotNetFuzzing.Common.Implementation
{
    public class FuzzerSettings : IFuzzerSettings
    {
        public string InputDirectory{ get; set; }

        public string OutputDirectory{ get; set; }

        private string _documentationDirectory;
        public string DocumentationDirectory
        {
            get
            {
                if (_documentationDirectory == null)
                {
                    return "docs";
                }
                return _documentationDirectory;
            }
            set
            {
                _documentationDirectory = value;
            }
        }

        public string ExtrasDirectory{ get; set; }

        public string MasterSyncId{ get; set; }

        public bool Single{ get; set; }

        public bool Multiple{ get; set; }

        public string SyncId{ get; set; }

        public string TargetFile{ get; set; }

        public TimeSpan? Timeout { get; set; }

        public bool SkipTimeouts { get; set; }

        public bool SkipCrashes { get; set; }

        public long MemoryLimit{ get; set; }

        public bool SkipDeterministic{ get; set; }

        public bool UseSplicing{ get; set; }

        public string FuzzBitmap{ get; set; }

        public bool CrashMode{ get; set; }

        public bool DumbMode{ get; set; }

        public bool QueueMode{ get; set; }

        public string Banner{ get; set; }

        public bool NoForkServer{ get; set; }

        public bool NoCpuMeterRed{ get; set; }

        public bool NoArithmatic{ get; set; }

        public bool ShuffleQueue{ get; set; }

        public bool FactCalcuation{ get; set; }

        public string DumbForkServer{ get; set; }

        public string Preload{ get; set; }

        public TimeSpan? HangTimeout{ get; set; }

        public string QemuBinaryFile{ get; set; }

        public string OutFile{ get; set; }

        public ILogger Logger{ get; set; }

        public IFileSystem FileSystem{ get; set; }

        public long MaxFileSize{ get; set; }

        public LogLevel LogLevel{ get; set; }

        public bool ImportFirst{ get; set; }

        public int SyncInterval{ get; set; }

        public bool BenchJustOne{ get; set; }

        public bool IgnoreFinds{ get; set; }

        public int StatsUpdateFrequency { get; set; }

        public bool RunOver10M{ get; set; }

        public bool ResumeFuzzing{ get; set; }

        public bool ResumeInplace{ get; set; }

        public bool FastCal{ get; set; }

        public bool SimpleFiles{ get; set; }
    }
}
