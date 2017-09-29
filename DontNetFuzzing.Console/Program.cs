using DotNetFuzzing.Common;
using DotNetFuzzing.Common.Implementation;
using DotNetFuzzing.Fuzzing;
using System;

namespace DontNetFuzzing.Console
{
    class Program
    {
        static void Main(string[] args)
        {
            var settings = new FuzzerSettings
            {
                Logger = new ConsoleLogger(),
                FileSystem = new FileSystem(),
                TargetInitiator = new TestTargetInitiator(),
                LogLevel = LogLevel.Verbose,
                InputDirectory = "./examples/example1",
                OutputDirectory = "./output/example1",
                OutFile = "testcase",
                ShuffleQueue = true,
                DumbMode = true,
                Banner = "Example #1"
            };

            var fuzzer = new Fuzzer();
            fuzzer.Fuzz(settings);
        }
    }
}
