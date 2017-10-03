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
            ILogger logger = new ConsoleLogger();
            var settings = new FuzzerSettings
            {
                Logger = logger,
                FileSystem = new FileSystem(),
                TargetInitiator = new TestTargetInitiator(),
                ProgressListener = new ProgressListener(logger),
                LogLevel = LogLevel.Verbose,
                InputDirectory = "./examples/example1",
                OutputDirectory = "./output/example1",
                ExtrasDirectory = "./dictionaries/html_tags.dict",
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
