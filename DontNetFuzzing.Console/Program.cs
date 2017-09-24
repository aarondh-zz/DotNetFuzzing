using DotNetFuzzing;
using DotNetFuzzing.Common;
using DotNetFuzzing.Common.Implementation;
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
                LogLevel = LogLevel.Verbose,
                InputDirectory = "../../examples/example1",
                OutputDirectory = "../../output/example1",
                DumbMode = true,
                Banner = "Example #1"
            };

            var fuzzer = new Fuzzer();
            fuzzer.Fuzz(settings);
        }
    }
}
