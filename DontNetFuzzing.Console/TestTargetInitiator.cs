using DotNetFuzzing.Common;
using DotNetFuzzing.Common.Implementation;
using DotNetFuzzing.Utilities;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace DontNetFuzzing.Console
{
    class TestTargetInitiator : ITargetInitiator
    {
        Random _random = new Random();
        Dictionary<UInt32, IRunResult> _results = new Dictionary<uint, IRunResult>();
        public Task<IRunResult> RunTarget(IFuzzerSettings settings, string testCaseFile, byte[] traceBits)
        {
            byte[] testCase;
            IRunResult runResult = new RunResult();
            using (var stream = File.Open(testCaseFile, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                testCase = new byte[stream.Length];
                stream.Read(testCase, 0, testCase.Length);
            }
            string textCaseText = Encoding.ASCII.GetString(testCase);
            UInt32 checksum = Hasher.Hash32(testCase);
            bool cacheResult = true;
            if (_results.TryGetValue(checksum, out runResult))
            {
                if (runResult.Outcome == RunOutcomes.FAULT_TMOUT)
                {
                    if ( _random.Next(10) == 0 )
                    {
                        return Task.FromResult<IRunResult>(runResult);
                    }
                    cacheResult = false;
                }
                else
                {
                    return Task.FromResult<IRunResult>(runResult);
                }
            }
            int failcase = _random.Next(10);
            switch (failcase)
            {
                case 0:
                    runResult = new RunResult(RunOutcomes.FAULT_CRASH);
                    break;
                case 1:
                    runResult = new RunResult(RunOutcomes.FAULT_TMOUT);
                    break;
                default:
                    runResult = new RunResult(RunOutcomes.FAULT_NONE);
                    break;
            }
            if ( cacheResult )
            {
                _results[checksum] = runResult;
            }
            return Task.FromResult<IRunResult>(runResult);
        }
    }
}
