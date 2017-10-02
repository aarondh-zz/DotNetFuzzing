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
    public class TestTargetInitiator : ITargetInitiator
    {
        Random _random = new Random();
        private class CachedRunResult : IRunResult
        {
            public RunOutcomes Outcome { get; }

            public int Reason { get; }

            public Exception Exception { get; }
            public int TraceBitSet{ get; }
            public CachedRunResult(RunOutcomes outcome = RunOutcomes.FAULT_NONE, int reason = 0, Exception exception = null, int traceBitSet = -1)
            {
                Outcome = outcome;
                Reason = reason;
                Exception = exception;
                TraceBitSet = traceBitSet;
            }
        }
        Dictionary<UInt32, CachedRunResult> _results = new Dictionary<uint, CachedRunResult>();
        private CachedRunResult GeneratedNewRunResult(int traceBitsLength )
        {
            int failcase = _random.Next(10);
            switch (failcase)
            {
                case 0:
                    return new CachedRunResult(RunOutcomes.FAULT_CRASH);
                case 1:
                    return new CachedRunResult(RunOutcomes.FAULT_TMOUT);
                default:
                    int traceBit = _random.Next(1000);
                    if (traceBit >= traceBitsLength)
                    {
                        traceBit = -1;
                    }
                    return new CachedRunResult(RunOutcomes.FAULT_NONE, traceBitSet: traceBit);
            }
        }
        public Task<IRunResult> RunTarget(IFuzzerSettings settings, string testCaseFile, byte[] traceBits)
        {
            byte[] testCase;
            CachedRunResult runResult = new CachedRunResult();
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
                    runResult = GeneratedNewRunResult(traceBits.Length);
                }
            }
            else
            {
                runResult = GeneratedNewRunResult(traceBits.Length);
            }
            if ( cacheResult )
            {
                _results[checksum] = runResult;
            }
            if ( runResult.TraceBitSet >= 0 )
            {
                traceBits[runResult.TraceBitSet] = 1;
            }
            return Task.FromResult<IRunResult>(runResult);
        }
    }
}
