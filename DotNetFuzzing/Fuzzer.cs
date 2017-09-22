using DotNetFuzzing.Common;
using DotNetFuzzing.Internal.Models;
using DotNetFuzzing.Utilities;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static DotNetFuzzing.Internal.Models.Queue;

namespace DotNetFuzzing
{
    public class Fuzzer
    {
        private long _seekTo;
        private Queue _queue;
        /// <summary>
        /// Top entries for bitmap bytes
        /// </summary>
        private Queue.QueueEntry[] top_rated = new QueueEntry[Constants.MAP_SIZE];
        private int _queueCycle;
        private int stage_cur, stage_max;      /* Stage progression                */
        private int splicing_with = -1;        /* Splicing with which test case?   */

        private uint master_id, master_max;     /* Master instance job splitting    */

        private uint syncing_case;              /* Syncing with case #...           */

        private long stage_cur_byte;            /* Byte offset of current stage op  */
        private int stage_cur_val;            
        private int _currentSkippedPaths;
        private ILogger _logger;
        private IFuzzerSettings _settings;
        private FuzzerStatistics _stats;
        private int _lastPathTime;
        private int _queuedAtStart;
        private Random _random;
        private int total_cal_us;
        private int total_cal_cycles;
        private int total_bitmap_size;
        private int total_bitmap_entries;
        private byte[] trace_bits;
        /// <summary>
        /// Patterns found per fuzz stage
        /// </summary>
        private Int64[] stage_finds = new Int64[(int)FuzzingStages.TotalStages];
        /// <summary>
        /// Execs per fuzz stage 
        /// </summary>
        private Int64[] stage_cycles = new Int64[(int)FuzzingStages.TotalStages];
        private string stage_name;

        public string stage_short { get; private set; }

        public List<ExtraData> _extras = new List<ExtraData>();
        public List<ExtraData> _autoExtras = new List<ExtraData>();

        public int orig_hit_cnt;

        private int _bytes_trim_out;
        private bool score_changed;
        private IStream _outputStream;
        private uint _executionTimeout;
        private bool bitmap_changed;
        /// <summary>
        /// Paths with new coverage bytes
        /// </summary>
        private int queued_with_cov;
        private byte[] virgin_bits;
        private byte[] virgin_tmout;
        private bool[] var_bytes;
        public byte[] virgin_crash { get; private set; }

        public enum StopMode
        {
            NotStopping,
            Programatically,
            ByUser
        }
        enum FuzzingStages : int {
            STAGE_FLIP1 = 0,
            STAGE_FLIP2 = 1,
            STAGE_FLIP4 = 2,
            STAGE_FLIP8 = 3,
            STAGE_FLIP16 = 4,
            STAGE_FLIP32 = 5,
            STAGE_ARITH8 = 6,
            STAGE_ARITH16 = 7,
            STAGE_ARITH32 = 8,
            STAGE_INTEREST8 = 9,
            STAGE_INTEREST16 = 10,
            STAGE_INTEREST32 = 11,
            STAGE_EXTRAS_UO = 12,
            STAGE_EXTRAS_UI = 13,
            STAGE_EXTRAS_AO = 14,
            STAGE_HAVOC = 15,
            STAGE_SPLICE = 16,
            TotalStages = 32
        };
        PostHandler _postHandler = null;

        /* Stage value types */

        enum StageValueTypes {
            /* 00 */
            STAGE_VAL_NONE,
            /* 01 */
            STAGE_VAL_LE,
            /* 02 */
            STAGE_VAL_BE
        };

        public StopMode StopSoon { get; set; }
        public int _bytes_trim_in { get; private set; }

        public Fuzzer()
        {
            _random = new Random();
            var_bytes = new bool[Constants.MAP_SIZE];
        }
        public void Fuzz(IFuzzerSettings settings)
        {
            StopSoon = StopMode.NotStopping;

            _settings = settings;

            _logger = settings.Logger;
            if (_logger == null)
            {
                _logger = new Utilities.TraceLogger();
            }

            SetupSignalHandlers();

            CheckAsanOptions();

            if (settings.SyncId != null)
            {
                FixUpSync();
            }

            if (string.Equals(settings.InputDirectory, settings.OutputDirectory, StringComparison.CurrentCultureIgnoreCase))
            {
                var exception = new InvalidOperationException("Input and output directories can't be the same");
                _logger.Fatal(exception, "Input and output directories can't be the same");
                throw exception;
            }

            if (settings.DumbMode)
            {

                if (settings.CrashMode)
                {
                    throw new InvalidOperationException("-C and -n are mutually exclusive");
                }
                if (settings.QueueMode)
                {
                    throw new InvalidOperationException("-Q and -n are mutually exclusive");
                }
                if (settings.DumbForkServer != null && settings.NoForkServer)
                {
                    throw new InvalidOperationException("DumbMode with DumbForkServer and NoForkServer are mutually exclusive");
                }
            }

            GetCoreCount();

            CheckCrashHandling();
            CheckCpuGovernor();

            SetupPost();
            SetupSharedMemoryAndVirginBits();
            InitCountClass16();

            SetupDirsFds();

            _queue = new Queue(settings);

            ReadTestCases();

            _lastPathTime = 0;
            _queuedAtStart = _queue.Count;

            LoadAuto();

            PivotInputs();

            if (settings.ExtrasDirectory != null)
            {
                LoadExtras(settings.ExtrasDirectory);
            }

            if (settings.Timeout != TimeSpan.Zero)
            {
                FindTimeout();
            }

            SetupOutput();

            CheckBinary(settings.QemuBinaryFile);

            var startTime = DateTime.Now;

            bitmap_changed = true; //set up to write the bitmap first time through

            object useArugments;
            if (settings.QueueMode)
                useArugments = GetQueueArguments(settings);
            else
                useArugments = GetArguments(settings);


            PerformDryRun(useArugments);

            _queue.Cull(_settings.DumbMode, score_changed,top_rated,Constants.MAP_SIZE);

            ShowInitStats();

            var seekTo = FindStartPosition();

            WriteStatsFile(0, 0, 0);

            SaveAuto();

            QueueEntry queueCurrent = null;
            int currentEntry = 0;
            int queueCycle = 0;
            int cyclesWithoutFinds = 0;
            int prev_queued = 0;
            int _queueCount = _queue.Count;
            bool use_splicing = settings.SkipDeterministic;
            int sync_interval_cnt = 0;

            while (true)
            {
                bool skippedFuzz = false;

                _queue.Cull(_settings.DumbMode, score_changed, top_rated, Constants.MAP_SIZE);

                if (queueCurrent == null)
                {
                    queueCycle++;
                    currentEntry = 0;
                    _currentSkippedPaths = 0;
                    queueCurrent = _queue.First;
                }
                while (seekTo != 0)
                {
                    currentEntry++;
                    seekTo--;
                    queueCurrent = queueCurrent.Next;
                }

                ShowStats();
                if (settings.LogLevel == LogLevel.Verbose)
                {
                    settings.Logger.Verbose($"Entering queue cycle {_queueCycle}.");
                }

                /* If we had a full queue cycle with no new finds, try
                   recombination strategies next. */

                if (_queue.Count == prev_queued)
                {

                    if (use_splicing) cyclesWithoutFinds++; else use_splicing = true;

                }
                else cyclesWithoutFinds = 0;

                prev_queued = _queue.Count;

                if (settings.SyncId != null && queueCycle == 1 && settings.ImportFirst)
                {
                    SyncFuzzers(useArugments);
                }


                skippedFuzz = FuzzOne(useArugments);

                if (StopSoon == StopMode.NotStopping && settings.SyncId != null && !skippedFuzz)
                {

                    if ((sync_interval_cnt++ % settings.SyncInterval) == 0)
                    {
                        SyncFuzzers(useArugments);
                    }

                }

                if (StopSoon == StopMode.NotStopping && settings.BenchJustOne)
                {
                    StopSoon = StopMode.ByUser;
                }

                if (StopSoon != StopMode.NotStopping) break;

                queueCurrent = queueCurrent.Next;
                currentEntry++;
            }

        }
        /// <summary>
        /// Setup shared memory and virgin_bits.  Called at startup
        /// </summary>
        private void SetupSharedMemoryAndVirginBits()
        {

            virgin_bits = new byte[Constants.MAP_SIZE];

            if (_settings.FuzzBitmap == null)
            {
                virgin_bits = Enumerable.Repeat<byte>(0xff, Constants.MAP_SIZE).ToArray();
            }
            else
            {
                using (var stream = _settings.FileSystem.Open(_settings.FuzzBitmap, OpenOptions.ReadOnly))
                {
                    stream.Read(virgin_bits, 0, Constants.MAP_SIZE);
                    stream.Close();
                }
            }
            virgin_tmout = Enumerable.Repeat<byte>(0xff, Constants.MAP_SIZE).ToArray();
            virgin_crash = Enumerable.Repeat<byte>(0xff, Constants.MAP_SIZE).ToArray();
#if never
        shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);

                if (shm_id < 0) PFATAL("shmget() failed");

                atexit(remove_shm);

                shm_str = alloc_printf("%d", shm_id);

                /* If somebody is asking us to fuzz instrumented binaries in dumb mode,
                   we don't want them to detect instrumentation, since we won't be sending
                   fork server commands. This should be replaced with better auto-detection
                   later on, perhaps? */

                if (!dumb_mode) setenv(SHM_ENV_VAR, shm_str, 1);

                trace_bits = shmat(shm_id, NULL, 0);

                if (!trace_bits) PFATAL("shmat() failed");

#endif
        }

        private void SetupOutput()
        {
            var outputFileName = $"{_settings.OutputDirectory}/.cur_input";

            _settings.FileSystem.Delete(outputFileName); /* Ignore errors */

            _outputStream = _settings.FileSystem.Open(outputFileName, OpenOptions.Create | OpenOptions.Exclusive | OpenOptions.ReadWrite);
        }
        /// <summary>
        ///  Write modified data to file for testing. If out_file is set, the old file
        ///  is unlinked and a new one is created.Otherwise, out_fd is rewound and
        ///  truncated.
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name=""></param>
        private void WriteToTestCase(byte[] buffer, int length)
        {

            if (_settings.TargetFile != null)
            {
                var fileSystem = _settings.FileSystem;
                fileSystem.Delete(_settings.TargetFile); //ignore errors
                using (var stream = fileSystem.Open(_settings.TargetFile, OpenOptions.Create | OpenOptions.Exclusive | OpenOptions.WriteOnly))
                {
                    stream.Write(buffer, 0, length);
                    stream.Flush();
                    stream.Close();
                }
            }
            else
            {
                _outputStream.Seek(0L);
                _outputStream.Write(buffer, 0, length);
                _outputStream.Flush();
                _outputStream.SetLength(length);
                _outputStream.Seek(0L);
            }
        }
        /// <summary>
        /// Same as WriteToTestCase , but with an adjustable gap. Used for trimming.
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="length"></param>
        /// <param name="skip_at"></param>
        /// <param name="skip_len"></param>
        private void WriteToTestCaseWithGap(byte[] buffer, int length, int skip_at, int skip_len)
        {

            int tail_len = length - skip_at - skip_len;
            if (_settings.TargetFile != null)
            {
                var fileSystem = _settings.FileSystem;
                fileSystem.Delete(_settings.TargetFile); //ignore errors
                using (var stream = fileSystem.Open(_settings.TargetFile, OpenOptions.Create | OpenOptions.Exclusive | OpenOptions.WriteOnly))
                {
                    if (skip_at > 0) stream.Write(buffer, 0, skip_at);

                    if (tail_len > 0) stream.Write(buffer, skip_at + skip_len, tail_len);

                    stream.Flush();

                    stream.Close();
                }
            }
            else
            {
                _outputStream.Seek(0L);

                _outputStream.Write(buffer, 0, length);

                if (skip_at > 0) _outputStream.Write(buffer, 0, skip_at);

                if (tail_len > 0) _outputStream.Write(buffer, skip_at + skip_len, tail_len);

                _outputStream.Flush();

                _outputStream.SetLength(length - skip_len);

                _outputStream.Seek(0L);
            }
        }
        private void SyncFuzzers(object useArugments)
        {
            throw new NotImplementedException();
        }
        private int Randomize(int limit)
        {
            return _random.Next(limit);
        }

        public enum FuzzOutcomes
        {
            FAULT_TMOUT,
            FAULT_ERROR,
            Success,
            FAULT_NOINST,
            FAULT_NOBITS,
            FAULT_CRASH,
            FAULT_STOPPING
        }
        [Flags]
        public enum NewBitTypes
        {
            NoNewBits = 0x00,
            HitCount = 0x01,
            NewTuple = 0x02
        }
        /// <summary>
        /// Check if the current execution path brings anything new to the table.
        /// Update virgin bits to reflect the finds.Returns NewBitTypes.HitCount if the only change is
        /// the hit-count for a particular tuple; NewBitTypes.NewTuple if there are new tuples seen.
        /// Updates the map, so subsequent calls will always return 0.
        /// 
        /// This function is called after every exec() on a fairly large buffer, so
        /// it needs to be fast. We do this in 32-bit and 64-bit flavors.
        /// </summary>
        /// <param name="virgin_map"></param>
        /// <param name="trace_bits"></param>
        /// <returns></returns>
        private NewBitTypes has_new_bits(byte[] virgin_map, byte[] trace_bits)
        {
            int i = trace_bits.Length;

            NewBitTypes ret = 0;

            while (i-- > 0)
            {
                byte cur = trace_bits[i];
                byte vir = virgin_map[i];

                if (cur != 0 && (cur & vir) != 0)
                {
                    if (ret != NewBitTypes.NewTuple)
                    {
                        if (cur != 0 && vir == 0xff)
                        {
                            return NewBitTypes.NewTuple;
                        }
                        else
                        {
                            ret = NewBitTypes.HitCount;
                        }
                    }
                    virgin_map[i] &= (byte)~cur;
                }
            }
            return ret;
        }
        private int CountBytes(byte[] map)
        {
            int i = map.Length;
            int count = 0;

            while (i-- > 0)
            {
                if (map[i] != 0)
                {
                    count++;
                }
            }

            return count;
        }
        private int CountBytes(bool[] map)
        {
            int i = map.Length;
            int count = 0;

            while (i-- > 0)
            {
                if (map[i])
                {
                    count++;
                }
            }

            return count;
        }
        private int CalculateScore(QueueEntry q)
        {

            int avg_exec_us = total_cal_us / total_cal_cycles;
            int avg_bitmap_size = total_bitmap_size / total_bitmap_entries;
            double perf_score = 100;

            /* Adjust score based on execution speed of this path, compared to the
               global average. Multiplier ranges from 0.1x to 3x. Fast inputs are
               less expensive to fuzz, so we're giving them more air time. */

            if (q.ExecutionTimeUs * 0.1 > avg_exec_us) perf_score = 10;
            else if (q.ExecutionTimeUs * 0.25 > avg_exec_us) perf_score = 25;
            else if (q.ExecutionTimeUs * 0.5 > avg_exec_us) perf_score = 50;
            else if (q.ExecutionTimeUs * 0.75 > avg_exec_us) perf_score = 75;
            else if (q.ExecutionTimeUs * 4 < avg_exec_us) perf_score = 300;
            else if (q.ExecutionTimeUs * 3 < avg_exec_us) perf_score = 200;
            else if (q.ExecutionTimeUs * 2 < avg_exec_us) perf_score = 150;

            /* Adjust score based on bitmap size. The working theory is that better
               coverage translates to better targets. Multiplier from 0.25x to 3x. */

            if (q.BitmapSize * 0.3 > avg_bitmap_size) perf_score *= 3;
            else if (q.BitmapSize * 0.5 > avg_bitmap_size) perf_score *= 2;
            else if (q.BitmapSize * 0.75 > avg_bitmap_size) perf_score *= 1.5;
            else if (q.BitmapSize * 3 < avg_bitmap_size) perf_score *= 0.25;
            else if (q.BitmapSize * 2 < avg_bitmap_size) perf_score *= 0.5;
            else if (q.BitmapSize * 1.5 < avg_bitmap_size) perf_score *= 0.75;

            /* Adjust score based on handicap. Handicap is proportional to how late
               in the game we learned about this path. Latecomers are allowed to run
               for a bit longer until they catch up with the rest. */

            if (q.Handicap >= 4)
            {

                perf_score *= 4;
                q.Handicap -= 4;

            }
            else if (q.Handicap > 0)
            {

                perf_score *= 2;
                q.Handicap--;

            }

            /* Final adjustment based on input depth, under the assumption that fuzzing
               deeper test cases is more likely to reveal stuff that can't be
               discovered with traditional fuzzers. */

            switch (q.Depth)
            {
                case 0:
                case 1:
                case 2:
                case 3:
                    break;
                case 4:
                case 5:
                case 6:
                case 7:
                    perf_score *= 2;
                    break;
                case 8:
                case 9:
                case 10:
                case 11:
                case 12:
                case 13:
                    perf_score *= 3;
                    break;
                case 14:
                case 15:
                case 16:
                case 17:
                case 18:
                case 19:
                case 20:
                case 21:
                case 22:
                case 23:
                case 24:
                case 25:
                    perf_score *= 4;
                    break;
                default:
                    perf_score *= 5;
                    break;
            }

            /* Make sure that we don't go over limit. */

            if (perf_score > Constants.HAVOC_MAX_MULT * 100) perf_score = Constants.HAVOC_MAX_MULT * 100;

            return (int)perf_score;
        }
        private byte[] _firstTrace = new byte[Constants.MAP_SIZE];
        private FuzzOutcomes CalibrateCase(QueueEntry q, byte[] use_mem, int queue_cylcle, int x)
        {
            FuzzOutcomes fault = FuzzOutcomes.Success;
            NewBitTypes new_bits = NewBitTypes.NoNewBits;
            bool var_detected = false;
            bool first_run = (q.ExecutionTraceChecksum == 0);

            DateTime start_us;
            DateTime stop_us;

            int old_sc = stage_cur;
            int old_sm = stage_max;
            uint userTimeout = _executionTimeout;
            string old_sn = stage_name;

            /* Be a bit more generous about timeouts when resuming sessions, or when
               trying to calibrate already-added finds. This helps avoid trouble due
               to intermittent latency. */

            if (!from_queue || resuming_fuzz)
            {
                userTimeout = Math.Max(_executionTimeout + Constants.CAL_TMOUT_ADD,
                                _executionTimeout * Constants.CAL_TMOUT_PERC / 100);
            }

            q.CalibrationFailed++;

            stage_name = "calibration";
            stage_max = fast_cal ? 3 : Constants.CAL_CYCLES;

            /* Make sure the forkserver is up before we do anything, and let's not
               count its spin-up time toward binary calibration. */

            if (!_settings.DumbMode && !_settings.NoForkServer && _settings.MasterSyncId == null)
                init_forkserver(argv);

            if (q.ExecutionTraceChecksum > 0)
            {
                Array.Copy(_firstTrace, trace_bits, Constants.MAP_SIZE);
            }

            start_us = DateTime.Now;

            for (var stage_cur = 0; stage_cur < stage_max; stage_cur++)
            {

                uint cksum;

                if (!first_run && (stage_cur % _settings.StatsUpdateFrequency) == 0)
                {
                    ShowStats();
                }

                WriteToTestCase(use_mem, q.Length);

                fault = RunTarget(userTimeout);

                /* stop_soon is set by the handler for Ctrl+C. When it's pressed,
                   we want to bail out quickly. */

                if (StopSoon != StopMode.NotStopping || fault != crash_mode)
                {
                    goto abort_calibration;
                }

                if (!_settings.DumbMode && stage_cur == 0 && CountBytes(trace_bits) > 0)
                {
                    fault = FuzzOutcomes.FAULT_NOINST;
                    goto abort_calibration;
                }

                cksum = Hasher.Hash32(trace_bits);

                if (q.ExecutionTraceChecksum != cksum)
                {

                    var hnb = has_new_bits(virgin_bits, trace_bits);
                    if (hnb > new_bits)
                    {
                        new_bits = hnb;
                        bitmap_changed = true;
                    }

                    if (q.ExecutionTraceChecksum != 0)
                    {

                        uint i;

                        for (i = 0; i < Constants.MAP_SIZE; i++)
                        {

                            if (!var_bytes[i] && _firstTrace[i] != trace_bits[i])
                            {

                                var_bytes[i] = true;
                                stage_max = Constants.CAL_CYCLES_LONG;

                            }

                        }

                        var_detected = true;

                    }
                    else
                    {

                        q.ExecutionTraceChecksum = cksum;
                        Array.Copy(_firstTrace, trace_bits, Constants.MAP_SIZE);

                    }

                }
            }

            stop_us = DateTime.Now;

            total_cal_us += (int)(stop_us - start_us).TotalMilliseconds;
            total_cal_cycles += stage_max;

            /* OK, let's collect some stats about the performance of this test case.
               This is used for fuzzing air time calculations in calculate_score(). */

            q.ExecutionTimeUs = (int)(stop_us - start_us).TotalMilliseconds / stage_max;
            q.BitmapSize = CountBytes(trace_bits);
            q.Handicap = handicap;
            q.CalibrationFailed = 0;

            total_bitmap_size += q.BitmapSize;
            total_bitmap_entries++;

            UpdateBitmapScore(q, trace_bits, top_rated);

            /* If this case didn't result in new output from the instrumentation, tell
               parent. This is a non-critical problem, but something to warn the user
               about. */

            if (!_settings.DumbMode && first_run && fault == FuzzOutcomes.Success && new_bits == NewBitTypes.NoNewBits)
            {
                fault = FuzzOutcomes.FAULT_NOBITS;
            }

            abort_calibration:

            if (new_bits == NewBitTypes.NewTuple && !q.HasNewCoverage) {
                q.HasNewCoverage = true;
                queued_with_cov++;
            }

            /* Mark variable paths. */

            if (var_detected) {

                var_byte_count = CountBytes(var_bytes);

                if (!q.VariableBehavior) {
                    mark_as_variable(q);
                    queued_variable++;
                }

            }

            stage_name = old_sn;
            stage_cur = old_sc;
            stage_max = old_sm;

            if (!first_run)
            {
                ShowStats();
            }

            return fault;
        }

        private int unique_crashes;
        private int new_hit_cnt;
        private bool skip_requested;
        private int cur_skipped_paths;
        private int subseq_tmouts;
        private int var_byte_count;
        private int queued_variable;
        private bool auto_changed;
        private int _queued_discovered;
        private int blocks_eff_select;
        private int blocks_eff_total;

        /// <summary>
        ///         Describe integer. Uses 12 cyclic static buffers for return values.
        ///         The value returned should be five characters or less for all the integers 
        ///         we reasonably expect to see.
        /// </summary>
        /// <param name="val"></param>
        /// <returns>string describing the integer</returns>
        private static string Describe(uint val)
        {
            return val.ToString();
        }
        /// <summary>
        ///  Compact trace bytes into a smaller bitmap. We effectively just drop the
        ///  count information here.This is called only sporadically, for some
        ///  new paths.
        /// </summary>
        /// <param name="dst"></param>
        /// <param name="src"></param>
        private static void MinimizeBits(byte[] dst, byte[] src)
        {

            int i = 0;

            while (i < Constants.MAP_SIZE)
            {

                if (src[i] != 0)
                {
                    dst[i >> 3] |= (byte)(1 << (i & 7));
                }
                i++;

            }

        }
        /// <summary>
        /// When we bump into a new path, we call this to see if the path appears
        /// more "favorable" than any of the existing ones. The purpose of the
        /// "favorables" is to have a minimal set of paths that trigger all the bits
        /// seen in the bitmap so far, and focus on fuzzing them at the expense of
        /// the rest.
        /// 
        /// The first step of the process is to maintain a list of top_rated[] entries
        /// for every byte in the bitmap.We win that slot if there is no previous
        /// contender, or if the contender has a more favorable speed x size factor.
        /// </summary>
        /// <param name="q"></param>
        /// <param name="trace_bits"></param>
        /// <param name="topRated"></param>
        /// <returns>true if the score changed</returns>
        public static bool UpdateBitmapScore(QueueEntry q, byte[] trace_bits, QueueEntry[] topRated)
        {

            int i;
            long favorFactor = q.ExecutionTimeUs * q.Length;
            bool scoreChanged = false;

            /* For every byte set in trace_bits[], see if there is a previous winner,
               and how it compares to us. */

            for (i = 0; i < Constants.MAP_SIZE; i++)

                if (trace_bits[i] != 0)
                {

                    if (topRated[i] != null)
                    {

                        /* Faster-executing or smaller test cases are favored. */

                        if (favorFactor > topRated[i].ExecutionTimeUs * topRated[i].Length) continue;

                        /* Looks like we're going to win. Decrease ref count for the
                           previous winner, discard its trace_bits[] if necessary. */

                        if (--topRated[i].TraceBytesReferenceCount == 0)
                        {
                            topRated[i].TraceMini = null;
                        }

                    }

                    /* Insert ourselves as the new winner. */

                    topRated[i] = q;
                    q.TraceBytesReferenceCount++;

                    if (q.TraceMini == null)
                    {
                        q.TraceMini = new byte[Constants.MAP_SIZE >> 3];
                        MinimizeBits(q.TraceMini, trace_bits);
                    }

                    scoreChanged = true;

                }
            return scoreChanged;
        }

        /// <summary>
        /// Find first power of two greater or equal to val (assuming val under 2^31)
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        private int NextPowerOf2(int value)
        {
            int powerOf2 = 1;
            while (value > powerOf2)
            {
                powerOf2 <<= 1;
            }
            return powerOf2;
        }
        /// <summary>
        ///     Trim all new test cases to save cycles when doing deterministic checks. The
        ///     trimmer uses power-of-two increments somewhere between 1/16 and 1/1024 of
        ///     file size, to keep the stage short and sweet.
        /// </summary>
        /// <param name="q"></param>
        /// <param name="in_buf"></param>
        /// <returns></returns>
        private FuzzOutcomes TrimCase(QueueEntry q, byte[] in_buf)
        {
            string tmp = null;
            byte[] clean_trace = new byte[Constants.MAP_SIZE];

            bool needs_write = false;
            FuzzOutcomes fault = FuzzOutcomes.Success;
            int trim_exec = 0;
            int remove_len;
            int len_p2;

            /* Although the trimmer will be less useful when variable behavior is
               detected, it will still work to some extent, so we don't check for
               this. */

            if (q.Length < 5)
            {
                return FuzzOutcomes.Success;
            }

            stage_name = tmp;
            _bytes_trim_in += q.Length;

            /* Select initial chunk len, starting with large steps. */

            len_p2 = NextPowerOf2(q.Length);

            remove_len = Math.Max(len_p2 / Constants.TRIM_START_STEPS, Constants.TRIM_MIN_BYTES);

            /* Continue until the number of steps gets too high or the stepover
               gets too small. */

            while (remove_len >= Math.Max(len_p2 / Constants.TRIM_END_STEPS, Constants.TRIM_MIN_BYTES))
            {

                int remove_pos = remove_len;

                tmp = "trim {Describe(remove_len)}/{Describe(remove_len)}";

                stage_cur = 0;
                stage_max = q.Length / remove_len;

                while (remove_pos < q.Length)
                {

                    int trim_avail = Math.Min(remove_len, q.Length - remove_pos);
                    uint cksum;

                    WriteToTestCaseWithGap(in_buf, q.Length, remove_pos, trim_avail);

                    fault = run_target(_executionTimeout);
                    trim_execs++;

                    if (StopSoon != StopMode.NotStopping || fault == FuzzOutcomes.FAULT_ERROR)
                    {
                        goto abort_trimming;
                    }

                    /* Note that we don't keep track of crashes or hangs here; maybe TODO? */

                    cksum = Hasher.Hash32(trace_bits);

                    /* If the deletion had no impact on the trace, make it permanent. This
                       isn't perfect for variable-path inputs, but we're just making a
                       best-effort pass, so it's not a big deal if we end up with false
                       negatives every now and then. */

                    if (cksum == q.ExecutionTraceChecksum)
                    {

                        int move_tail = q.Length - remove_pos - trim_avail;

                        q.Length -= trim_avail;
                        len_p2 = NextPowerOf2(q.Length);

                        Array.Copy(in_buf, remove_pos, in_buf, remove_pos + trim_avail, move_tail);
                        /* Let's save a clean trace, which will be needed by
                           update_bitmap_score once we're done with the trimming stuff. */

                        if (!needs_write)
                        {

                            needs_write = true;
                            Array.Copy(clean_trace, trace_bits, Constants.MAP_SIZE);

                        }

                    }
                    else remove_pos += remove_len;

                    /* Since this can be slow, update the screen every now and then. */

                    if ((trim_exec++ % _settings.StatsUpdateFrequency) == 0)
                    {
                        ShowStats();
                    }
                    stage_cur++;

                }

                remove_len >>= 1;

            }

            /* If we have made changes to in_buf, we also need to update the on-disk
               version of the test case. */

            if (needs_write)
            {

                _settings.FileSystem.Delete(q.FileName); /* ignore errors */

                using (var stream = _settings.FileSystem.Open(q.FileName, OpenOptions.ReadOnly | OpenOptions.Create | OpenOptions.Exclusive))
                {
                    stream.Write(in_buf, 0, q.Length);
                    stream.Flush();
                    stream.Close();
                }

                Array.Copy(trace_bits, clean_trace, Constants.MAP_SIZE);
                UpdateBitmapScore(q, trace_bits, top_rated);

            }

            abort_trimming:

            _bytes_trim_out += q.Length;
            return fault;
        }
        private static void FlipBit(byte[] map, uint bitToFlip)
        {
            byte bitInByte = (byte)(bitToFlip & 7);
            map[bitToFlip >> 3] ^= (byte)(128 >> bitInByte);
        }
        private static void FlipBit(byte[] map, int bitToFlip)
        {
            byte bitInByte = (byte)(bitToFlip & 7);
            map[bitToFlip >> 3] ^= (byte)(128 >> bitInByte);
        }
        /// <summary>
        /// Write a modified test case, run program, process results. Handle
        /// error conditions, returning true if it's time to bail out. This is
        /// a helper function for fuzz_one(). 
        /// </summary>
        /// <param name="argv"></param>
        /// <param name="out_buf"></param>
        /// <param name="len"></param>
        /// <returns></returns>
        private bool CommonFuzzStuff(ByteStream out_buf, int length)
        {

            FuzzOutcomes fault;
            byte[] resultingBytes;
            if( _postHandler == null )
            {
                resultingBytes = out_buf.GetBytes();
            }
            else
            {

                resultingBytes = _postHandler(out_buf.GetBytes());
                if (resultingBytes == null || resultingBytes.Length == 0) return false;

            }

            WriteToTestCase(resultingBytes, length);

            fault = RunTarget(exec_tmout);

            if (StopSoon != StopMode.NotStopping) return true;

            if (fault == FuzzOutcomes.FAULT_TMOUT)
            {

                if (subseq_tmouts++ > Constants.TMOUT_LIMIT)
                {
                    cur_skipped_paths++;
                    return true;
                }

            }
            else subseq_tmouts = 0;

            /* Users can hit us with SIGUSR1 to request the current input
               to be abandoned. */

            if (skip_requested)
            {

                skip_requested = false;
                cur_skipped_paths++;
                return true;

            }

            /* This handles FAULT_ERROR for us: */
            
            _queued_discovered += save_if_interesting(resultingBytes, length, fault);

            if ((stage_cur % _settings.StatsUpdateFrequency) == 0 || stage_cur + 1 == stage_max)
                ShowStats();

            return false;

        }
        private static UInt16 SWAP16(UInt16 value)
        {
            return (UInt16)((value << 8) | (value >> 8));
        }
        private static UInt16 SWAP16(Int16 value)
        {
            return (UInt16)((value << 8) | (value >> 8));
        }
        private static UInt32 SWAP32(UInt32 value)
        {
            return (UInt32)((value << 24) | (value >> 24) |
              ((value << 8) & 0x00FF0000) |
              ((value >> 8) & 0x0000FF00));
        }
        private static UInt32 SWAP32(Int32 value)
        {
            return (UInt32)((value << 24) | (value >> 24) |
              ((value << 8) & 0x00FF0000) |
              ((value >> 8) & 0x0000FF00));
        }
        /// <summary>
        /// Maybe add automatic extra.
        /// </summary>
        /// <param name="mem"></param>
        /// <param name="len"></param>
        private void MaybeAddAutoExtra(byte[] mem, int len)
        {

            int i;

            /* Allow users to specify that they don't want auto dictionaries. */

            if (Constants.MAX_AUTO_EXTRAS == 0 || Constants.USE_AUTO_EXTRAS == 0) return;

            /* Skip runs of identical bytes. */

            for (i = 1; i < len; i++)
                if ((mem[0] ^ mem[i]) != 0) break;

            if (i == len) return;

            /* Reject builtin interesting values. */
            unsafe
            {
                fixed( byte* bytePointer = &mem[0])
                {
                    if (len == 2)
                    {
                        UInt16* pointer = (UInt16*)bytePointer;
                        i = Constants.INTERESTING_16.Length;

                        while (i-- > 0)
                            if (*pointer == Constants.INTERESTING_16[i] ||
                                *pointer == SWAP16((UInt16)Constants.INTERESTING_16[i])) return;

                    }

                    if (len == 4)
                    {
                        UInt32* pointer = (UInt32*)bytePointer;

                        i = Constants.INTERESTING_32.Length;

                        while (i-- > 0)
                        {
                            if (*pointer == Constants.INTERESTING_32[i] ||
                                *pointer == SWAP32((UInt32)Constants.INTERESTING_32[i])) return;
                        }

                    }


                }
            }
            /* Reject anything that matches existing extras. Do a case-insensitive
               match. We optimize by exploiting the fact that extras[] are sorted
               by size. */
            for (i = 0; i < _extras.Count; i++)
                if (_extras[i].Data.Length >= len) break;

            for (; i < _extras.Count && _extras[i].Length == len; i++)
            {
                if (Enumerable.SequenceEqual(_extras[i].Data, mem))
                {
                    return;
                }
            }

            /* Last but not least, check _autoExtras[] for matches. There are no
               guarantees of a particular sort order. */

            auto_changed = true;

            for (i = 0; i < _autoExtras.Count; i++)
            {
                if (Enumerable.SequenceEqual(_autoExtras[i].Data, mem))
                {
                    _autoExtras[i].HitCount++;
                    goto sort_a_extras;
                }
            }

            /* At this point, looks like we're dealing with a new entry. So, let's
               append it if we have room. Otherwise, let's randomly evict some other
               entry from the bottom half of the list. */

            if (_autoExtras.Count < Constants.MAX_AUTO_EXTRAS)
            {
                var newAExtra = new ExtraData()
                {
                    Data = (byte[])mem.Clone(),
                    Length = mem.Length
                };
                _autoExtras.Add(newAExtra);

            } else {

                i = Constants.MAX_AUTO_EXTRAS / 2 + Randomize((Constants.MAX_AUTO_EXTRAS + 1) / 2);
                _autoExtras[i].Data = (byte[])mem.Clone();
                _autoExtras[i].Length = len;
                _autoExtras[i].HitCount = 0;
            }

            sort_a_extras:

            /* First, sort all auto extras by use count, descending order. */
            _autoExtras.Sort((a, b) => {
                return a.HitCount - b.HitCount;
            });

            /* Then, sort the top USE_AUTO_EXTRAS entries by size. */
            _autoExtras.Sort(0, Math.Min(Constants.USE_AUTO_EXTRAS, _autoExtras.Count), ExtraDataLengthComparer.Instance);
        }
        private class ExtraDataLengthComparer : IComparer<ExtraData>
        {
            public static readonly IComparer<ExtraData> Instance = new ExtraDataLengthComparer();
            public int Compare(ExtraData x, ExtraData y) { return x.Length - y.Length; }
        }
        /// <summary>
        /// Helper to choose random block len for block operations in fuzz_one().
        /// Doesn't return zero, provided that max_len is > 0.
        /// </summary>
        /// <param name="limit"></param>
        /// <returns></returns>
        private int choose_block_len(int limit, int queueCycle)
        {

            int min_value, max_value;
            int rlim = Math.Min(queueCycle, 3);

            if (!_settings.RunOver10M) rlim = 1;

            switch (Randomize(rlim))
            {

                case 0:
                    min_value = 1;
                    max_value = Constants.HAVOC_BLK_SMALL;
                    break;

                case 1:
                    min_value = Constants.HAVOC_BLK_SMALL;
                    max_value = Constants.HAVOC_BLK_MEDIUM;
                    break;

                default:

                    if (Randomize(10) != 0)
                    {

                        min_value = Constants.HAVOC_BLK_MEDIUM;
                        max_value = Constants.HAVOC_BLK_LARGE;

                    }
                    else
                    {

                        min_value = Constants.HAVOC_BLK_LARGE;
                        max_value = Constants.HAVOC_BLK_XL;

                    }
                    break;

            }

            if (min_value >= limit) min_value = 1;

            return min_value + Randomize(Math.Min(max_value, limit) - min_value + 1);

        }
        /// <summary>
        /// Helper function to see if a particular change (xor_val = old ^ new) could
        /// be a product of deterministic bit flips with the lengths and stepovers
        /// attempted by afl-fuzz.This is used to avoid dupes in some of the
        /// deterministic fuzzing operations that follow bit flips.We also
        /// return true if xor_val is zero, which implies that the old and attempted new
        /// values are identical and the exec would be a waste of time.
        /// </summary>
        /// <param name="xor_val"></param>
        /// <returns></returns>
        private static bool could_be_bitflip(UInt32 xor_val)
        {

            UInt32 sh = 0;

            if (xor_val == 0) return true;

            /* Shift left until first bit set. */

            while ((xor_val & 1) == 0) { sh++; xor_val >>= 1; }

            /* 1-, 2-, and 4-bit patterns are OK anywhere. */

            if (xor_val == 1 || xor_val == 3 || xor_val == 15) return true;

            /* 8-, 16-, and 32-bit patterns are OK only if shift factor is
               divisible by 8, since that's the stepover for these ops. */

            if ((sh & 7)!=0) return false;

            if (xor_val == 0xff || xor_val == 0xffff || xor_val == 0xffffffff)
                return true;

            return false;

        }
        /// <summary>
        /// Helper function to see if a particular value is reachable through
        /// arithmetic operations.Used for similar purposes.
        /// </summary>
        /// <param name="old_val"></param>
        /// <param name="new_val"></param>
        /// <param name="blen"></param>
        /// <returns></returns>
        private static bool could_be_arith(UInt32 old_val, UInt32 new_val, byte blen)
        {

            UInt32 ov = 0, nv = 0, diffs = 0;

            if (old_val == new_val) return true;

            /* See if one-byte adjustments to any byte could produce this result. */

            for (int i = 0; i < blen; i++)
            {

                byte a = (byte)( old_val >> (8 * i)),
                   b = (byte)(new_val >> (8 * i));

                if (a != b) { diffs++; ov = a; nv = b; }

            }

            /* If only one byte differs and the values are within range, return 1. */

            if (diffs == 1)
            {

                if ((byte)(ov - nv) <= Constants.ARITH_MAX ||
                    (byte)(nv - ov) <= Constants.ARITH_MAX) return true;

            }

            if (blen == 1) return false;

            /* See if two-byte adjustments to any byte would produce this result. */

            diffs = 0;

            for (int i = 0; i < blen / 2; i++)
            {

                UInt16 a = (UInt16)(old_val >> (16 * i)),
                    b = (UInt16)(new_val >> (16 * i));

                if (a != b) { diffs++; ov = a; nv = b; }

            }

            /* If only one word differs and the values are within range, return 1. */

            if (diffs == 1)
            {

                if ((UInt16)(ov - nv) <= Constants.ARITH_MAX ||
                    (UInt16)(nv - ov) <= Constants.ARITH_MAX) return true;

                ov = SWAP16((UInt16)ov); nv = SWAP16((UInt16)nv);

                if ((UInt16)(ov - nv) <= Constants.ARITH_MAX ||
                    (UInt16)(nv - ov) <= Constants.ARITH_MAX) return true;

            }

            /* Finally, let's do the same thing for dwords. */

            if (blen == 4)
            {

                if ((UInt32)(old_val - new_val) <= Constants.ARITH_MAX ||
                    (UInt32)(new_val - old_val) <= Constants.ARITH_MAX) return true;

                new_val = SWAP32(new_val);
                old_val = SWAP32(old_val);

                if ((UInt32)(old_val - new_val) <= Constants.ARITH_MAX ||
                    (UInt32)(new_val - old_val) <= Constants.ARITH_MAX) return true;

            }

            return false;

        }


        /// <summary>
        /// Last but not least, a similar helper to see if insertion of an 
        /// interesting integer is redundant given the insertions done for
        /// shorter blen.The last param (check_le) is set if the caller
        /// already executed LE insertion for current blen and wants to see
        /// if BE variant passed in new_val is unique.
        /// /// </summary>
        /// <param name="old_val"></param>
        /// <param name="new_val"></param>
        /// <param name="blen"></param>
        /// <param name="check_le"></param>
        /// <returns></returns>

        public static bool could_be_interest(UInt32 old_val, UInt32 new_val, byte blen, bool check_le)
        {

            if (old_val == new_val) return true;

            /* See if one-byte insertions from interesting_8 over old_val could
               produce new_val. */

            for (int i = 0; i < blen; i++)
            {

                for (int j = 0; j < Constants.INTERESTING_8.Length; j++)
                {

                    UInt32 tval = (UInt32)((old_val & ~(0xff << (i * 8))) |
                               (Constants.INTERESTING_8[j] << (i * 8)));

                    if (new_val == tval) return true;

                }

            }

            /* Bail out unless we're also asked to examine two-byte LE insertions
               as a preparation for BE attempts. */

            if (blen == 2 && !check_le) return false;

            /* See if two-byte insertions over old_val could give us new_val. */

            for (int i = 0; i < blen - 1; i++)
            {

                for (int j = 0; j < Constants.INTERESTING_16.Length; j++)
                {

                    UInt32 tval = (UInt32)((old_val & ~(0xffff << (i * 8))) |
                               (Constants.INTERESTING_16[j] << (i * 8)));

                    if (new_val == tval) return true;

                    /* Continue here only if blen > 2. */

                    if (blen > 2)
                    {

                        tval = (UInt32)((old_val & ~(0xffff << (i * 8))) |
                               (SWAP16(Constants.INTERESTING_16[j]) << (i * 8)));

                        if (new_val == tval) return true;

                    }

                }

            }

            if (blen == 4 && check_le)
            {

                /* See if four-byte insertions could produce the same result
                   (LE only). */

                for (int j = 0; j < Constants.INTERESTING_32.Length; j++)
                    if (new_val == Constants.INTERESTING_32[j]) return true;

            }

            return false;

        }
        /// <summary>
        /// Take the current entry from the queue, fuzz it for a while. This function is a tad too long... 
        /// returns true if fuzzed successfully, false if skipped or bailed out. */
        /// </summary>
        /// <param name="useArugments"></param>
        /// <param name="currentQueue"></param>
        /// <param name="queueCycle"></param>
        /// <param name="queuedPaths"></param>
        /// <returns></returns>
        private bool FuzzOne(object useArugments, QueueEntry currentQueue, int queueCycle, int queuedPaths)
        {
            bool returnValue = true;
            bool doingDeterministic = false;
            byte[] a_collect = new byte[Constants.MAX_AUTO_EXTRA];
            int a_len = 0;
            FuzzOutcomes crash_mode = _settings.CrashMode ? FuzzOutcomes.FAULT_CRASH : FuzzOutcomes.Success;
            int havoc_queued, orig_hit_cnt, new_hit_cnt;
            if (_settings.IgnoreFinds)
            {
                /* In IGNORE_FINDS mode, skip any entries that weren't in the
                   initial data set. */

                if (currentQueue.Depth > 1)
                {
                    return false;
                }
            }
            else
            {

                if (_queue.PendingFavored > 0)
                {

                    /* If we have any favored, non-fuzzed new arrivals in the queue,
                       possibly skip to them at the expense of already-fuzzed or non-favored
                       cases. */

                    if ((currentQueue.WasFuzzed || !currentQueue.Favored) &&
                        Randomize(100) < Constants.SKIP_TO_NEW_PROB)
                    {
                        return false;
                    }

                }
                else if (!_settings.DumbMode && !currentQueue.Favored && queuedPaths > 10)
                {

                    /* Otherwise, still possibly skip non-favored cases, albeit less often.
                       The odds of skipping stuff are higher for already-fuzzed inputs and
                       lower for never-fuzzed entries. */

                    if (queueCycle > 1 && !currentQueue.WasFuzzed)
                    {

                        if (Randomize(100) < Constants.SKIP_NFAV_NEW_PROB) return true;

                    }
                    else
                    {

                        if (Randomize(100) < Constants.SKIP_NFAV_OLD_PROB) return true;

                    }

                }

            }
            if (_settings.LogLevel == LogLevel.Verbose)
            {
                _settings.Logger.Verbose("Fuzzing test case {currentQueue} ({queuedPaths} total, {uniqueCrashes} uniq crashes found)...",
                     currentQueue, queuedPaths, unique_crashes);
            }

            /* Map the test case into memory. */
            int length;
            byte[] orig_in;
            byte[] in_buf;
            using (var stream = _settings.FileSystem.Open(currentQueue.FileName, OpenOptions.ReadOnly))
            {
                length = currentQueue.Length;
                orig_in = in_buf = new byte[length];
                var bytesRead = stream.Read(orig_in, 0, length);
                if (bytesRead != length)
                {
                    _settings.Logger.Error("Unable to mmap '{fileName}'", currentQueue.FileName);
                }
            }
            /* We could mmap() out_buf as MAP_PRIVATE, but we end up clobbering every
               single byte anyway, so it wouldn't give us any performance or memory usage
               benefits. */

            var out_buf = new ByteStream(length);
            var subseq_tmouts = 0;
            var cur_depth = currentQueue.Depth;

            /*******************************************
             * CALIBRATION (only if failed earlier on) *
             *******************************************/

            if (currentQueue.CalibrationFailed > 0)
            {

                FuzzOutcomes res = FuzzOutcomes.FAULT_TMOUT;

                if (currentQueue.CalibrationFailed < Constants.CAL_CHANCES)
                {

                    res = CalibrateCase(currentQueue, in_buf, queueCycle - 1, 0);

                    if (res == FuzzOutcomes.FAULT_ERROR)
                    {
                        _settings.Logger.Fatal("Unable to execute target application");
                        throw new Exception("Unable to execute target application");
                    }

                }

                if (StopSoon != StopMode.NotStopping || res != crash_mode)
                {
                    _currentSkippedPaths++;
                    goto abandon_entry;
                }

            }

            /************
             * TRIMMING *
             ************/

            if (!_settings.DumbMode && !currentQueue.TrimDone)
            {

                FuzzOutcomes res = TrimCase(currentQueue, in_buf);

                if (res == FuzzOutcomes.FAULT_ERROR)
                {
                    _settings.Logger.Fatal("Unable to execute target application");
                    throw new Exception("Unable to execute target application");
                }

                if (StopSoon != StopMode.NotStopping)
                {
                    _currentSkippedPaths++;
                    goto abandon_entry;
                }

                /* Don't retry trimming, even if it failed. */

                currentQueue.TrimDone = true;

                if (length != currentQueue.Length)
                {
                    length = currentQueue.Length;
                }

            }
            out_buf.Seek(0L, SeekOrigin.Begin);
            out_buf.Read(in_buf, 0, length);

            /*********************
             * PERFORMANCE SCORE *
             *********************/
            int perf_score;
            int orig_perf = perf_score = CalculateScore(currentQueue);

            /* Skip right away if -d is given, if we have done deterministic fuzzing on
               this entry ourselves (WasFuzzed), or if it has gone through deterministic
               testing in earlier, resumed runs (passed_det). */

            if (_settings.SkipDeterministic || currentQueue.WasFuzzed || currentQueue.PassedDeterministic)
                goto havoc_stage;

            /* Skip deterministic fuzzing if exec path checksum puts this out of scope
               for this master instance. */

            if (master_max > 0  && (currentQueue.ExecutionTraceChecksum % master_max) != master_id - 1)
                goto havoc_stage;

            doingDeterministic = true;

            /*********************************************
             * SIMPLE BITFLIP (+dictionary construction) *
             *********************************************/



            /* Single walking bit. */

            stage_short = "flip1";
            stage_max = length << 3;
            stage_name = "bitflip 1/1";

            var stage_val_type = StageValueTypes.STAGE_VAL_NONE;
            int stage_cur_byte = -1;

            orig_hit_cnt = _queue.Count + unique_crashes;

            var prev_cksum = currentQueue.ExecutionTraceChecksum;

            for (int stage_cur = 0; stage_cur < stage_max; stage_cur++) {

                stage_cur_byte = (int)(stage_cur >> 3);

                out_buf.FlipBit(stage_cur);

                if (CommonFuzzStuff(out_buf, length)) goto abandon_entry;

                out_buf.FlipBit(stage_cur);

                /* While flipping the least significant bit in every byte, pull of an extra
                   trick to detect possible syntax tokens. In essence, the idea is that if
                   you have a binary blob like this:

                   xxxxxxxxIHDRxxxxxxxx

                   ...and changing the leading and trailing bytes causes variable or no
                   changes in program flow, but touching any character in the "IHDR" string
                   always produces the same, distinctive path, it's highly likely that
                   "IHDR" is an atomically-checked magic value of special significance to
                   the fuzzed format.

                   We do this here, rather than as a separate stage, because it's a nice
                   way to keep the operation approximately "free" (i.e., no extra execs).

                   Empirically, performing the check when flipping the least significant bit
                   is advantageous, compared to doing it at the time of more disruptive
                   changes, where the program flow may be affected in more violent ways.

                   The caveat is that we won't generate dictionaries in the -d mode or -S
                   mode - but that's probably a fair trade-off.

                   This won't work particularly well with paths that exhibit variable
                   behavior, but fails gracefully, so we'll carry out the checks anyway.

                  */

                if (!_settings.DumbMode && (stage_cur & 7) == 7) {

                    uint cksum = Hasher.Hash32(trace_bits);

                    if (stage_cur == stage_max - 1 && cksum == prev_cksum)
                    {
                        /* If at end of file and we are still collecting a string, grab the
                           final character and force output. */
                        out_buf.Seek(stage_cur >> 3, SeekOrigin.Begin);
                        if (a_len < Constants.MAX_AUTO_EXTRA) a_collect[a_len] = out_buf.ReadByte();
                        a_len++;

                        if (a_len >= Constants.MIN_AUTO_EXTRA && a_len <= Constants.MAX_AUTO_EXTRA)
                            MaybeAddAutoExtra(a_collect, a_len);

                    }
                    else if (cksum != prev_cksum)
                    {

                        /* Otherwise, if the checksum has changed, see if we have something
                           worthwhile queued up, and collect that if the answer is yes. */

                        if (a_len >= Constants.MIN_AUTO_EXTRA && a_len <= Constants.MAX_AUTO_EXTRA)
                            MaybeAddAutoExtra(a_collect, a_len);

                        a_len = 0;
                        prev_cksum = cksum;

                    }

                    /* Continue collecting string, but only if the bit flip actually made
                       any difference - we don't want no-op tokens. */

                    if (cksum != currentQueue.ExecutionTraceChecksum) {

                        out_buf.Seek(stage_cur >> 3, SeekOrigin.Begin);
                        if (a_len < Constants.MAX_AUTO_EXTRA) a_collect[a_len] = out_buf.ReadByte();
                        a_len++;

                    }

                }

            }

            new_hit_cnt = _queue.Count + unique_crashes;

            stage_finds[(int)FuzzingStages.STAGE_FLIP1] += new_hit_cnt - orig_hit_cnt;
            stage_cycles[(int)FuzzingStages.STAGE_FLIP1] += stage_max;

            /* Two walking bits. */

            stage_name = "bitflip 2/1";
            stage_short = "flip2";
            stage_max = (length << 3) - 1;

            orig_hit_cnt = new_hit_cnt;

            for (int stage_cur = 0; stage_cur < stage_max; stage_cur++) {

                stage_cur_byte = stage_cur >> 3;

                out_buf.FlipBit(stage_cur);
                out_buf.FlipBit(stage_cur + 1);

                if (CommonFuzzStuff(out_buf, length)) goto abandon_entry;

                out_buf.FlipBit(stage_cur);
                out_buf.FlipBit(stage_cur + 1);

            }

            new_hit_cnt = _queue.Count + unique_crashes;

            stage_finds[(int)FuzzingStages.STAGE_FLIP2] += new_hit_cnt - orig_hit_cnt;
            stage_cycles[(int)FuzzingStages.STAGE_FLIP2] += stage_max;

            /* Four walking bits. */

            stage_name = "bitflip 4/1";
            stage_short = "flip4";
            stage_max = (length << 3) - 3;

            orig_hit_cnt = new_hit_cnt;

            for (int stage_cur = 0; stage_cur < stage_max; stage_cur++) {

                stage_cur_byte = stage_cur >> 3;

                out_buf.FlipBit(stage_cur);
                out_buf.FlipBit(stage_cur + 1);
                out_buf.FlipBit(stage_cur + 2);
                out_buf.FlipBit(stage_cur + 3);

                if (CommonFuzzStuff(out_buf, length)) goto abandon_entry;

                out_buf.FlipBit(stage_cur);
                out_buf.FlipBit(stage_cur + 1);
                out_buf.FlipBit(stage_cur + 2);
                out_buf.FlipBit(stage_cur + 3);

            }

            new_hit_cnt = _queue.Count + unique_crashes;

            stage_finds[(int)FuzzingStages.STAGE_FLIP4] += new_hit_cnt - orig_hit_cnt;
            stage_cycles[(int)FuzzingStages.STAGE_FLIP4] += stage_max;

            /* Initialize effector map for the next step (see comments below). Always
               flag first and last byte as doing something. */

            EffectorMap eff_map = new EffectorMap(length);

            /* Walking byte. */

            stage_name = "bitflip 8/8";
            stage_short = "flip8";
            stage_max = length;

            orig_hit_cnt = new_hit_cnt;

            for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

                stage_cur_byte = stage_cur;
                out_buf.Seek(stage_cur, SeekOrigin.Begin);
                out_buf.Xor( 0xFF );

                if (CommonFuzzStuff(out_buf, length)) goto abandon_entry;

                /* We also use this stage to pull off a simple trick: we identify
                   bytes that seem to have no effect on the current execution path
                   even when fully flipped - and we skip them during more expensive
                   deterministic stages, such as arithmetics or known ints. */

                if (eff_map.HasNoEffect(stage_cur)) {

                    uint cksum;

                    /* If in dumb mode or if the file is very short, just flag everything
                       without wasting time on checksums. */

                    if (!_settings.DumbMode && length >= Constants.EFF_MIN_LEN)
                        cksum = Hasher.Hash32(trace_bits);
                    else
                        cksum = ~currentQueue.ExecutionTraceChecksum;

                    if (cksum != currentQueue.ExecutionTraceChecksum) {
                        eff_map[stage_cur] = 1;
                    }

                }
                out_buf.Seek(stage_cur, SeekOrigin.Begin);
                out_buf.Xor(0xFF);

            }

            /* If the effector map is more than EFF_MAX_PERC dense, just flag the
               whole thing as worth fuzzing, since we wouldn't be saving much time
               anyway. */

            if (eff_map.IsMaxDensity) {

                eff_map.MarkAll();

            }
            blocks_eff_select += eff_map.Count;

            blocks_eff_total += eff_map.Length;

            new_hit_cnt = _queue.Count + unique_crashes;

            stage_finds[(int)FuzzingStages.STAGE_FLIP8] += new_hit_cnt - orig_hit_cnt;
            stage_cycles[(int)FuzzingStages.STAGE_FLIP8] += stage_max;

            /* Two walking bytes. */

            if (length < 2) goto skip_bitflip;

            stage_name = "bitflip 16/8";
            stage_short = "flip16";
            stage_cur = 0;
            stage_max = length - 1;

            orig_hit_cnt = new_hit_cnt;

            for (int i = 0; i < length - 1; i++) {

                /* Let's consult the effector map... */

                if (eff_map.HasNoEffect(i) && eff_map.HasNoEffect(i + 1)) {
                    stage_max--;
                    continue;
                }

                stage_cur_byte = i;
                out_buf.Seek(i, SeekOrigin.Begin);
                out_buf.Xor(0xFFFF);
                if (CommonFuzzStuff(out_buf, length)) goto abandon_entry;
                stage_cur++;
                out_buf.Xor(0xFFFF);

            }

            new_hit_cnt = _queue.Count + unique_crashes;

            stage_finds[(int)FuzzingStages.STAGE_FLIP16] += new_hit_cnt - orig_hit_cnt;
            stage_cycles[(int)FuzzingStages.STAGE_FLIP16] += stage_max;

            if (length < 4) goto skip_bitflip;

            /* Four walking bytes. */

            stage_name = "bitflip 32/8";
            stage_short = "flip32";
            stage_cur = 0;
            stage_max = length - 3;

            orig_hit_cnt = new_hit_cnt;

            for (int i = 0; i < length - 3; i++) {

                /* Let's consult the effector map... */
                if (eff_map.HasNoEffect(i) && eff_map.HasNoEffect(i + 1) &&
                    eff_map.HasNoEffect(i + 2) && eff_map.HasNoEffect(i + 3)) {
                    stage_max--;
                    continue;
                }

                stage_cur_byte = i;
                out_buf.Seek(i, SeekOrigin.Begin);
                out_buf.Xor(0xFFFFFFFF);

                if (CommonFuzzStuff(out_buf, length)) goto abandon_entry;
                stage_cur++;

                out_buf.Seek(i, SeekOrigin.Begin);
                out_buf.Xor(0xFFFFFFFF);

            }

            new_hit_cnt = _queue.Count + unique_crashes;

            stage_finds[(int)FuzzingStages.STAGE_FLIP32] += new_hit_cnt - orig_hit_cnt;
            stage_cycles[(int)FuzzingStages.STAGE_FLIP32] += stage_max;

            skip_bitflip:

            if (no_arith) goto skip_arith;

            /**********************
             * ARITHMETIC INC/DEC *
             **********************/

            /* 8-bit arithmetics. */

            stage_name = "arith 8/8";
            stage_short = "arith8";
            stage_cur = 0;
            stage_max = 2 * length * Constants.ARITH_MAX;

            stage_val_type = StageValueTypes.STAGE_VAL_LE;

            orig_hit_cnt = new_hit_cnt;

            out_buf.Seek(0L, SeekOrigin.Begin);
            for (var i = 0; i < length; i++) {
                byte orig = out_buf.ReadByte();

                /* Let's consult the effector map... */

                if (eff_map.HasNoEffect(i)) {
                    stage_max -= 2 * Constants.ARITH_MAX;
                    continue;
                }

                stage_cur_byte = i;

                for (int j = 1; j <= Constants.ARITH_MAX; j++) {

                    byte r = (byte)(orig ^ (orig + j));

                    /* Do arithmetic operations only if the result couldn't be a product
                       of a bitflip. */

                    if (!could_be_bitflip(r)) {

                        stage_cur_val = j;
                        out_buf.Seek(i, SeekOrigin.Begin);
                        out_buf.Write((byte)(orig + j), 1);

                        if (CommonFuzzStuff(out_buf, length)) goto abandon_entry;
                        stage_cur++;

                    } else stage_max--;

                    r = (byte)(orig ^ (orig - j));

                    if (!could_be_bitflip(r)) {

                        stage_cur_val = -j;
                        out_buf.Seek(i, SeekOrigin.Begin);
                        out_buf.Write((byte)(orig - j), 1);

                        if (CommonFuzzStuff(out_buf, length)) goto abandon_entry;
                        stage_cur++;

                    } else stage_max--;

                    out_buf.Seek(i, SeekOrigin.Begin);
                    out_buf.Write(orig, 1);

                }

            }

            new_hit_cnt = _queue.Count + unique_crashes;

            stage_finds[(int)FuzzingStages.STAGE_ARITH8] += new_hit_cnt - orig_hit_cnt;
            stage_cycles[(int)FuzzingStages.STAGE_ARITH8] += stage_max;

            /* 16-bit arithmetics, both endians. */

            if (length < 2) goto skip_arith;

            stage_name = "arith 16/8";
            stage_short = "arith16";
            stage_cur = 0;
            stage_max = 4 * (length - 1) * Constants.ARITH_MAX;

            orig_hit_cnt = new_hit_cnt;

            out_buf.Seek(0L, SeekOrigin.Begin);
            for (var i = 0; i < length - 1; i++) {

                UInt16 orig = out_buf.ReadInt16();

                /* Let's consult the effector map... */

                if (eff_map.HasNoEffect(i) && eff_map.HasNoEffect(i + 1)) {
                    stage_max -= 4 * Constants.ARITH_MAX;
                    continue;
                }

                stage_cur_byte = i;

                for (int j = 1; j <= Constants.ARITH_MAX; j++) {

                    UInt16 r1 = (UInt16)(orig ^ (orig + j)),
                        r2 = (UInt16)(orig ^ (orig - j)),
                        r3 = (UInt16)(orig ^ SWAP16((UInt16)(SWAP16(orig) + j))),
                        r4 = (UInt16)(orig ^ SWAP16((UInt16)(SWAP16(orig) - j)));

                    /* Try little endian addition and subtraction first. Do it only
                       if the operation would affect more than one byte (hence the 
                       & 0xff overflow checks) and if it couldn't be a product of
                       a bitflip. */

                    stage_val_type = StageValueTypes.STAGE_VAL_LE;

                    if ((orig & 0xff) + j > 0xff && !could_be_bitflip(r1)) {

                        stage_cur_val = j;
                        out_buf.Seek(i, SeekOrigin.Begin);
                        out_buf.Write((UInt16)(orig + j),1);

                        if (CommonFuzzStuff(out_buf, length)) goto abandon_entry;
                        stage_cur++;

                    } else stage_max--;

                    if ((orig & 0xff) < j && !could_be_bitflip(r2)) {

                        stage_cur_val = -j;
                        out_buf.Seek(i, SeekOrigin.Begin);
                        out_buf.Write((UInt16)(orig - j), 1);

                        if (CommonFuzzStuff( out_buf, length)) goto abandon_entry;
                        stage_cur++;

                    } else stage_max--;

                    /* Big endian comes next. Same deal. */

                    stage_val_type = StageValueTypes.STAGE_VAL_BE;


                    if ((orig >> 8) + j > 0xff && !could_be_bitflip(r3)) {

                        stage_cur_val = j;
                        out_buf.Seek(i, SeekOrigin.Begin);
                        out_buf.Write(SWAP16((UInt16)(SWAP16(orig) + j)), 1);

                        if (CommonFuzzStuff(out_buf, length)) goto abandon_entry;
                        stage_cur++;

                    } else stage_max--;

                    if ((orig >> 8) < j && !could_be_bitflip(r4)) {

                        stage_cur_val = -j;
                        out_buf.Seek(i, SeekOrigin.Begin);
                        out_buf.Write(SWAP16((UInt16)(SWAP16(orig) - j)), 1);

                        if (CommonFuzzStuff( out_buf, length)) goto abandon_entry;
                        stage_cur++;

                    } else stage_max--;

                    out_buf.Seek(i, SeekOrigin.Begin);
                    out_buf.Write(orig, 1);

                }

            }

            new_hit_cnt = _queue.Count + unique_crashes;

            stage_finds[(int)FuzzingStages.STAGE_ARITH16] += new_hit_cnt - orig_hit_cnt;
            stage_cycles[(int)FuzzingStages.STAGE_ARITH16] += stage_max;

            /* 32-bit arithmetics, both endians. */

            if (length < 4) goto skip_arith;

            stage_name = "arith 32/8";
            stage_short = "arith32";
            stage_cur = 0;
            stage_max = 4 * (length - 3) * Constants.ARITH_MAX;

            orig_hit_cnt = new_hit_cnt;
            out_buf.Seek(0L, SeekOrigin.Begin);
            for (var i = 0; i < length - 3; i++) {

                UInt32 orig = out_buf.ReadInt32();

                /* Let's consult the effector map... */

                if (eff_map.HasNoEffect(i) && eff_map.HasNoEffect(i + 1) &&
                    eff_map.HasNoEffect(i + 2) && eff_map.HasNoEffect(i + 3)) {
                    stage_max -= 4 * Constants.ARITH_MAX;
                    continue;
                }

                stage_cur_byte = i;

                for (var j = 1; j <= Constants.ARITH_MAX; j++) {

                    UInt32 r1 = (UInt32)( orig ^ (orig + j)),
                        r2 = (UInt32)(orig ^ (orig - j)),
                        r3 = (UInt32)(orig ^ SWAP32((UInt32)(SWAP32(orig) + j))),
                        r4 = (UInt32)(orig ^ SWAP32((UInt32)(SWAP32(orig) - j)));

                    /* Little endian first. Same deal as with 16-bit: we only want to
                       try if the operation would have effect on more than two bytes. */

                    stage_val_type = StageValueTypes.STAGE_VAL_LE;

                    if ((orig & 0xffff) + j > 0xffff && !could_be_bitflip(r1)) {

                        stage_cur_val = j;
                        out_buf.Seek(i, SeekOrigin.Begin);
                        out_buf.Write((UInt32)(orig + j), 1);

                        if (CommonFuzzStuff(out_buf, length)) goto abandon_entry;
                        stage_cur++;

                    } else stage_max--;

                    if ((orig & 0xffff) < j && !could_be_bitflip(r2)) {

                        stage_cur_val = -j;
                        out_buf.Seek(i, SeekOrigin.Begin);
                        out_buf.Write((UInt32)(orig - j), 1);

                        if (CommonFuzzStuff(out_buf, length)) goto abandon_entry;
                        stage_cur++;

                    } else stage_max--;

                    /* Big endian next. */

                    stage_val_type = StageValueTypes.STAGE_VAL_BE;

                    if ((SWAP32(orig) & 0xffff) + j > 0xffff && !could_be_bitflip(r3)) {

                        stage_cur_val = j;
                        out_buf.Seek(i, SeekOrigin.Begin);
                        out_buf.Write(SWAP32((UInt32)(SWAP32(orig) + j)), 1);

                        if (CommonFuzzStuff(out_buf, length)) goto abandon_entry;
                        stage_cur++;

                    } else stage_max--;

                    if ((SWAP32(orig) & 0xffff) < j && !could_be_bitflip(r4)) {

                        stage_cur_val = -j;
                        out_buf.Seek(i, SeekOrigin.Begin);
                        out_buf.Write(SWAP32((UInt32)(SWAP32(orig) - j)), 1);

                        if (CommonFuzzStuff(out_buf, length)) goto abandon_entry;
                        stage_cur++;

                    } else stage_max--;

                    out_buf.Seek(i, SeekOrigin.Begin);
                    out_buf.Write(orig, 1);

                }

            }

            new_hit_cnt = _queue.Count + unique_crashes;

            stage_finds[(int)FuzzingStages.STAGE_ARITH32] += new_hit_cnt - orig_hit_cnt;
            stage_cycles[(int)FuzzingStages.STAGE_ARITH32] += stage_max;

            skip_arith:

            /**********************
             * INTERESTING VALUES *
             **********************/

            stage_name = "interest 8/8";
            stage_short = "int8";
            stage_cur = 0;
            stage_max = length * Constants.INTERESTING_8.Length;

            stage_val_type = StageValueTypes.STAGE_VAL_LE;

            orig_hit_cnt = new_hit_cnt;

            /* Setting 8-bit integers. */

            for (int i = 0; i < length; i++) {

                out_buf.Seek(i, SeekOrigin.Begin);
                byte orig = out_buf.ReadByte();

                /* Let's consult the effector map... */

                if (eff_map.HasNoEffect(i)) {
                    stage_max -= Constants.INTERESTING_8.Length;
                    continue;
                }

                stage_cur_byte = i;

                for (var j = 0; j < Constants.INTERESTING_8.Length; j++) {

                    /* Skip if the value could be a product of bitflips or arithmetics. */

                    if (could_be_bitflip((UInt32)(orig ^ (byte)Constants.INTERESTING_8[j])) ||
                        could_be_arith(orig, (byte)Constants.INTERESTING_8[j], 1)) {
                        stage_max--;
                        continue;
                    }

                    stage_cur_val = Constants.INTERESTING_8[j];
                    out_buf.Seek(i, SeekOrigin.Begin);
                    out_buf.WriteByte(Constants.INTERESTING_8[j]);

                    if (CommonFuzzStuff(out_buf, length)) goto abandon_entry;

                    out_buf.Seek(i, SeekOrigin.Begin);
                    out_buf.WriteByte(orig);
                    stage_cur++;

                }

            }

            new_hit_cnt = _queue.Count + unique_crashes;

            stage_finds[(int)FuzzingStages.STAGE_INTEREST8] += new_hit_cnt - orig_hit_cnt;
            stage_cycles[(int)FuzzingStages.STAGE_INTEREST8] += stage_max;

            /* Setting 16-bit integers, both endians. */

            if (no_arith || length < 2) goto skip_interest;

            stage_name = "interest 16/8";
            stage_short = "int16";
            stage_cur = 0;
            stage_max = 2 * (length - 1) * (Constants.INTERESTING_16.Length);

            orig_hit_cnt = new_hit_cnt;

            for (var i = 0; i < length - 1; i++) {

                out_buf.Seek(i, SeekOrigin.Begin);
                UInt16 orig = out_buf.ReadInt16();

                /* Let's consult the effector map... */

                if (eff_map.HasNoEffect(i) && eff_map.HasNoEffect(i + 1)) {
                    stage_max -= Constants.INTERESTING_16.Length;
                    continue;
                }

                stage_cur_byte = i;

                for (int j = 0; j < Constants.INTERESTING_16.Length; j++) {

                    stage_cur_val = Constants.INTERESTING_16[j];

                    /* Skip if this could be a product of a bitflip, arithmetics,
                       or single-byte interesting value insertion. */

                    if (!could_be_bitflip((UInt32)(orig ^ (UInt16)Constants.INTERESTING_16[j])) &&
                        !could_be_arith(orig, (UInt16)Constants.INTERESTING_16[j], 2) &&
                        !could_be_interest(orig, (UInt16)Constants.INTERESTING_16[j], 2, false)) {

                        stage_val_type = StageValueTypes.STAGE_VAL_LE;

                        out_buf.Seek(i, SeekOrigin.Begin);
                        out_buf.Write((UInt16)Constants.INTERESTING_16[j], 1);

                        if (CommonFuzzStuff(out_buf, length)) goto abandon_entry;
                        stage_cur++;

                    } else stage_max--;

                    if ((UInt16)Constants.INTERESTING_16[j] != SWAP16(Constants.INTERESTING_16[j]) &&
                        !could_be_bitflip((UInt32)(orig ^ SWAP16(Constants.INTERESTING_16[j]))) &&
                        !could_be_arith(orig, SWAP16(Constants.INTERESTING_16[j]), 2) &&
                        !could_be_interest(orig, SWAP16(Constants.INTERESTING_16[j]), 2, true)) {

                        stage_val_type = StageValueTypes.STAGE_VAL_BE;

                        out_buf.Seek(i, SeekOrigin.Begin);
                        out_buf.Write(SWAP16((UInt16)Constants.INTERESTING_16[j]), 1);

                        if (CommonFuzzStuff(out_buf, length)) goto abandon_entry;
                        stage_cur++;

                    } else stage_max--;

                }
                out_buf.Seek(i, SeekOrigin.Begin);
                out_buf.Write(orig, 1);

            }

            new_hit_cnt = _queue.Count + unique_crashes;

            stage_finds[(int)FuzzingStages.STAGE_INTEREST16] += new_hit_cnt - orig_hit_cnt;
            stage_cycles[(int)FuzzingStages.STAGE_INTEREST16] += stage_max;

            if (length < 4) goto skip_interest;

            /* Setting 32-bit integers, both endians. */

            stage_name = "interest 32/8";
            stage_short = "int32";
            stage_cur = 0;
            stage_max = 2 * (length - 3) * (Constants.INTERESTING_32.Length);

            orig_hit_cnt = new_hit_cnt;

            out_buf.Seek(0L, SeekOrigin.Begin);
            for (var i = 0; i < length - 3; i++) {

                uint orig = out_buf.ReadInt32();

                /* Let's consult the effector map... */

                if (eff_map.HasNoEffect(i) && eff_map.HasNoEffect(i + 1) &&
                    eff_map.HasNoEffect(i + 2) && eff_map.HasNoEffect(i + 3)) {
                    stage_max -= Constants.INTERESTING_32.Length >> 1;
                    continue;
                }

                stage_cur_byte = i;

                for (int j = 0; j < Constants.INTERESTING_32.Length; j++) {

                    stage_cur_val = Constants.INTERESTING_32[j];

                    /* Skip if this could be a product of a bitflip, arithmetics,
                       or word interesting value insertion. */

                    if (!could_be_bitflip(orig ^ (UInt32)Constants.INTERESTING_32[j]) &&
                        !could_be_arith(orig, (UInt32)Constants.INTERESTING_32[j], 4) &&
                        !could_be_interest(orig, (UInt32)Constants.INTERESTING_32[j], 4, false)) {

                        stage_val_type = StageValueTypes.STAGE_VAL_LE;

                        out_buf.Seek(0L, SeekOrigin.Begin);
                        out_buf.Write((UInt32)Constants.INTERESTING_32[j], 1);

                        if (CommonFuzzStuff(out_buf, length)) goto abandon_entry;
                        stage_cur++;

                    } else stage_max--;

                    if ((UInt32)Constants.INTERESTING_32[j] != SWAP32((UInt32)Constants.INTERESTING_32[j]) &&
                        !could_be_bitflip(orig ^ SWAP32((UInt32)Constants.INTERESTING_32[j])) &&
                        !could_be_arith(orig, SWAP32((UInt32)Constants.INTERESTING_32[j]), 4) &&
                        !could_be_interest(orig, SWAP32((UInt32)Constants.INTERESTING_32[j]), 4, true)) {

                        stage_val_type = StageValueTypes.STAGE_VAL_BE;

                        out_buf.Seek(0L, SeekOrigin.Begin);
                        out_buf.Write(SWAP32((UInt32)Constants.INTERESTING_32[j]), 1);
                        if (CommonFuzzStuff(out_buf, length)) goto abandon_entry;
                        stage_cur++;

                    } else stage_max--;

                }

                out_buf.Seek(0L, SeekOrigin.Begin);
                out_buf.Write(orig, 1);

            }

            new_hit_cnt = _queue.Count + unique_crashes;

            stage_finds[(int)FuzzingStages.STAGE_INTEREST32] += new_hit_cnt - orig_hit_cnt;
            stage_cycles[(int)FuzzingStages.STAGE_INTEREST32] += stage_max;

            skip_interest:

            /********************
             * DICTIONARY STUFF *
             ********************/

            if (this._extras.Count==0) goto skip_user_extras;

            /* Overwrite with user-supplied extras. */

            stage_name = "user extras (over)";
            stage_short = "ext_UO";
            stage_cur = 0;
            stage_max = this._extras.Count * length;

            stage_val_type = StageValueTypes.STAGE_VAL_NONE;

            orig_hit_cnt = new_hit_cnt;

            for (var i = 0; i < length; i++) {

                int last_len = 0;

                stage_cur_byte = i;

                /* Extras are sorted by size, from smallest to largest. This means
                   that we don't have to worry about restoring the buffer in
                   between writes at a particular offset determined by the outer
                   loop. */

                for (int j = 0; j < this._extras.Count; j++) {

                    /* Skip extras probabilistically if _extras.Count > MAX_DET_EXTRAS. Also
                       skip them if there's no room to insert the payload, if the token
                       is redundant, or if its entire span has no bytes set in the effector
                       map. */

                    if ((this._extras.Count > Constants.MAX_DET_EXTRAS && Randomize(this._extras.Count) >= Constants.MAX_DET_EXTRAS) ||
                        this._extras[j].Length > length - i ||
                        out_buf.Equal(this._extras[j].Data, i, 0, this._extras[j].Length) ||
                        eff_map.HasNoEffect(i, this._extras[j].Length)) {

                        stage_max--;
                        continue;

                    }

                    last_len = this._extras[j].Length;
                    out_buf.Seek(i, SeekOrigin.Begin);
                    out_buf.Write(in_buf, 0, _extras[j].Length);

                    if (CommonFuzzStuff( out_buf, length)) goto abandon_entry;

                    stage_cur++;

                }

                /* Restore all the clobbered memory. */
                out_buf.Seek(i, SeekOrigin.Begin);
                out_buf.Write(in_buf, i, last_len);

            }

            new_hit_cnt = _queue.Count + unique_crashes;

            stage_finds[(int)FuzzingStages.STAGE_EXTRAS_UO] += new_hit_cnt - orig_hit_cnt;
            stage_cycles[(int)FuzzingStages.STAGE_EXTRAS_UO] += stage_max;

            /* Insertion of user-supplied extras. */

            stage_name = "user extras (insert)";
            stage_short = "ext_UI";
            stage_cur = 0;
            stage_max = this._extras.Count * length;

            orig_hit_cnt = new_hit_cnt;

            ByteStream ex_tmp = new ByteStream(length + Constants.MAX_DICT_FILE);

            for (int i = 0; i <= length; i++) {

                stage_cur_byte = i;
                for (int j = 0; j < this._extras.Count; j++) {

                    if (length + _extras[j].Length > Constants.MAX_FILE) {
                        stage_max--;
                        continue;
                    }

                    /* Insert token */
                    ex_tmp.Seek(i, SeekOrigin.Begin);
                    ex_tmp.Write(_extras[j].Data, 0, _extras[j].Length);

                    /* Copy tail */
                    ex_tmp.WriteBytes(out_buf, i, length - i);

                    if (CommonFuzzStuff(ex_tmp, length + _extras[j].Length)) {
                        ex_tmp.Dispose();
                        goto abandon_entry;
                    }

                    stage_cur++;

                }

                /* Copy head */
                byte[] head = new byte[1];
                out_buf.Seek(i, SeekOrigin.Begin);
                out_buf.Read(head, 0, 1);
                ex_tmp.Seek(i, SeekOrigin.Begin);
                out_buf.Write(head, 0, 1);

            }

            ex_tmp.Dispose();

            new_hit_cnt = _queue.Count + unique_crashes;

            stage_finds[(int)FuzzingStages.STAGE_EXTRAS_UI] += new_hit_cnt - orig_hit_cnt;
            stage_cycles[(int)FuzzingStages.STAGE_EXTRAS_UI] += stage_max;

            skip_user_extras:

            if (_autoExtras.Count==0) goto skip_extras;

            stage_name = "auto extras (over)";
            stage_short = "ext_AO";
            stage_cur = 0;
            stage_max = Math.Min(_autoExtras.Count, Constants.USE_AUTO_EXTRAS) * length;

            stage_val_type =  StageValueTypes.STAGE_VAL_NONE;

            orig_hit_cnt = new_hit_cnt;

            for (int i = 0; i < length; i++) {

                int last_len = 0;

                stage_cur_byte = i;

                for (int j = 0; j < Math.Min(_autoExtras.Count, Constants.USE_AUTO_EXTRAS); j++) {

                    /* See the comment in the earlier code; extras are sorted by size. */

                    if (_autoExtras[j].Length > length - i ||
                        out_buf.Equal(_autoExtras[j].Data, i, 0, _autoExtras[j].Length) ||
                        eff_map.HasNoEffect(i, _autoExtras[j].Length)) {

                        stage_max--;
                        continue;

                    }

                    last_len = _autoExtras[j].Length;
                    out_buf.Seek(i, SeekOrigin.Begin);
                    out_buf.Write(_autoExtras[j].Data, 0, last_len);

                    if (CommonFuzzStuff(out_buf, length)) goto abandon_entry;

                    stage_cur++;

                }

                /* Restore all the clobbered memory. */
                out_buf.Seek(i, SeekOrigin.Begin);
                out_buf.Write(in_buf, i, last_len);

            }

            new_hit_cnt = _queue.Count + unique_crashes;

            stage_finds[(int)FuzzingStages.STAGE_EXTRAS_AO] += new_hit_cnt - orig_hit_cnt;
            stage_cycles[(int)FuzzingStages.STAGE_EXTRAS_AO] += stage_max;

            skip_extras:

            /* If we made this to here without jumping to havoc_stage or abandon_entry,
               we're properly done with deterministic steps and can mark it as such
               in the .state/ directory. */

            if (!currentQueue.PassedDeterministic) mark_as_det_done(currentQueue);

            /****************
             * RANDOM HAVOC *
             ****************/

            havoc_stage:

            /* The havoc stage mutation code is also invoked when splicing files; if the
               splice_cycle variable is set, generate different descriptions and such. */

            if (!splice_cycle) {

                stage_name = "havoc";
                stage_short = "havoc";
                stage_max = (doingDeterministic ? Constants.HAVOC_CYCLES_INIT : Constants.HAVOC_CYCLES) *
                              perf_score / havoc_div / 100;

            } else {

                perf_score = orig_perf;

                stage_name = $"splace {splice_cycle}";
                stage_short = "splice";
                stage_max = Constants.SPLICE_HAVOC * perf_score / havoc_div / 100;

            }

            if (stage_max < Constants.HAVOC_MIN) stage_max = Constants.HAVOC_MIN;

            var temp_len = length;
            ByteStream new_buf;

            orig_hit_cnt = _queue.Count + unique_crashes;

            havoc_queued = _queue.Count;

            /* We essentially just do several thousand runs (depending on perf_score)
               where we take the input file and make random stacked tweaks. */

            for (uint stage_cur = 0; stage_cur < stage_max; stage_cur++) {

                int use_stacking = 1 << (1 + Randomize(Constants.HAVOC_STACK_POW2));

                var stage_cur_val = use_stacking;

                for (var i = 0; i < use_stacking; i++) {

                    switch (Randomize(15 + ((_extras.Count + _autoExtras.Count) > 0 ? 2 : 0))) {

                        case 0:

                            /* Flip a single bit somewhere. Spooky! */

                            out_buf.FlipBit(Randomize(temp_len << 3));
                            break;

                        case 1:

                            /* Set byte to interesting value. */
                            out_buf.Seek(Randomize(temp_len), SeekOrigin.Begin);
                            out_buf.Write(Constants.INTERESTING_8,Randomize(Constants.INTERESTING_8.Length),1);
                            break;

                        case 2:

                            /* Set word to interesting value, randomly choosing endian. */

                            if (temp_len < 2) break;

                            if (Randomize(2)>0) {
                                out_buf.Seek(Randomize(temp_len - 1), SeekOrigin.Begin);
                                out_buf.Write((UInt16)(Constants.INTERESTING_16[Randomize(Constants.INTERESTING_16.Length)]), 1);

                            } else {

                                out_buf.Seek(Randomize(temp_len - 1), SeekOrigin.Begin);
                                out_buf.Write(SWAP16((UInt16)Constants.INTERESTING_16[Randomize(Constants.INTERESTING_16.Length)]), 1);
                            }

                            break;

                        case 3:

                            /* Set dword to interesting value, randomly choosing endian. */

                            if (temp_len < 4) break;

                            if (Randomize(2)>0) {


                                out_buf.Seek(Randomize(temp_len - 3), SeekOrigin.Begin);
                                out_buf.Write((UInt32)Constants.INTERESTING_32[Randomize(Constants.INTERESTING_32.Length)], 1);

                            } else {

                                out_buf.Seek(Randomize(temp_len - 3), SeekOrigin.Begin);
                                out_buf.Write(SWAP32((UInt32)Constants.INTERESTING_32[Randomize(Constants.INTERESTING_32.Length)]), 1);

                            }

                            break;

                        case 4:

                            /* Randomly subtract from byte. */
                            out_buf.Seek(Randomize(temp_len), SeekOrigin.Begin);
                            out_buf.Substract((byte)(1 + Randomize(Constants.ARITH_MAX)));
                            break;

                        case 5:

                            /* Randomly add to byte. */

                            out_buf.Seek(Randomize(temp_len), SeekOrigin.Begin);
                            out_buf.Add((byte)(1 + Randomize(Constants.ARITH_MAX)));
                            break;

                        case 6:

                            /* Randomly subtract from word, random endian. */

                            if (temp_len < 2) break;

                            if (Randomize(2) > 0) {

                                out_buf.Seek(Randomize(temp_len - 1), SeekOrigin.Begin);

                                out_buf.Add((UInt16)(1 + Randomize(Constants.ARITH_MAX)));

                            }
                            else {

                                out_buf.Seek(Randomize(temp_len - 1), SeekOrigin.Begin);
                                int num = 1 + Randomize(Constants.ARITH_MAX);

                                out_buf.Func((UInt16 w) => SWAP16(SWAP16((UInt16)(w - num))));

                            }

                            break;

                        case 7:

                            /* Randomly add to word, random endian. */

                            if (temp_len < 2) break;

                            if (Randomize(2)>0) {

                                out_buf.Seek(Randomize(temp_len - 1), SeekOrigin.Begin);
                                out_buf.Add((UInt16)(1 + Randomize(Constants.ARITH_MAX)));

                            } else {

                                out_buf.Seek(Randomize(temp_len - 1), SeekOrigin.Begin);
                                int num = 1 + Randomize(Constants.ARITH_MAX);

                                out_buf.Func((UInt16 w) => SWAP16(SWAP16((UInt16)(w + num))));

                            }

                            break;

                        case 8:

                            /* Randomly subtract from dword, random endian. */

                            if (temp_len < 4) break;

                            out_buf.Seek(Randomize(temp_len - 3), SeekOrigin.Begin);
                            if (Randomize(2)>0) {

                                out_buf.Substract((UInt32)(1 + Randomize(Constants.ARITH_MAX)));

                            } else {

                                int num = 1 + Randomize(Constants.ARITH_MAX);

                                out_buf.Func((UInt32 w) => SWAP32(SWAP32((UInt32)(w - num))));

                            }

                            break;

                        case 9:

                            /* Randomly add to dword, random endian. */

                            if (temp_len < 4) break;

                            out_buf.Seek(Randomize(temp_len - 3), SeekOrigin.Begin);
                            if (Randomize(2)>0) {

                                out_buf.Add((UInt32)(1 + Randomize(Constants.ARITH_MAX)));

                            } else {

                                int num = 1 + Randomize(Constants.ARITH_MAX);
                                out_buf.Func((UInt32 w)=>SWAP32(SWAP32((UInt32)(w + num))));
                            }

                            break;

                        case 10:

                            /* Just set a random byte to a random value. Because,
                               why not. We use XOR with 1-255 to eliminate the
                               possibility of a no-op. */
                            out_buf.Seek(Randomize(temp_len), SeekOrigin.Begin);
                            out_buf.Xor((byte)( 1 + Randomize(255)));
                            break;
                        case 11:
                        case 12: {

                                /* Delete bytes. We're making this a bit more likely
                                   than insertion (the next option) in hopes of keeping
                                   files reasonably small. */

                                int del_from, del_len;

                                if (temp_len < 2) break;

                                /* Don't delete too much. */

                                del_len = choose_block_len(temp_len - 1, _queueCycle);

                                del_from = Randomize(temp_len - del_len + 1);

                                memmove(out_buf + del_from, out_buf + del_from + del_len,
                                        temp_len - del_from - del_len);

                                temp_len -= del_len;

                                break;

                            }

                        case 13:

                            if (temp_len + Constants.HAVOC_BLK_XL < Constants.MAX_FILE) {

                                /* Clone bytes (75%) or insert a block of constant bytes (25%). */

                                bool actually_clone = Randomize(4) != 0;
                                int clone_from, clone_to, clone_len;

                                if (actually_clone) {

                                    clone_len = choose_block_len(temp_len, _queueCycle);
                                    clone_from = Randomize(temp_len - clone_len + 1);

                                } else {

                                    clone_len = choose_block_len(Constants.HAVOC_BLK_XL, _queueCycle);
                                    clone_from = 0;

                                }

                                clone_to = Randomize(temp_len);

                                new_buf = new ByteStream(temp_len + clone_len);

                                /* Head */
                                new_buf.WriteBytes(out_buf, 0, clone_to);

                                /* Inserted part */

                                if (actually_clone)
                                {
                                    new_buf.WriteBytes(out_buf, clone_from, clone_len);
                                }
                                else if ( Randomize(2) == 0)
                                {
                                    out_buf.Seek(Randomize(temp_len), SeekOrigin.Begin);
                                    byte[] randomFromOutBuf = new byte[1];
                                    out_buf.Read(randomFromOutBuf, 0, 1);
                                    new_buf.Write(randomFromOutBuf, 0, clone_len);
                                }
                                else
                                {
                                    new_buf.Write( (byte)Randomize(256), clone_len);
                                }
                                /* Tail */
                                new_buf.WriteBytes(out_buf, clone_to, temp_len - clone_to);

                                out_buf.Dispose();
                                out_buf = new_buf;
                                temp_len += clone_len;

                            }

                            break;

                        case 14: {

                                /* Overwrite bytes with a randomly selected chunk (75%) or fixed
                                   bytes (25%). */

                                int copy_from, copy_to, copy_len;

                                if (temp_len < 2) break;

                                copy_len = choose_block_len(temp_len - 1, _queueCycle);

                                copy_from = Randomize(temp_len - copy_len + 1);
                                copy_to = Randomize(temp_len - copy_len + 1);

                                out_buf.Seek(copy_to, SeekOrigin.Begin);

                                if (Randomize(4) != 0)
                                {

                                    if (copy_from != copy_to)
                                    {
                                        out_buf.WriteBytes(out_buf, copy_from, copy_len);
                                    }

                                }
                                else if ( Randomize(2) != 0)
                                {
                                    byte[] randomOutBufValue = new byte[1];
                                    out_buf.Read(randomOutBufValue, 0, 1);
                                    out_buf.Seek(copy_to, SeekOrigin.Begin);
                                    out_buf.Write(randomOutBufValue[0], copy_len);
                                }
                                else
                                {
                                    out_buf.Write((byte)Randomize(256), copy_len);
                                }
                                break;

                            }

                        /* Values 15 and 16 can be selected only if there are any extras
                           present in the dictionaries. */

                        case 15: {

                                /* Overwrite bytes with an extra. */

                                if (_extras.Count == 0 || (_autoExtras.Count > 0 && Randomize(2) > 0)) {

                                    /* No user-specified extras or odds in our favor. Let's use an
                                       auto-detected one. */

                                    int use_extra = Randomize(_autoExtras.Count);
                                    int extra_len = _autoExtras[use_extra].Length;
                                    int insert_at;

                                    if (extra_len > temp_len) break;

                                    insert_at = Randomize(temp_len - extra_len + 1);
                                    out_buf.Seek(insert_at, SeekOrigin.Begin);
                                    out_buf.Write(_autoExtras[use_extra].Data, 0, extra_len);

                                } else {

                                    /* No auto extras or odds in our favor. Use the dictionary. */

                                    int use_extra = Randomize(_extras.Count);
                                    int extra_len = _extras[use_extra].Length;
                                    int insert_at;

                                    if (extra_len > temp_len) break;

                                    insert_at = Randomize(temp_len - extra_len + 1);
                                    out_buf.Seek(insert_at, SeekOrigin.Begin);
                                    out_buf.Write(_extras[use_extra].Data, 0, extra_len);

                                }

                                break;

                            }

                        case 16: {

                                int use_extra, extra_len, insert_at = Randomize(temp_len + 1);

                                /* Insert an extra. Do the same dice-rolling stuff as for the
                                   previous case. */

                                if (_extras.Count == 0 || (_autoExtras.Count > 0 && Randomize(2) > 0)) {

                                    use_extra = Randomize(_autoExtras.Count);
                                    extra_len = _autoExtras[use_extra].Length;

                                    if (temp_len + extra_len >= Constants.MAX_FILE) break;

                                    new_buf = new ByteStream(temp_len + extra_len);

                                    /* Head */
                                    new_buf.WriteBytes(out_buf, 0, insert_at);

                                    /* Inserted part */
                                    new_buf.Write(_autoExtras[use_extra].Data, 0, extra_len);

                                } else {

                                    use_extra = Randomize(_extras.Count);
                                    extra_len = _extras[use_extra].Length;

                                    if (temp_len + extra_len >= Constants.MAX_FILE) break;

                                    new_buf = new ByteStream(temp_len + extra_len);

                                    /* Head */
                                    new_buf.WriteBytes(out_buf, 0, insert_at);

                                    /* Inserted part */
                                    new_buf.Write(_extras[use_extra].Data, 0, extra_len);

                                }

                                /* Tail */
                                new_buf.WriteBytes(out_buf, insert_at, temp_len - insert_at);

                                out_buf.Dispose();
                                out_buf = new_buf;
                                temp_len += extra_len;

                                break;

                            }

                    }

                }

                if (CommonFuzzStuff(out_buf, temp_len))
                    goto abandon_entry;

                /* out_buf might have been mangled a bit, so let's restore it to its
                   original size and shape. */

                if (temp_len < length) out_buf.SetLength(length);
                temp_len = length;
                out_buf.Seek(0, SeekOrigin.Begin);
                out_buf.Write( in_buf, 0, length);

                /* If we're finding new stuff, let's run for a bit longer, limits
                   permitting. */

                if (_queue.Count != havoc_queued) {

                    if (perf_score <= Constants.HAVOC_MAX_MULT * 100) {
                        stage_max *= 2;
                        perf_score *= 2;
                    }

                    havoc_queued = _queue.Count;

                }

            }

            new_hit_cnt = _queue.Count + unique_crashes;

            if (!splice_cycle) {
                stage_finds[(int)FuzzingStages.STAGE_HAVOC] += new_hit_cnt - orig_hit_cnt;
                stage_cycles[(int)FuzzingStages.STAGE_HAVOC] += stage_max;
            } else {
                stage_finds[(int)FuzzingStages.STAGE_SPLICE] += new_hit_cnt - orig_hit_cnt;
                stage_cycles[(int)FuzzingStages.STAGE_SPLICE] += stage_max;
            }

            if (!_settings.IgnoreFinds) {

                /************
                 * SPLICING *
                 ************/

                /* This is a last-resort strategy triggered by a full round with no findings.
                   It takes the current input file, randomly selects another input, and
                   splices them together at some offset, then relies on the havoc
                   code to mutate that blob. */

                retry_splicing:

                if (use_splicing && splice_cycle++ < Constants.SPLICE_CYCLES &&
                    _queue.Count > 1 && currentQueue.Length > 1) {

                    QueueEntry target;
                    int tid, split_at;
                    int f_diff, l_diff;

                    /* First of all, if we've modified in_buf for havoc, let's clean that
                       up... */

                    if (in_buf != orig_in) {
                        ck_free(in_buf);
                        in_buf = orig_in;
                        length = currentQueue.Length;
                    }

                    /* Pick a random queue entry and seek to it. Don't splice with yourself. */

                    do { tid = Randomize(_queue.Count); } while (tid == current_entry);

                    splicing_with = tid;
                    target = queue;

                    while (tid >= 100) { target = target.Next100; tid -= 100; }
                    while (tid-- > 0) target = target.Next;

                    /* Make sure that the target has a reasonable length. */

                    while (target && (target.Length < 2 || target == queue_cur)) {
                        target = target.Next;
                        splicing_with++;
                    }

                    if (target == null) goto retry_splicing;

                    /* Read the testcase into a new buffer. */

                    fd = open(target.FileName, O_RDONLY);

                    if (fd < 0) PFATAL("Unable to open '%s'", target.FileName);

                    new_buf = new ByteStream(target.Length);

                    ck_read(fd, new_buf, target.Length, target.FileName);

                    close(fd);

                    /* Find a suitable splicing location, somewhere between the first and
                       the last differing byte. Bail out if the difference is just a single
                       byte or so. */

                    locate_diffs(in_buf, new_buf, Math.Min(length, target.Length), &f_diff, &l_diff);

                    if (f_diff < 0 || l_diff < 2 || f_diff == l_diff)
                    {
                        new_buf.Dispose();
                        goto retry_splicing;
                    }

                    /* Split somewhere between the first and last differing byte. */

                    split_at = f_diff + Randomize(l_diff - f_diff);

                    /* Do the thing. */

                    length = target.Length;
                    new_buf.Write(in_buf, 0, split_at);
                    in_buf = new_buf.GetBytes();

                    out_buf.Dispose();
                    out_buf =  new ByteStream(length);
                    out_buf.Write(in_buf, 0, length);

                    goto havoc_stage;

                }

            }

            returnValue = true;

            abandon_entry:

            splicing_with = -1;

            /* Update pending_not_fuzzed count if we made it through the calibration
               cycle and have not seen this entry before. */

            if (StopSoon != StopMode.NotStopping && currentQueue.CalibrationFailed == 0 && !currentQueue.WasFuzzed) {
                currentQueue.WasFuzzed = true;
                pending_not_fuzzed--;
                if (currentQueue.Favored) pending_favored--;
            }

            if (in_buf != orig_in) ck_free(in_buf);
            out_buf.Dispose();
            eff_map.Dispose();

            return returnValue;

        }
        private void ShowStats()
        {
        }

        private void SaveAuto()
        {
        }

        private void WriteStatsFile(int v1, int v2, int v3)
        {
            throw new NotImplementedException();
        }

        private long FindStartPosition(bool resumingFuzz, bool in_place_resume)
        {
            string fileName;

            if (!resumingFuzz)
            {
                return 0;
            }

            if (in_place_resume)
            {
                fileName = $"{_settings.OutputDirectory}/fuzzer_stats";
            }
            else
            {
                fileName = $"{_settings.OutputDirectory}/../fuzzer_stats";
            }
            if (_settings.FileSystem.FileExists(fileName))
            {
                using (var stream = _settings.FileSystem.Open(fileName, OpenOptions.ReadOnly))
                {
                    var fuzzerStatisticsSource = stream.ReadToEnd(Encoding.UTF8);

                    stream.Close();

                    var fuzzerStatistics = JsonConvert.DeserializeObject<FuzzerStatistics>(fuzzerStatisticsSource);

                    if (fuzzerStatistics.CurrentPath.HasValue)
                    {
                        return fuzzerStatistics.CurrentPath.Value;
                    }
                }
            }

            return 0;

        }

        private void ShowInitStats()
        {
        }

        private void PerformDryRun(object useArugments)
        {
            throw new NotImplementedException();
        }

        private object GetArguments(IFuzzerSettings settings)
        {
            throw new NotImplementedException();
        }

        private object GetQueueArguments(IFuzzerSettings settings)
        {
            throw new NotImplementedException();
        }

        private void CheckBinary(string qemuBinaryFile)
        {
            throw new NotImplementedException();
        }

        private void FindTimeout()
        {
            throw new NotImplementedException();
        }

        private void LoadExtras(string extrasDirectory)
        {
            throw new NotImplementedException();
        }

        private void PivotInputs()
        {
            throw new NotImplementedException();
        }

        private void LoadAuto()
        {
            throw new NotImplementedException();
        }

        private void ReadTestCases()
        {

            var directoryName = $"{_settings.InputDirectory}/queue";
            if (_settings.FileSystem.DirectoryExists(directoryName))
            {
                _settings.Logger.Information("Scanning 'inputDirectory'...", _settings.InputDirectory);
                var fileNames = _settings.FileSystem.EnumerateFiles(directoryName);
                if (_settings.ShuffleQueue && fileNames.Count() > 1)
                {
                    _settings.Logger.Information("Shuffling queue...");
                    fileNames = ShuffleFileNames(fileNames);
                }
                foreach (var fileName in fileNames)
                {
                    var path = $"{_settings.InputDirectory}/{fileName}";
                    var deterministicFileName = $"{_settings.InputDirectory}/.state/deterministic_done/{fileName}";

                    if (string.Equals(fileName, "readme.txt", StringComparison.CurrentCultureIgnoreCase))
                    {
                        continue;
                    }

                    var fileInfo = _settings.FileSystem.GetFileInfo(path);

                    if (fileInfo.Length > _settings.MaxFileSize)
                    {
                        _settings.Logger.Fatal($"Test case '{fileName}' is too big ({fileInfo.Length}, limit is {_settings.MaxFileSize})");
                    }
                    /* Check for metadata that indicates that deterministic fuzzing
                       is complete for this entry. We don't want to repeat deterministic
                       fuzzing when resuming aborted scans, because it would be pointless
                       and probably very time-consuming. */

                    var passedDeterministic = _settings.FileSystem.FileExists(deterministicFileName);

                    _queue.Add(path, fileInfo.Length, passedDeterministic);

                }

                if (_queue.Count == 0)
                {
                    _settings.Logger.Warning("Looks like there are no valid test cases in the input directory!The fuzzer\n"
                         + "needs one or more test case to start with - ideally, a small file under\n"
                         + "1 kB or so. The cases must be stored as regular files directly in the\n"
                         + "input directory.\n");
                    throw new Exception($"Not usable test cased in '{directoryName}'");
                }
            }
            else
            {
                _settings.Logger.Warning("The input directory does not seem to be valid - try again.The fuzzer needs\n"
                   + "one or more test case to start with - ideally, a small file under 1 kB\n"
                   + "or so. The cases must be stored as regular files directly in the input\n"
                   + "directory.\n");
                throw new Exception($"Unable to open '{directoryName}'");
            }

        }
        private void RunTarget( int timeout )
        {
            throw new NotImplementedException();
        }
        private IEnumerable<string> ShuffleFileNames(IEnumerable<string> fileNames)
        {
            throw new NotImplementedException();
        }

        private void SetupDirsFds()
        {
            throw new NotImplementedException();
        }

        private void InitCountClass16()
        {
            throw new NotImplementedException();
        }

        private void SetupShm()
        {
            throw new NotImplementedException();
        }

        private void SetupPost()
        {
            throw new NotImplementedException();
        }

        private void CheckCpuGovernor()
        {
            throw new NotImplementedException();
        }

        private void CheckCrashHandling()
        {
            throw new NotImplementedException();
        }

        private void GetCoreCount()
        {
            throw new NotImplementedException();
        }

        private void FixUpSync()
        {
            throw new NotImplementedException();
        }

        private void SetupSignalHandlers()
        {
            throw new NotImplementedException();
        }

        private void CheckAsanOptions()
        {
            throw new NotImplementedException();
        }
    }
}
