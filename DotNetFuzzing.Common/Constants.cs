﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotNetFuzzing.Common
{
    public static class Constants
    {
        public const string VERSION = "2.51b";

        /******************************************************
         *                                                    *
         *  Settings that may be of interest to power users:  *
         *                                                    *
         ******************************************************/

        /* Comment out to disable terminal colors (note that this makes afl-analyze
           a lot less nice): */

        public const bool USE_COLOR = true;

        /* Comment out to disable fancy ANSI boxes and use poor man's 7-bit UI: */

        public const bool FANCY_BOXES = true;

        /* Default timeout for fuzzed code (milliseconds). This is the upper bound,
           also used for detecting hangs; the actual value is auto-scaled: */

        public const int EXEC_TIMEOUT = 1000;

        /* Timeout rounding factor when auto-scaling (milliseconds): */

        public const int EXEC_TM_ROUND = 20;

        /* Default memory limit for child process (MB): */


        public const int MEM_LIMIT = 25;

        /* Default memory limit when running in QEMU mode (MB): */

        public const int MEM_LIMIT_QEMU = 200;

        /* Number of calibration cycles per every new test case (and for test
           cases that show variable behavior): */

        public const int CAL_CYCLES = 8;
        public const int CAL_CYCLES_LONG = 40;

        /* Number of subsequent timeouts before abandoning an input file: */

        public const int TMOUT_LIMIT = 250;

        /* Maximum number of unique hangs or crashes to record: */

        public const int KEEP_UNIQUE_HANG = 500;
        public const int KEEP_UNIQUE_CRASH = 5000;

        /* Baseline number of random tweaks during a single 'havoc' stage: */

        public const int HAVOC_CYCLES = 256;
        public const int HAVOC_CYCLES_INIT = 1024;

        /* Maximum multiplier for the above (should be a power of two, beware
           of 32-bit int overflows): */

        public const int HAVOC_MAX_MULT = 16;

        /* Absolute minimum number of havoc cycles (after all adjustments): */

        public const int HAVOC_MIN = 16;

        /* Maximum stacking for havoc-stage tweaks. The actual value is calculated
           like this: 

           n = random between 1 and HAVOC_STACK_POW2
           stacking = 2^n

           In other words, the default (n = 7) produces 2, 4, 8, 16, 32, 64, or
           128 stacked tweaks: */

        public const int HAVOC_STACK_POW2 = 7;

        /* Caps on block sizes for cloning and deletion operations. Each of these
           ranges has a 33% probability of getting picked, except for the first
           two cycles where smaller blocks are favored: */

        public const int HAVOC_BLK_SMALL = 32;
        public const int HAVOC_BLK_MEDIUM = 128;
        public const int HAVOC_BLK_LARGE = 1500;

        /* Extra-large blocks, selected very rarely (<5% of the time): */

        public const int HAVOC_BLK_XL = 32768;

        /* Probabilities of skipping non-favored entries in the queue, expressed as
           percentages: */

        public const int SKIP_TO_NEW_PROB = 99; // ...when there are new, pending favorites 
        public const int SKIP_NFAV_OLD_PROB = 95; // ...no new favs, cur entry already fuzzed 
        public const int SKIP_NFAV_NEW_PROB = 75; // ...no new favs, cur entry not fuzzed yet 

        /* Splicing cycle count: */

        public const int SPLICE_CYCLES = 15;

        /* Nominal per-splice havoc cycle length: */

        public const int SPLICE_HAVOC = 32;

        /* Maximum offset for integer addition / subtraction stages: */

        public const int ARITH_MAX = 35;

        /* Limits for the test case trimmer. The absolute minimum chunk size; and
           the starting and ending divisors for chopping up the input file: */

        public const int TRIM_MIN_BYTES = 4;
        public const int TRIM_START_STEPS = 16;
        public const int TRIM_END_STEPS = 1024;

        /* Maximum size of input file, in bytes (keep under 100MB): */

        public const int MAX_FILE = (1 * 1024 * 1024);

        /* The same, for the test case minimizer: */

        public const int TMIN_MAX_FILE = (10 * 1024 * 1024);

        /* Block normalization steps for afl-tmin: */

        public const int TMIN_SET_MIN_SIZE = 4;
        public const int TMIN_SET_STEPS = 128;

        /* Maximum dictionary token size (-x), in bytes: */

        public const int MAX_DICT_FILE = 128;

        /* Length limits for auto-detected dictionary tokens: */

        public const int MIN_AUTO_EXTRA = 3;
        public const int MAX_AUTO_EXTRA = 32;

        /* Maximum number of user-specified dictionary tokens to use in deterministic
           steps; past this point, the "extras/user" step will be still carried out,
           but with proportionally lower odds: */

        public const int MAX_DET_EXTRAS = 200;

        /* Maximum number of auto-extracted dictionary tokens to actually use in fuzzing
           (first value), and to keep in memory as candidates. The latter should be much
           higher than the former. */

        public const int USE_AUTO_EXTRAS = 50;
        public const int MAX_AUTO_EXTRAS = (USE_AUTO_EXTRAS * 10);

        /* Scaling factor for the effector map used to skip some of the more
           expensive deterministic steps. The actual divisor is set to
           2^EFF_MAP_SCALE2 bytes: */

        public const int EFF_MAP_SCALE2 = 3;

        /* Minimum input file length at which the effector logic kicks in: */

        public const int EFF_MIN_LEN = 128;

        /* Maximum effector density past which everything is just fuzzed
           unconditionally (%): */

        public const int EFF_MAX_PERC = 90;

        /* UI refresh frequency (Hz): */

        public const int UI_TARGET_HZ = 5;

        /* Fuzzer stats file and plot update intervals (sec): */

        public const int STATS_UPDATE_SEC = 60;
        public const int PLOT_UPDATE_SEC = 5;

        /* Smoothing divisor for CPU load and exec speed stats (1 - no smoothing). */

        public const int AVG_SMOOTHING = 16;

        /* Sync interval (every n havoc cycles): */

        public const int SYNC_INTERVAL = 5;

        /* Output directory reuse grace period (minutes): */

        public const int OUTPUT_GRACE = 25;

        /* Set this to true  to use simple file names (id_NNNNNN): */

        public const bool SIMPLE_FILES = false;

        /* List of interesting values to use in fuzzing. */

        public static readonly byte[] INTERESTING_8 = {
           0x80,         /* Overflow signed 8-bit when decremented  */ 
           0xff,         /*                                         */ 
           0,            /*                                         */ 
           1,            /*                                         */ 
           16,           /* One-off with common buffer size         */ 
           32,           /* One-off with common buffer size         */ 
           64,           /* One-off with common buffer size         */ 
           100,          /* One-off with common buffer size         */ 
           127           /* Overflow signed 8-bit when incremented  */
           };
        public static readonly Int16[] INTERESTING_16 = new Int16[] {
          -32768,        /* Overflow signed 16-bit when decremented */ 
          -129,          /* Overflow signed 8-bit                   */ 
           128,          /* Overflow signed 8-bit                   */ 
           255,          /* Overflow unsig 8-bit when incremented   */ 
           256,          /* Overflow unsig 8-bit                    */ 
           512,          /* One-off with common buffer size         */ 
           1000,         /* One-off with common buffer size         */ 
           1024,         /* One-off with common buffer size         */ 
           4096,         /* One-off with common buffer size         */ 
           32767         /* Overflow signed 16-bit when incremented */
           };
        public static readonly int[] INTERESTING_32 = new int[] {
          -2147483648, /* Overflow signed 32-bit when decremented */ 
          -100663046,    /* Large negative number (endian-agnostic) */ 
          -32769,        /* Overflow signed 16-bit                  */ 
           32768,        /* Overflow signed 16-bit                  */ 
           65535,        /* Overflow unsig 16-bit when incremented  */ 
           65536,        /* Overflow unsig 16 bit                   */ 
           100663045,    /* Large positive number (endian-agnostic) */ 
           2147483647    /* Overflow signed 32-bit when incremented */
        };
        /***********************************************************
         *                                                         *
         *  Really exotic stuff you probably don't want to touch:  *
         *                                                         *
         ***********************************************************/

        /* Call count interval between reseeding the libc PRNG from /dev/urandom: */

        public const int RESEED_RNG = 10000;

        /* Maximum line length passed from GCC to 'as' and used for parsing
           configuration files: */

        public const int MAX_LINE = 8192;

        /* Environment variable used to pass SHM ID to the called program. */

        public const string SHM_ENV_VAR = "__AFL_SHM_ID";

        /* Other less interesting, internal-only variables. */

        public const string CLANG_ENV_VAR = "__AFL_CLANG_MODE";
        public const string AS_LOOP_ENV_VAR = "__AFL_AS_LOOPCHECK";
        public const string PERSIST_ENV_VAR = "__AFL_PERSISTENT";
        public const string DEFER_ENV_VAR = "__AFL_DEFER_FORKSRV";

        /* In-code signatures for deferred and persistent mode. */

        public const string PERSIST_SIG = "##SIG_AFL_PERSISTENT##";
        public const string DEFER_SIG = "##SIG_AFL_DEFER_FORKSRV##";

        /* Distinctive bitmap signature used to indicate failed execution: */

        public const uint EXEC_FAIL_SIG = 0xfee1dead;

        /* Distinctive exit code used to indicate MSAN trip condition: */

        public const int MSAN_ERROR = 86;

        /* Designated file descriptors for forkserver commands (the application will
           use FORKSRV_FD and FORKSRV_FD + 1): */

        public const int FORKSRV_FD = 198;

        /* Fork server init timeout multiplier: we'll wait the user-selected
           timeout plus this much for the fork server to spin up. */

        public const int FORK_WAIT_MULT = 10;

        /* Calibration timeout adjustments, to be a bit more generous when resuming
           fuzzing sessions or trying to calibrate already-added internal finds.
           The first value is a percentage, the other is in milliseconds: */

        public const int CAL_TMOUT_PERC = 125;
        public const int CAL_TMOUT_ADD = 50;

        /* Number of chances to calibrate a case before giving up: */

        public const int CAL_CHANCES = 3;

        /* Map size for the traced binary (2^MAP_SIZE_POW2). Must be greater than
           2; you probably want to keep it under 18 or so for performance reasons
           (adjusting AFL_INST_RATIO when compiling is probably a better way to solve
           problems with complex programs). You need to recompile the target binary
           after changing this - otherwise, SEGVs may ensue. */

        public const int MAP_SIZE_POW2 = 16;
        public const int MAP_SIZE = (1 << MAP_SIZE_POW2);

        /* Maximum allocator request size (keep well under INT_MAX): */

        public const int MAX_ALLOC = 0x40000000;

        /* A made-up hashing seed: */

        public const uint HASH_CONST = 0xa5b35705;

        /* Constants for afl-gotcpu to control busy loop timing: */

        public const int CTEST_TARGET_MS = 5000;
        public const int CTEST_CORE_TRG_MS = 1000;
        public const int CTEST_BUSY_CYCLES = (10 * 1000 * 1000);

        /* Set this to true  this to use inferior block-coverage-based instrumentation. Note
           that you need to recompile the target binary for this to have any effect: */

        public const bool COVERAGE_ONLY = false;

        /* Set this to true  this to ignore hit counts and output just one bit per tuple.
           As with the previous setting, you will need to recompile the target
           binary: */

        public const bool SKIP_COUNTS = false;

        /* Set this to true to use instrumentation data to record newly discovered paths,
           but do not use them as seeds for fuzzing. This is useful for conveniently
           measuring coverage that could be attained by a "dumb" fuzzing algorithm: */

        public const bool IGNORE_FINDS = false;
    }
}
