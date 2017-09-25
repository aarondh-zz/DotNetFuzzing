using System;

namespace DotNetFuzzing
{
    public class FuzzerStatistics
    {
        public int? CurrentPath { get; set; }
        public DateTime? start_time { get; set; }
        public DateTime? last_update { get; set; }
        public string fuzzer_pid { get; set; }
        public int cycles_done { get; set; }
        public int execs_done { get; set; }
        public int execs_per_sec { get; set; }
        public int paths_total { get; set; }
        public int paths_favored { get; set; }
        public int paths_found { get; set; }
        public int paths_imported { get; set; }
        public int max_depth { get; set; }
        public int cur_path { get; set; }
        public int pending_favs { get; set; }
        public int pending_total { get; set; }
        public int variable_paths { get; set; }
        public int stability { get; set; }
        public int bitmap_cvg { get; set; }
        public int unique_crashes { get; set; }
        public int unique_hangs { get; set; }
        public int last_path { get; set; }
        public int last_crash { get; set; }
        public int last_hang { get; set; }
        public int execs_since_crash { get; set; }
        public TimeSpan? exec_timeout { get; set; }
        public string afl_banner { get; set; }
        public string afl_version { get; set; }
        public string command_line { get; set; }
        public int TrimExecutions { get; internal set; }
        public int total_crashes { get; internal set; }
        public DateTime last_hang_time { get; internal set; }
        public DateTime last_crash_time { get; internal set; }
        public int last_crash_execs { get; internal set; }
        public int total_executions { get; internal set; }
        public int total_timeouts { get; internal set; }
        public int unique_tmouts { get; internal set; }
    }
}