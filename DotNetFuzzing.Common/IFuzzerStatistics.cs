using System;

namespace DotNetFuzzing.Common
{
    public interface IFuzzerStatistics
    {
        string afl_banner { get; set; }
        string afl_version { get; set; }
        int bitmap_cvg { get; set; }
        string command_line { get; set; }
        TimeSpan? exec_timeout { get; set; }
        int execs_done { get; set; }
        int execs_per_sec { get; set; }
        int execs_since_crash { get; set; }
        string fuzzer_pid { get; set; }
        int last_crash { get; set; }
        int last_crash_execs { get; }
        DateTime last_crash_time { get; }
        int last_hang { get; set; }
        DateTime last_hang_time { get; }
        int last_path { get; set; }
        DateTime? last_update { get; set; }
        int max_depth { get; set; }
        int paths_favored { get; set; }
        int paths_found { get; set; }
        int paths_imported { get; set; }
        int paths_total { get; set; }
        int pending_favs { get; set; }
        int pending_total { get; set; }
        int stability { get; set; }
        DateTime? start_time { get; set; }
        int total_crashes { get; }
        int total_executions { get; }
        int total_timeouts { get; }
        int TrimExecutions { get; }
        int unique_crashes { get; set; }
        int unique_hangs { get; set; }
        int unique_tmouts { get; }
        int variable_paths { get; set; }
    }
}