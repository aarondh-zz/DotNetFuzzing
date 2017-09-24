using DotNetFuzzing.Common;
using DotNetFuzzing.Utilities;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotNetFuzzing.Internal.Models
{
    public class Queue
    {
        /* Map size for the traced binary (2^MAP_SIZE_POW2). Must be greater than
          2; you probably want to keep it under 18 or so for performance reasons
          (adjusting AFL_INST_RATIO when compiling is probably a better way to solve
          problems with complex programs). You need to recompile the target binary
          after changing this - otherwise, SEGVs may ensue. */

        const int MAP_SIZE_POW2 = 16;
        const int MAP_SIZE = (1 << MAP_SIZE_POW2);
        private int _currentDepth;
        private int _maxDepth;

        public class QueueEntry
        {
            private Queue _queue;
            public QueueEntry(Queue queue)
            {
                _queue = queue;
            }
            /// <summary>
            ///  File name for the test case
            /// </summary>
            public string FileName { get; set; }
            /// <summary>
            /// Input length
            /// </summary>
            public int Length { get; set; }
            /// <summary>
            /// Calibration failed?     
            /// </summary>
            public int CalibrationFailed { get; set; } 
            public bool TrimDone { get; set; }                     /* Trimmed?                         */
            private bool _wasFuzzed;
            /// <summary>
            /// Has any fuzzing been done yet?
            /// </summary>
            public bool WasFuzzed
            {
                get
                {
                    return _wasFuzzed;
                }
                set {
                    if ( _wasFuzzed != value)
                    {
                        _wasFuzzed = value;
                        _queue.PendingNotFuzzed += value ? -1 : 1;
                    }
                }
            }
            public bool PassedDeterministic { get; set; }                     /* Deterministic stages passed?     */
            public bool HasNewCoverage { get; set; }                    /* Triggers new coverage?           */
            public bool VariableBehavior { get; set; }                  /* Variable behavior?               */
            /// <summary>
            /// Current favored?
            /// </summary>
            private bool _favored;
            public bool Favored
            {
                get
                {
                    return _favored;
                }
                set
                {
                    if ( _favored != value )
                    {
                        _queue.PendingFavored += value ? -1 : 1;
                        _queue.Favored += value ? 1 : -1;
                    }
                }
            }
            public bool FsRedundant { get; set; }                   /* Marked as redundant in the fs?   */
            public void MarkAsVariable(IFuzzerSettings settings)
            {
                string entryFileName = Path.GetFileName(FileName);
                string destinationFileName = $"../../{entryFileName}";
                string fileName = $"{settings.OutputDirectory}/queue/.state/variable_behavior/{entryFileName}";

                using (var stream = settings.FileSystem.Open(fileName, OpenOptions.Create | OpenOptions.Exclusive | OpenOptions.WriteOnly))
                {
                    stream.Write(destinationFileName);
                    stream.Flush();
                }
                this.VariableBehavior = true;
            }
            public void MarkAsRedundant(IFuzzerSettings settings)
            {
                var redundant = !this.Favored;
                if (!redundant == this.FsRedundant) return;

                this.FsRedundant = redundant;

                var queueFileName = Path.GetFileName(this.FileName);

                var filePath = $"{settings.OutputDirectory}/queue/.state/redundant_edges/{queueFileName}";

                if (redundant)
                {

                    using (var stream = settings.FileSystem.Open(filePath, OpenOptions.WriteOnly | OpenOptions.Create | OpenOptions.Exclusive))
                    {
                        stream.Write($"../../../{queueFileName}");
                        stream.Flush();
                        stream.Close();
                    }

                }
                else
                {
                    if (!settings.FileSystem.Delete(filePath))
                    {
                        var exception = new Exception($"Unable to remove '{filePath}'");
                        settings.Logger.Fatal(exception, $"Unable to remove '{filePath}'", filePath);
                        throw exception;
                    }
                }
            }            /// <summary>
                         /// Number of bits set in bitmap
                         /// </summary>
            public int BitmapSize { get; set; }
            /// <summary>
            /// Checksum of the execution trace
            /// </summary>
            public uint ExecutionTraceChecksum { get; set; }
            /// <summary>
            /// Execution time (microseconds) 
            /// </summary>
            public long ExecutionTimeUs { get; set; }
            /// <summary>
            /// Number of queue cycles behind
            /// </summary>
            public int Handicap { get; set; }
            /// <summary>
            /// Path depth
            /// </summary>
            public int Depth { get; set; }

            /// <summary>
            /// Trace bytes, if kept
            /// </summary>
            public byte[] TraceMini { get; set; }
            /// <summary>
            /// Trace bytes ref count
            /// </summary>
            public int TraceBytesReferenceCount { get; set; }
            /// <summary>
            /// Next queue entry in the linked list
            /// </summary>
            public QueueEntry Next { get; set; }
            public QueueEntry Next100 { get; set; }

            internal void MarkAsDeterministicDone(IFuzzerSettings settings)
            {
                var queueFileName = Path.GetFileName(this.FileName);
                string filePath = $"{settings.OutputDirectory}/queue/.state/deterministic_done/{queueFileName}";
                using (var stream = settings.FileSystem.Open(filePath, OpenOptions.Create | OpenOptions.Exclusive | OpenOptions.WriteOnly))
                {
                    stream.Write($"../../{queueFileName}");
                    stream.Flush();
                    stream.Close();
                }

                this.PassedDeterministic = true;
            }
        }
        public QueueEntry this[int index]
        {
            get
            {
                var target = this.First;
                while (index >= 100) { target = target.Next100; index -= 100; }
                while (index-- > 0) target = target.Next;
                return target;
            }
        }
        public IFuzzerSettings Settings { get; }
        public QueueEntry Last { get; set; }
        public QueueEntry Previous100 { get; set; }
        public int Favored { get; private set; }
        public int PendingFavored { get; private set; }
        public QueueEntry First { get; private set; }
        public int Count { get; private set; }
        public int PendingNotFuzzed { get; private set; }

        public Queue(IFuzzerSettings settings)
        {
            Settings = settings;
        }
        /// <summary>
        /// The second part of the mechanism discussed above is a routine that
        /// goes over top_rated[] entries, and then sequentially grabs winners for
        /// previously-unseen bytes(temp_v) and marks them as favored, at least
        /// until the next run.The favored entries are given more air time during
        /// all fuzzing steps. 
        /// </summary>
        public void Cull(bool dumbMode, bool scoreChanged, QueueEntry[] topRated, int mapSize = MAP_SIZE)
        {
            if (dumbMode || !scoreChanged) return;

            QueueEntry q;
            byte[] tempV = new byte[mapSize >> 3];
            for (var i = 0; i < tempV.Length; i++)
            {
                tempV[i] = 255;
            }

            scoreChanged = false;

            q = this.First;

            while (q != null)
            {
                q.Favored = false;
                q = q.Next;
            }
            Favored = 0;
            PendingFavored = Count;

            /* Let's see if anything in the bitmap isn't captured in tempV.
               If yes, and if it has a topRated[] contender, let's use it. */

            for (var i = 0; i < mapSize; i++)
            {
                if (topRated[i] != null && (tempV[i >> 3] & (1 << (i & 7))) != 0)
                {

                    var j = MAP_SIZE >> 3;

                    // Remove all bits belonging to the current entry from tempV.

                    while (j-- > 0)
                    {
                        if (topRated[i].TraceMini[j] != 0)
                        {
                            tempV[j] &= (byte)~topRated[i].TraceMini[j];
                        }
                    }

                    topRated[i].Favored = true;

                    if (!topRated[i].WasFuzzed)
                    {
                        PendingFavored++;
                    }

                }
            }

            q = this.First;

            while (q != null)
            {
                q.MarkAsRedundant(Settings);
                q = q.Next;
            }
        }
        
        public QueueEntry Add(string fileName, int length, bool passedDeterministic)
        {
            var queueEntry = new QueueEntry(this)
            {
                FileName = fileName,
                Length = length,
                Depth = _currentDepth + 1,
                PassedDeterministic = passedDeterministic
            };

            if (queueEntry.Depth > _maxDepth)
            {
                _maxDepth = queueEntry.Depth;
            }
            if (First == null)
            {
                First = Last = Previous100 = queueEntry;
            }
            else
            {
                Last.Next = queueEntry;
                Last = queueEntry;
            }
            Count++;
            PendingNotFuzzed++;

            //cycles_wo_finds = 0;

            if ((Count % 100) == 0)
            {
                Previous100.Next100 = queueEntry;
                Previous100 = queueEntry;
            }

            //last_path_time = get_cur_time();

            return queueEntry;
        }
    }
}
