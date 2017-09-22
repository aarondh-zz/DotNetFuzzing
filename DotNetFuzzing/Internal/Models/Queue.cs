using DotNetFuzzing.Common;
using System;
using System.Collections.Generic;
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
            public bool WasFuzzed { get; set; }                     /* Had any fuzzing done yet?        */
            public bool PassedDeterministic { get; set; }                     /* Deterministic stages passed?     */
            public bool HasNewCoverage { get; set; }                    /* Triggers new coverage?           */
            public bool VariableBehavior { get; set; }                  /* Variable behavior?               */
            public bool Favored { get; set; }                       /* Currently favored?               */
            public bool FsRedundant { get; set; }                   /* Marked as redundant in the fs?   */
            /// <summary>
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
       }
        public IFuzzerSettings Settings { get; }
        public QueueEntry Last { get; set; }
        public QueueEntry Previous100 { get; set; }
        public int Favored { get; private set; }
        public int PendingFavored { get; set; }
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
            Favored = 0;
            PendingFavored = 0;

            q = this.Last;

            while (q != null)
            {
                q.Favored = false;
                q = q.Next;
            }

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
                    Favored++;

                    if (!topRated[i].WasFuzzed)
                    {
                        PendingFavored++;
                    }

                }
            }

            q = this.Last;

            while (q != null)
            {
                MarkAsRedundant(q, !q.Favored);
                q = q.Next;
            }
        }
        private string StringAfter(string text, char c)
        {
            if (text != null)
            {
                var sep = text.LastIndexOf(c);
                if (sep >= 0)
                {
                    return text.Substring(sep + 1);
                }
            }
            return null;
        }

        private void MarkAsRedundant(QueueEntry q, bool state)
        {
            if (state == q.FsRedundant) return;

            q.FsRedundant = state;

            var fileName = $"{Settings.OutputDirectory}/queue/.state/redundant_edges/{StringAfter(q.FileName, '/')}";

            if (state)
            {

                var stream = Settings.FileSystem.Open(fileName, OpenOptions.WriteOnly | OpenOptions.Create | OpenOptions.Exclusive);
                if (stream == null)
                {
                    var exception = new Exception($"Unable to create '{fileName}'");
                }
                stream.Close();

            }
            else
            {
                if (!Settings.FileSystem.Delete(fileName))
                {
                    var exception = new Exception($"Unable to remove '{fileName}'");
                    Settings.Logger.Fatal(exception, $"Unable to remove '{fileName}'", fileName);
                    throw exception;
                }
            }
        }
        public QueueEntry Add(string fileName, int length, bool passedDeterministic)
        {
            var queueEntry = new QueueEntry
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
