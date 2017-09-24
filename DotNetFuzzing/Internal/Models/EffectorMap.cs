using DotNetFuzzing.Common;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotNetFuzzing.Internal.Models
{
    public class EffectorMap : IDisposable
    {
        private byte[] _map;
        private int _count;

        public EffectorMap( int length )
        {
            ScalingFactor = Constants.EFF_MAP_SCALE2;
            MaxDensity = Constants.EFF_MAX_PERC;
            MinimumInputFileLength = Constants.EFF_MIN_LEN;

            _map = new byte[EFF_ALEN(length)];
            _map[0] = 1;
            if (EFF_APOS(length - 1) != 0)
            {
                _map[EFF_APOS(length - 1)] = 1;
                _count++;
            }
        }
        /// <summary>
        /// position of a particular file offset in the map
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        private int EFF_APOS(int value)
        {
            return value >> ScalingFactor;
        }
        private int EFF_REM(int value)
        {
            return ((value) & ((1 << ScalingFactor) - 1));
        }
        /// <summary>
        /// length of a map with a particular number of bytes
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        private int EFF_ALEN(int value)
        {
            return (EFF_APOS(value) + EFF_REM(value));
        }
        /// <summary>
        /// map span for a sequence of bytes
        /// </summary>
        /// <param name="position"></param>
        /// <param name="length"></param>
        /// <returns></returns>
        public int EFF_SPAN_ALEN(int position, int length)
        {
            return (EFF_APOS((position) + (length) - 1) - EFF_APOS(position) + 1);
        }
        public void MarkAll()
        {
            var count = _map.Length;
            var i = 0;
            while(count-->0)
            {
                _map[i++] = 1;
            }
            _count = _map.Length;
        }
        public byte[] GetBytes()
        {
            return _map;
        }
        /// <summary>
        /// Scaling factor for the effector map used to skip some of the more
        /// expensive deterministic steps.The actual divisor is set to
        /// 2^EFF_MAP_SCALE2 bytes
        /// </summary>
        public int ScalingFactor { get; set; }
        /// <summary>
        /// Maximum effector density past which everything is just fuzzed
        /// unconditionally(%)
        /// </summary>
        public int MaxDensity { get; set; }
        /// <summary>
        /// Minimum input file length at which the effector logic kicks in
        /// </summary>
        public int MinimumInputFileLength { get; set; }

        public byte this[int position]
        {
            get
            {
                return _map[EFF_APOS(position)];
            }
            set
            {
                _map[EFF_APOS(position)] = value;
                _count += value != 0 ? 1 : 0;
            }
        }
        public bool HasNoEffect(int position)
        {
            return _map[EFF_APOS(position)] == 0;
        }
        public bool HasNoEffect(int position, int length)
        {
            int from = EFF_APOS(position);
            int count = EFF_SPAN_ALEN(position, length);
            while( count-- > 0)
            {
                if ( _map[from++] != 0)
                {
                    return false;
                }
            }
            return true;
        }
        public bool IsMaxDensity
        {
            get
            {
                return _count != _map.Length && _count * 100 / _map.Length > MaxDensity;
            }
        }
        public int Count
        {
            get
            {
                return _count;
            }
        }
        public int Length
        {
            get
            {
                return _map.Length;
            }
        }
        protected void Dispose(bool dispositing)
        {
            if ( dispositing )
            {
                _map = null;
            }
        }
        public void Dispose()
        {
            GC.SuppressFinalize(this);
            Dispose(true);
        }
    }
}
