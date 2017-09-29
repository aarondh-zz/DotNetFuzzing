using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotNetFuzzing.Fuzzing.Internal.Models
{
    public class TraceBits : ByteStream
    {
        public TraceBits(int capacity = 0) : base(capacity) { }
        public TraceBits(byte[] bytes) : base(bytes) { }
        private static byte[] _simplifyLookup;
        private static byte[] _countClassLookup8;
        private static UInt16[] _countClassLookup16;
        private static void InitCountClassLookup8()
        {
            _countClassLookup8 = new byte[256];
            for (int i = 0; i < _countClassLookup8.Length; i++)
            {
                byte value;
                switch (i)
                {
                    case 0:
                        value = 0;
                        break;
                    case 1:
                        value = 1;
                        break;
                    case 2:
                        value = 2;
                        break;
                    case 3:
                        value = 4;
                        break;
                    case 4:
                    case 5:
                    case 6:
                    case 7:
                        value = 8;
                        break;
                    case 8:
                    case 9:
                    case 10:
                    case 11:
                    case 12:
                    case 13:
                    case 14:
                    case 15:
                        value = 16;
                        break;
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
                    case 26:
                    case 27:
                    case 28:
                    case 29:
                    case 30:
                    case 31:
                        value = 32;
                        break;
                    default:
                        value = i < 128 ? (byte)64 : (byte)128;
                        break;
                }
                _countClassLookup8[i] = value;
            }
        }

        private static void InitCountClassLookup16()
        {
            _countClassLookup16 = new UInt16[65536];

            for (int b1 = 0; b1 < 256; b1++)
            {
                for (int b2 = 0; b2 < 256; b2++)
                {
                    _countClassLookup16[(b1 << 8) + b2] = (UInt16)((_countClassLookup16[b1] << 8) | _countClassLookup16[b2]);
                }
            }

        }
        private static void InitSimplifyLookup()
        {
            _simplifyLookup = new byte[256];
            _simplifyLookup[0] = 0x01;
            for (int i = 1; i < _simplifyLookup.Length; i++)
            {
                _simplifyLookup[i] = 0x80;
            }
        }
        static TraceBits()
        {
            InitSimplifyLookup();
            InitCountClassLookup8();
            InitCountClassLookup16();
        }
        /// <summary>
        /// Destructively simplify trace by eliminating hit count information
        /// and replacing it with 0x80 or 0x01 depending on whether the tuple
        /// is hit or not.Called on every new crash or timeout, should be
        /// reasonably fast.
        /// </summary>
        /// <param name="traceBits"></param>
        public void SimplifyTrace()
        {

            long i = this.Length;
            unsafe {
                fixed (byte* bytePointer = &_bytes[0])
                {
                    if (IntPtr.Size == 8)
                    {
                        i = i << 3;
                        UInt64* pointer = (UInt64*)bytePointer;
                        while (i-- > 0)
                        {
                            /* Optimize for sparse bitmaps. */

                            if (*pointer != 0)
                            {

                                byte* mem8 = (byte*)pointer;

                                mem8[0] = _simplifyLookup[mem8[0]];
                                mem8[1] = _simplifyLookup[mem8[1]];
                                mem8[2] = _simplifyLookup[mem8[2]];
                                mem8[3] = _simplifyLookup[mem8[3]];
                                mem8[4] = _simplifyLookup[mem8[4]];
                                mem8[5] = _simplifyLookup[mem8[5]];
                                mem8[6] = _simplifyLookup[mem8[6]];
                                mem8[7] = _simplifyLookup[mem8[7]];

                            }
                            else
                            {
                                *pointer = 0x0101010101010101;
                            }

                            pointer++;

                        }
                    }
                    else
                    {
                        i = i << 2;
                        UInt32* pointer = (UInt32*)bytePointer;
                        while (i-- > 0)
                        {
                            /* Optimize for sparse bitmaps. */

                            if (*pointer != 0)
                            {

                                byte* mem8 = (byte*)pointer;

                                mem8[0] = _simplifyLookup[mem8[0]];
                                mem8[1] = _simplifyLookup[mem8[1]];
                                mem8[2] = _simplifyLookup[mem8[2]];
                                mem8[3] = _simplifyLookup[mem8[3]];

                            }
                            else
                            {
                                *pointer = 0x01010101;
                            }

                            pointer++;

                        }
                    }
                }
            }
        }

        /// <summary>
        ///    Destructively classify execution counts in a trace. This is used as a
        ///    preprocessing step for any newly acquired traces.Called on every exec,
        ///    must be fast.
        /// </summary>
        public void ClassifyCounts()
        {
            unsafe
            {
                fixed( byte *fixedBytePointer = &_bytes[0])
                {
                    byte* bytePointer = fixedBytePointer;
                    if (IntPtr.Size == 8)
                    {
                        int i = (int)(_length >> 3);

                        while (i-- > 0)
                        {

                            /* Optimize for sparse bitmaps. */

                            if (*bytePointer != 0)
                            {

                                UInt16* mem16 = (UInt16*)bytePointer;

                                mem16[0] = _countClassLookup16[mem16[0]];
                                mem16[1] = _countClassLookup16[mem16[1]];
                                mem16[2] = _countClassLookup16[mem16[2]];
                                mem16[3] = _countClassLookup16[mem16[3]];

                            }

                            bytePointer++;

                        }

                    }
                    else
                    {
                        int i = (int)(_length >> 2);

                        while (i-- > 0)
                        {

                            /* Optimize for sparse bitmaps. */

                            if (*bytePointer != 0)
                            {

                                UInt16* mem16 = (UInt16*)bytePointer;

                                mem16[0] = _countClassLookup16[mem16[0]];
                                mem16[1] = _countClassLookup16[mem16[1]];

                            }

                            bytePointer++;

                        }

                    }
                }
            }
        }
        public int CountBytes()
        {
            long i = _length;
            long count = 0;

            while (i-- > 0)
            {
                if (_bytes[i] != 0)
                {
                    count++;
                }
            }

            return (int)count;
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
        /// <param name="trace_bits"></param>
        /// <returns></returns>
        public NewBitTypes HasNewBits(TraceBits traceBits)
        {
            long i = traceBits.Length;

            NewBitTypes result = NewBitTypes.NoNewBits;
            unsafe
            {
                fixed (byte* thisPtr = &_bytes[0])
                {
                    fixed (byte* thatPtr = &traceBits._bytes[0])
                    {
                        if (IntPtr.Size == 8)
                        {
                            i = i >> 3;
                            UInt64* virginPtr = (UInt64*)thisPtr;
                            UInt64* currentPtr = (UInt64*)thatPtr;
                            while (i-- > 0)
                            {
                                if (*currentPtr != 0 && (*currentPtr & *virginPtr) > 0)
                                {
                                    if (result < NewBitTypes.NewTuple)
                                    {
                                        byte* cur = (byte*)currentPtr;
                                        byte* vir = (byte*)virginPtr;

                                        if ((cur[0] != 0 && vir[0] == 0xff) || (cur[1] != 0 && vir[1] == 0xff) ||
                                            (cur[2] != 0 && vir[2] == 0xff) || (cur[3] != 0 && vir[3] == 0xff) ||
                                            (cur[4] != 0 && vir[4] == 0xff) || (cur[5] != 0 && vir[5] == 0xff) ||
                                            (cur[6] != 0 && vir[6] == 0xff) || (cur[7] != 0 && vir[7] == 0xff)) result = NewBitTypes.NewTuple;
                                        else result = NewBitTypes.HitCount;
                                    }
                                }
                                *virginPtr &= ~*currentPtr;
                            }
                        }
                        else
                        {
                            UInt32* virginPtr = (UInt32*)thisPtr;
                            UInt32* currentPtr = (UInt32*)thatPtr;
                            i = i >> 2;
                            while (i-- > 0)
                            {
                                if (*currentPtr != 0 && (*currentPtr & *virginPtr) > 0)
                                {
                                    if (result < NewBitTypes.NewTuple)
                                    {
                                        byte* cur = (byte*)currentPtr;
                                        byte* vir = (byte*)virginPtr;

                                        if ((cur[0] != 0 && vir[0] == 0xff) || (cur[1] != 0 && vir[1] == 0xff) ||
                                            (cur[2] != 0 && vir[2] == 0xff) || (cur[3] != 0 && vir[3] == 0xff)) result = NewBitTypes.NewTuple;
                                        else result = NewBitTypes.HitCount;
                                    }
                                }
                                *virginPtr &= ~*currentPtr;
                            }
                        }
                    }
                }
            }
            return result;
        }
    }
}
