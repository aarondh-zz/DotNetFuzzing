using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotNetFuzzing.Internal.Models
{
    public class TraceBits : ByteStream
    {
        public TraceBits(int capacity = 0) : base(capacity) { }
        public TraceBits(byte[] bytes) : base(bytes) { }
        private static readonly byte[] _simplifyLookup = new byte[256];
        static TraceBits()
        {
            _simplifyLookup[0] = 0x01;
            for (int i = 1; i < _simplifyLookup.Length; i++)
            {
                _simplifyLookup[i] = 0x80;
            }
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

            NewBitTypes ret = NewBitTypes.NoNewBits;
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
                                    if (ret < NewBitTypes.NewTuple)
                                    {
                                        byte* cur = (byte*)currentPtr;
                                        byte* vir = (byte*)virginPtr;

                                        if ((cur[0] != 0 && vir[0] == 0xff) || (cur[1] != 0 && vir[1] == 0xff) ||
                                            (cur[2] != 0 && vir[2] == 0xff) || (cur[3] != 0 && vir[3] == 0xff) ||
                                            (cur[4] != 0 && vir[4] == 0xff) || (cur[5] != 0 && vir[5] == 0xff) ||
                                            (cur[6] != 0 && vir[6] == 0xff) || (cur[7] != 0 && vir[7] == 0xff)) ret = NewBitTypes.NewTuple;
                                        else ret = NewBitTypes.HitCount;
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
                                    if (ret < NewBitTypes.NewTuple)
                                    {
                                        byte* cur = (byte*)currentPtr;
                                        byte* vir = (byte*)virginPtr;

                                        if ((cur[0] != 0 && vir[0] == 0xff) || (cur[1] != 0 && vir[1] == 0xff) ||
                                            (cur[2] != 0 && vir[2] == 0xff) || (cur[3] != 0 && vir[3] == 0xff)) ret = NewBitTypes.NewTuple;
                                        else ret = NewBitTypes.HitCount;
                                    }
                                }
                                *virginPtr &= ~*currentPtr;
                            }
                        }
                    }
                }
            }
            return ret;
        }
    }
}
