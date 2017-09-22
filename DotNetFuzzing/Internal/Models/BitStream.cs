using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotNetFuzzing.Internal.Models
{
    public class BitStream : Stream
    {
        public const int BitsPerByte = 8;
        public const int BitsPerInt16 = BitsPerByte * sizeof(Int16);
        public const int BitsPerInt32 = BitsPerByte * sizeof(Int32);
        private const int DefaultMinimumCapacityGrowth = BitsPerInt32;
        private long _length;
        private long _position;
        private UInt32[] _buffer;
        public BitStream( long capacity = 0)
        {
            MinimumCapacityGrowth = DefaultMinimumCapacityGrowth;
            SetLength(capacity * BitsPerInt32);
        }
        public override bool CanRead => true;

        public override bool CanSeek => true;

        public override bool CanWrite => true;

        protected override void Dispose(bool disposing)
        {
            if ( disposing )
            {
                _buffer = null;
                _length = 0;
                _position = 0;
            }
        }

        public override long Length {
            get
            {
                return _length;
            }
        }

        public int MinimumCapacityGrowth { get; set; }

        public override long Position
        {
            get
            {
                return _position;
            }
            set
            {
                _position = value;
                if ( _position < 0)
                {
                    _position = 0;
                }
                if ( _position >= _length)
                {
                    SetLength(_position);
                }
            }
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_position % 8 == 0)
            {
                //reading on a byte boundary
                unsafe
                {
                    fixed (byte* inp = &buffer[offset])
                    {
                        byte* inBytep = inp;
                        fixed (UInt32* uint32p = &_buffer[0])
                        {
                            byte* bytep = (byte*)uint32p + _position / BitsPerByte;
                            _position += count;
                            while (count-- > 0)
                            {
                                *(bytep++) = *(inBytep++);
                            }
                        }
                    }
                }
                return count;
            }
            else
            {
                throw new Exception("Not positioned on a byte boundary");
            }
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            switch( origin )
            {
                case SeekOrigin.Begin:
                    _position = offset;
                    break;
                case SeekOrigin.Current:
                    _position += offset;
                    break;
                case SeekOrigin.End:
                    _position = _length - offset;
                    break;
            }
            if (_position < 0)
            {
                _position = 0;
            }
            if (_position >= _length)
            {
                SetLength(_position);
            }
            return _position;
        }

        public override void SetLength(long value)
        {
            _length = value;
            var actualLength = _length / BitsPerInt32;
            if ( actualLength == 0 )
            {
                actualLength++;
            }
            if (_buffer == null)
            {
                _buffer = new UInt32[actualLength];
            }
            else if (actualLength <= _buffer.Length)
            {
                return; //shrinking... 
            }
            else
            {
                var origBuffer = _buffer;
                _buffer = new UInt32[actualLength];
                Array.Copy(origBuffer, _buffer, origBuffer.Length);
            }
        }
        public void Grow()
        {
            SetLength( _length + MinimumCapacityGrowth);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (_position + count * BitsPerByte > _length)
            {
                SetLength(_position + count * BitsPerByte);
            }
            if (_position % BitsPerByte == 0)
            {
                //writing on a byte boundary
                unsafe
                {
                    fixed (UInt32* uint32p = &_buffer[0])
                    {
                        byte* bytep = (byte*)uint32p + _position / BitsPerByte;
                        while (count-- > 0)
                        {
                            *(bytep++) = buffer[offset++];
                            _position++;
                        }
                    }
                }
            }
            else
            {
                throw new Exception("Not positioned on a byte boundary");
            }
        }
        public void WriteBytes(BitStream source, int offset, int count)
        {
            if (_position + count * BitsPerByte > _length)
            {
                SetLength(_position + count * BitsPerByte);
            }
            if (_position % BitsPerByte == 0)
            {
                //writing on a byte boundary
                unsafe
                {
                    fixed (UInt32* inp = &source._buffer[0])
                    {
                        byte* byteinp = (byte*)inp + offset;
                        fixed (UInt32* outp = &_buffer[0])
                        {
                            byte* byteoutp = (byte*)outp + _position / BitsPerByte;
                            while (count-- > 0)
                            {
                                *(byteoutp++) = *(byteinp++);
                                _position++;
                            }
                        }
                    }
                }
            }
            else
            {
                throw new Exception("Not positioned on a byte boundary");
            }
        }
        public void Write(UInt32[] buffer, int offset, int count)
        {
            if (_position + BitsPerInt32 > _length)
            {
                SetLength(BitsPerInt32 + BitsPerInt32);
            }
            if (_position % BitsPerInt32 == 0)
            {
                //writing on a int32 boundary
                var i = _position / BitsPerInt32;
                var j = 0;
                _position += i;
                while (count-- > 0)
                {
                    _buffer[i++] = buffer[j++];
                }
            }
            else if (_position % BitsPerByte == 0)
            {
                //writing on a byte boundary
                var byteCount = count * BitsPerInt32;
                unsafe
                {
                    fixed (UInt32* inp = &buffer[offset])
                    {
                        byte* inbytep = (byte*)inp;
                        fixed (UInt32* uint32p = &_buffer[0])
                        {
                            byte* bytep = (byte*)uint32p + _position / BitsPerByte;
                            _position += byteCount * BitsPerByte;
                            while (byteCount-- > 0)
                            {
                                *(bytep++) = *(inbytep++);
                            }
                        }
                    }
                }
            }
            else
            {
                throw new Exception("Not positioned on a byte boundary");
            }
        }
        public void Write(UInt16[] buffer, int offset, int count)
        {
            if (_position + BitsPerInt16 * count > _length)
            {
                SetLength(BitsPerInt32 + BitsPerInt32);
            }
            if (_position % BitsPerByte == 0)
            {
                //writing on a byte boundary
                var byteCount = count * BitsPerInt16;
                unsafe
                {
                    fixed (UInt16* inp = &buffer[offset])
                    {
                        byte* inbytep = (byte*)inp;
                        fixed (UInt32* uint32p = &_buffer[0])
                        {
                            byte* bytep = (byte*)uint32p + _position / BitsPerByte;
                            _position += byteCount * BitsPerByte;
                            while (byteCount-- > 0)
                            {
                                *(bytep++) = *(inbytep++);
                            }
                        }
                    }
                }
            }
            else
            {
                throw new Exception("Not positioned on a byte boundary");
            }
        }
        public void Write(byte value, int count)
        {
            if (_position + count * BitsPerByte > _length)
            {
                SetLength(_position + count * BitsPerByte);
            }
            if (_position % BitsPerByte == 0)
            {
                //writing on a byte boundary
                unsafe
                {
                    fixed (UInt32* uint32p = &_buffer[0])
                    {
                        byte* bytep = (byte*)uint32p + _position / BitsPerByte;
                        while (count-- > 0)
                        {
                            *(bytep++) = value;
                            _position++;
                        }
                    }
                }
            }
            else
            {
                throw new Exception("Not positioned on a byte boundary");
            }
        }
        public void Write(UInt16 value, int count)
        {
            if (_position + count * BitsPerByte > _length)
            {
                SetLength(_position + count * BitsPerByte);
            }
            if (_position % BitsPerByte == 0)
            {
                //writing on a byte boundary
                unsafe
                {
                    fixed (UInt32* uint32p = &_buffer[0])
                    {
                        UInt16* uint16 = (UInt16*)uint32p + _position / BitsPerByte;
                        while (count-- > 0)
                        {
                            *(uint16++) = value;
                            _position++;
                        }
                    }
                }
            }
            else
            {
                throw new Exception("Not positioned on a byte boundary");
            }
        }
        public void Write(UInt32 value, int count)
        {
            if (_position + count * BitsPerByte > _length)
            {
                SetLength(_position + count * BitsPerByte);
            }
            if (_position % BitsPerByte == 0)
            {
                //writing on a byte boundary
                unsafe
                {
                    fixed (UInt32* uint32p = &_buffer[0])
                    {
                        UInt32* uintp = (UInt32*)uint32p + _position / BitsPerByte;
                        while (count-- > 0)
                        {
                            *(uintp++) = value;
                            _position++;
                        }
                    }
                }
            }
            else
            {
                throw new Exception("Not positioned on a byte boundary");
            }
        }
        public void Write(bool[] bits, int offset, int count)
        {
            while ( count-- > 0 )
            {
                Write(bits[offset++]);
            }
        }
        public void Write(bool bit)
        {

            int intOffset = (int)(_position / BitsPerInt32);
            int bitOffset = (int)(_position % BitsPerInt32);
            if (bit)
            {
                _buffer[intOffset] |= 0x80000000 >> bitOffset;
            }
            else
            {
                _buffer[intOffset] &= ~(0x80000000 >> bitOffset);
            }
            _position++;
            if (_position >= _length)
            {
                Grow();
            }
        }
        public int Read(bool[] bits, int offset, int count)
        {
            var bitCount = count;
            while (bitCount-- > 0)
            {
                bits[offset++] = Read();
            }
            return count;
        }
        public bool Read()
        {
            if (_position <= _length)
            {
                int intOffset = (int)(_position / BitsPerInt32);
                int bitOffset = (int)(_position % BitsPerInt32);
                _position++;
                return (_buffer[intOffset] & ~(0x80000000 >> bitOffset)) != 0;
            }
            else
            {
                return false;
            }
        }
        public new byte ReadByte()
        {
            if (_position <= _length)
            {
                int byteIndex = (int)(_position / BitsPerByte);
                unsafe
                {
                    fixed (UInt32* pointer = &_buffer[0])
                    {
                        return *(((byte*)pointer) + byteIndex);
                    }
                }
            }
            else
            {
                return 0;
            }
        }
        public UInt16 ReadInt16()
        {
            if (_position <= _length)
            {
                int byteIndex = (int)(_position / BitsPerByte);
                unsafe
                {
                    fixed (UInt32* pointer = &_buffer[0])
                    {
                        return *(((UInt16*)pointer) + byteIndex);
                    }
                }
            }
            else
            {
                return 0;
            }
        }
        public UInt32 ReadInt32()
        {
            if (_position <= _length)
            {
                int byteIndex = (int)(_position / BitsPerByte);
                unsafe
                {
                    fixed (UInt32* pointer = &_buffer[0])
                    {
                        return *(((UInt32*)pointer) + byteIndex);
                    }
                }
            }
            else
            {
                return 0;
            }
        }
        public void Write(bool bit, int position)
        {

            if (position < _length)
            {
                int intOffset = (int)(position / BitsPerInt32);
                int bitOffset = (int)(position % BitsPerInt32);
                if (bit)
                {
                    _buffer[intOffset] |= 0x80000000 >> bitOffset;
                }
                else
                {
                    _buffer[intOffset] &= ~(0x80000000 >> bitOffset);
                }
            }
            else
            {
                throw new IndexOutOfRangeException();
            }
        }
        public bool Read(int position)
        {
            if (position < _length )
            {
                int intOffset = (int)(position / BitsPerInt32);
                int bitOffset = (int)(position % BitsPerInt32);
                return (_buffer[intOffset] & ~(0x80000000 >> bitOffset)) != 0;
            }
            else
            {
                throw new IndexOutOfRangeException();
            }
        }
        public void FlipBit(int bitToFlip)
        {
            if (bitToFlip < _length)
            {
                SetLength(bitToFlip);
            }
            int intOffset = (int)(bitToFlip / BitsPerInt32);
            int bitOffset = (int)(bitToFlip % BitsPerInt32);
            _buffer[intOffset] |= (_buffer[intOffset] & ~(0x80000000 >> bitOffset));
        }
        #region Xor
        public void Xor(byte value)
        {
            if (_position % BitsPerByte == 0)
            {
                int byteIndex = (int)(_position / BitsPerByte);
                unsafe
                {
                    fixed (UInt32* uint32p = &_buffer[0])
                    {
                        byte* pointer = (byte*)uint32p + byteIndex;
                        *pointer ^= value;
                    }
                }
            }
            else
            {
                throw new Exception("Not positioned on a byte boundary");
            }

        }
        public void Xor(UInt16 value)
        {
            if (_position % BitsPerByte == 0)
            {
                int byteIndex = (int)(_position / BitsPerByte);
                unsafe
                {
                    fixed (UInt32* uint32p = &_buffer[0])
                    {
                        UInt16* pointer = (UInt16*)uint32p + byteIndex;
                        *pointer ^= value;
                    }
                }
            }
            else
            {
                throw new Exception("Not positioned on a byte boundary");
            }

        }
        public void Xor(UInt32 value)
        {
            if (_position % BitsPerByte == 0)
            {
                int byteIndex = (int)(_position / BitsPerByte);
                unsafe
                {
                    fixed (UInt32* uint32p = &_buffer[0])
                    {
                        UInt32* pointer = (UInt32*)uint32p + byteIndex;
                        *pointer ^= value;
                    }
                }
            }
            else
            {
                throw new Exception("Not positioned on a byte boundary");
            }

        }
        #endregion
        #region Add
        public void Add(byte value)
        {
            if (_position % BitsPerByte == 0)
            {
                int byteIndex = (int)(_position / BitsPerByte);
                unsafe
                {
                    fixed (UInt32* uint32p = &_buffer[0])
                    {
                        byte* pointer = (byte*)uint32p + byteIndex;
                        *pointer += value;
                    }
                }
            }
            else
            {
                throw new Exception("Not positioned on a byte boundary");
            }

        }
        public void Add(UInt16 value)
        {
            if (_position % BitsPerByte == 0)
            {
                int byteIndex = (int)(_position / BitsPerByte);
                unsafe
                {
                    fixed (UInt32* uint32p = &_buffer[0])
                    {
                        UInt16* pointer = (UInt16*)uint32p + byteIndex;
                        *pointer += value;
                    }
                }
            }
            else
            {
                throw new Exception("Not positioned on a byte boundary");
            }

        }
        public void Add(UInt32 value)
        {
            if (_position % BitsPerByte == 0)
            {
                int byteIndex = (int)(_position / BitsPerByte);
                unsafe
                {
                    fixed (UInt32* uint32p = &_buffer[0])
                    {
                        UInt32* pointer = (UInt32*)uint32p + byteIndex;
                        *pointer += value;
                    }
                }
            }
            else
            {
                throw new Exception("Not positioned on a byte boundary");
            }

        }
        #endregion
        #region Substract
        public void Substract(byte value)
        {
            if (_position % BitsPerByte == 0)
            {
                int byteIndex = (int)(_position / BitsPerByte);
                unsafe
                {
                    fixed (UInt32* uint32p = &_buffer[0])
                    {
                        byte* pointer = (byte*)uint32p + byteIndex;
                        *pointer -= value;
                    }
                }
            }
            else
            {
                throw new Exception("Not positioned on a byte boundary");
            }

        }
        public void Substract(UInt16 value)
        {
            if (_position % BitsPerByte == 0)
            {
                int byteIndex = (int)(_position / BitsPerByte);
                unsafe
                {
                    fixed (UInt32* uint32p = &_buffer[0])
                    {
                        UInt16* pointer = (UInt16*)uint32p + byteIndex;
                        *pointer -= value;
                    }
                }
            }
            else
            {
                throw new Exception("Not positioned on a byte boundary");
            }

        }
        public void Substract(UInt32 value)
        {
            if (_position % BitsPerByte == 0)
            {
                int byteIndex = (int)(_position / BitsPerByte);
                unsafe
                {
                    fixed (UInt32* uint32p = &_buffer[0])
                    {
                        UInt32* pointer = (UInt32*)uint32p + byteIndex;
                        *pointer -= value;
                    }
                }
            }
            else
            {
                throw new Exception("Not positioned on a byte boundary");
            }

        }
        #endregion
        #region And
        public void And(byte value)
        {
            if (_position % BitsPerByte == 0)
            {
                int byteIndex = (int)(_position / BitsPerByte);
                unsafe
                {
                    fixed (UInt32* uint32p = &_buffer[0])
                    {
                        byte* pointer = (byte*)uint32p + byteIndex;
                        *pointer &= value;
                    }
                }
            }
            else
            {
                throw new Exception("Not positioned on a byte boundary");
            }

        }
        public void And(UInt16 value)
        {
            if (_position % BitsPerByte == 0)
            {
                int byteIndex = (int)(_position / BitsPerByte);
                unsafe
                {
                    fixed (UInt32* uint32p = &_buffer[0])
                    {
                        UInt16* pointer = (UInt16*)uint32p + byteIndex;
                        *pointer &= value;
                    }
                }
            }
            else
            {
                throw new Exception("Not positioned on a byte boundary");
            }

        }
        public void And(UInt32 value)
        {
            if (_position % BitsPerByte == 0)
            {
                int byteIndex = (int)(_position / BitsPerByte);
                unsafe
                {
                    fixed (UInt32* uint32p = &_buffer[0])
                    {
                        UInt32* pointer = (UInt32*)uint32p + byteIndex;
                        *pointer &= value;
                    }
                }
            }
            else
            {
                throw new Exception("Not positioned on a byte boundary");
            }

        }
        #endregion
        #region Func
        public void Func(Func<byte,byte> func)
        {
            if (_position % BitsPerByte == 0)
            {
                int byteIndex = (int)(_position / BitsPerByte);
                unsafe
                {
                    fixed (UInt32* uint32p = &_buffer[0])
                    {
                        byte* pointer = (byte*)uint32p + byteIndex;
                        *pointer = func(*pointer);
                    }
                }
            }
            else
            {
                throw new Exception("Not positioned on a byte boundary");
            }

        }
        public void Func(Func<UInt16, UInt16> func)
        {
            if (_position % BitsPerByte == 0)
            {
                int byteIndex = (int)(_position / BitsPerByte);
                unsafe
                {
                    fixed (UInt32* uint32p = &_buffer[0])
                    {
                        UInt16* pointer = (UInt16*)uint32p + byteIndex;
                        *pointer = func(*pointer);
                    }
                }
            }
            else
            {
                throw new Exception("Not positioned on a byte boundary");
            }

        }
        public void Func(Func<UInt32, UInt32> func)
        {
            if (_position % BitsPerByte == 0)
            {
                int byteIndex = (int)(_position / BitsPerByte);
                unsafe
                {
                    fixed (UInt32* uint32p = &_buffer[0])
                    {
                        UInt32* pointer = (UInt32*)uint32p + byteIndex;
                        *pointer = func(*pointer);
                    }
                }
            }
            else
            {
                throw new Exception("Not positioned on a byte boundary");
            }

        }
        #endregion
        #region Or
        public void Or(byte value)
        {
            if (_position % BitsPerByte == 0)
            {
                int byteIndex = (int)(_position / BitsPerByte);
                unsafe
                {
                    fixed (UInt32* uint32p = &_buffer[0])
                    {
                        byte* pointer = (byte*)uint32p + byteIndex;
                        *pointer |= value;
                    }   
                }
                _position += BitsPerByte;
            }
            else
            {
                throw new Exception("Not positioned on a byte boundary");
            }

        }
        public void Or(UInt16 value)
        {
            if (_position % BitsPerByte == 0)
            {
                int byteIndex = (int)(_position / BitsPerByte);
                unsafe
                {
                    fixed (UInt32* uint32p = &_buffer[0])
                    {
                        UInt16* pointer = (UInt16*)uint32p + byteIndex;
                        *pointer |= value;
                    }
                }
                _position += BitsPerInt16;
            }
            else
            {
                throw new Exception("Not positioned on a byte boundary");
            }

        }
        public void Or(UInt32 value)
        {
            if (_position % BitsPerByte == 0)
            {
                int byteIndex = (int)(_position / BitsPerByte);
                unsafe
                {
                    fixed (UInt32* uint32p = &_buffer[0])
                    {
                        UInt32* pointer = (UInt32*)uint32p + byteIndex;
                        *pointer |= value;
                    }
                }
                _position += BitsPerInt32;
            }
            else
            {
                throw new Exception("Not positioned on a byte boundary");
            }

        }
        #endregion
        public long LengthInBytes
        {
            get
            {
                var lengthInBytes = _length / BitsPerByte;
                if ( _length % BitsPerByte != 0)
                {
                    lengthInBytes++;
                }
                return lengthInBytes;
            }
        }
        public byte[] GetBytes()
        {
            byte[] bytes = new byte[LengthInBytes];
            var currentPosition = _position;
            Seek(0L, SeekOrigin.Begin);
            Read(bytes, 0, bytes.Length);
            Seek(currentPosition, SeekOrigin.Begin);
            return bytes;
        }
    }
}
