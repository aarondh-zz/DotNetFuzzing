using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotNetFuzzing.Internal.Models
{
    public class ByteStream : Stream
    {
        public const int BitsPerByte = 8;
        public const int BitsPerInt16 = BitsPerByte * sizeof(Int16);
        public const int BitsPerInt32 = BitsPerByte * sizeof(Int32);
        private const int DefaultMinimumCapacityGrowth = sizeof(Int32);
        private long _length;
        private long _position;
        private UInt32[] _buffer;
        public ByteStream( long capacity = 0)
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
            unsafe
            {
                fixed (byte* inp = &buffer[offset])
                {
                    byte* inBytep = inp;
                    fixed (UInt32* uint32p = &_buffer[0])
                    {
                        byte* bytep = (byte*)uint32p + _position;
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
            var actualLength = _length / sizeof(UInt32);
            if (_length % sizeof(UInt32) != 0 )
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
        public override void Write(byte[] buffer, int offset, int count)
        {
            if (_position + count > _length)
            {
                SetLength(_position + count);
            }
            unsafe
            {
                fixed (UInt32* uint32p = &_buffer[0])
                {
                    byte* bytep = (byte*)uint32p + _position;
                    _position += count;
                    while (count-- > 0)
                    {
                        *(bytep++) = buffer[offset++];
                    }
                }
            }
        }
        public void WriteBytes(ByteStream source, long position, int count)
        {
            if (_position + count > _length)
            {
                SetLength(_position + count);
            }
            unsafe
            {
                long maxInLength = source._length;
                fixed (UInt32* inp = &source._buffer[0])
                {
                    byte* byteinp = (byte*)inp + position;
                    fixed (UInt32* outp = &_buffer[0])
                    {
                        byte* byteoutp = (byte*)outp + _position;
                        _position += count;
                        while (count-- > 0)
                        {
                            if (position++ < maxInLength)
                            {
                                *(byteoutp++) = *(byteinp++);
                            }
                            else
                            {
                                *(byteoutp++) = 0;
                            }
                        }
                    }
                }
            }
        }
        public void Write(UInt32[] buffer, int offset, int count)
        {
            if (_position + count * sizeof(UInt32) >= _length)
            {
                SetLength(_position + count * sizeof(UInt32));
            }
            if (_position % sizeof(UInt32) == 0)
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
            else
            {
                //writing on a byte boundary
                unsafe
                {
                    int byteCount = count * sizeof(UInt32);
                    fixed (UInt32* inp = &buffer[offset])
                    {
                        byte* inbytep = (byte*)inp;
                        fixed (UInt32* uint32p = &_buffer[0])
                        {
                            byte* bytep = (byte*)uint32p + _position;
                            _position += byteCount;
                            while (byteCount-- > 0)
                            {
                                *(bytep++) = *(inbytep++);
                            }
                        }
                    }
                }
            }
        }
        public void Write(UInt16[] buffer, int offset, int count)
        {
            var byteCount = count * sizeof(UInt16);
            if (_position + byteCount > _length)
            {
                SetLength(_position + byteCount);
            }
            unsafe
            {
                fixed (UInt16* inp = &buffer[offset])
                {
                    byte* inbytep = (byte*)inp;
                    fixed (UInt32* uint32p = &_buffer[0])
                    {
                        byte* bytep = (byte*)uint32p + _position;
                        _position += byteCount;
                        while (byteCount-- > 0)
                        {
                            *(bytep++) = *(inbytep++);
                        }
                    }
                }
            }
        }
        public void Write(byte value, int count)
        {
            if (_position + count > _length)
            {
                SetLength(_position + count);
            }
            unsafe
            {
                fixed (UInt32* uint32p = &_buffer[0])
                {
                    byte* bytep = (byte*)uint32p + _position;
                    _position += count;
                    while (count-- > 0)
                    {
                        *(bytep++) = value;
                    }
                }
            }
        }
        public void Write(UInt16 value, int count)
        {
            int byteCount = count * sizeof(UInt16);
            if (_position + byteCount > _length)
            {
                SetLength(_position + byteCount);
            }
            unsafe
            {
                fixed (UInt32* uint32p = &_buffer[0])
                {
                    UInt16* uint16 = (UInt16*)uint32p + _position;
                    _position += byteCount;
                    while (byteCount-- > 0)
                    {
                        *(uint16++) = value;
                    }
                }
            }
        }
        public bool Equal(byte[] values, long position, int offset, int count)
        {
            if (position + count >= _length)
            {
                return false;
            }
            unsafe
            {
                fixed (UInt32* uint32p = &_buffer[0])
                {
                    byte* pointer = (byte*)uint32p + position;
                    while (count-- > 0)
                    {
                        if (*(pointer++) != values[offset++])
                        {
                            return false;
                        }
                    }
                }

                return true;
            }
        }
        public void Write(UInt32 value, int count)
        {
            int byteCount = count * sizeof(UInt32);
            if (_position + byteCount > _length)
            {
                SetLength(_position + byteCount);
            }
            unsafe
            {
                fixed (UInt32* uint32p = &_buffer[0])
                {
                    UInt32* uintp = (UInt32*)uint32p + _position;
                    _position += byteCount;
                    while (byteCount-- > 0)
                    {
                        *(uintp++) = value;
                    }
                }
            }
        }
        #region Bit operations
        public void SetBit(bool bit, long position)
        {
            var length = position == 0 ? 1 : position / BitsPerByte + (position % BitsPerByte == 0 ? 0 : 1);
            if (length >= _length)
            {
                SetLength(length);
            }
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

        public bool GetBit(long position)
        {
            var length = position  == 0 ? 1 : position / BitsPerByte + (position % BitsPerByte == 0 ? 0 : 1);
            if (length >= _length)
            {
                return false;
            }
            else
            {
                int intOffset = (int)(position / BitsPerInt32);
                int bitOffset = (int)(position % BitsPerInt32);
                _position++;
                return (_buffer[intOffset] & ~(0x80000000 >> bitOffset)) != 0;
            }
        }
        public void FlipBit(long bitToFlip)
        {
            int byteIndex = (int)(bitToFlip / BitsPerByte);
            if (byteIndex <= _length)
            {
                SetLength(byteIndex);
            }
            int intOffset = (int)(byteIndex * sizeof(UInt32));
            int bitOffset = (int)(bitToFlip % BitsPerInt32);
            _buffer[intOffset] |= (_buffer[intOffset] & ~(0x80000000 >> bitOffset));
        }
#endregion
        public new byte ReadByte()
        {
            if (_position <= _length)
            {
                unsafe
                {
                    fixed (UInt32* pointer = &_buffer[0])
                    {
                        return *(((byte*)pointer) + _position++);
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
                int byteIndex = (int)(_position * sizeof(UInt16));
                unsafe
                {
                    fixed (UInt32* pointer = &_buffer[0])
                    {
                        _position += sizeof(UInt16);
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
                int byteIndex = (int)(_position * sizeof(UInt32));
                unsafe
                {
                    fixed (UInt32* pointer = &_buffer[0])
                    {
                        _position += sizeof(UInt32);
                        return *(((UInt32*)pointer) + byteIndex);
                    }
                }
            }
            else
            {
                return 0;
            }
        }

        #region Xor
        public void Xor(byte value)
        {
            unsafe
            {
                fixed (UInt32* uint32p = &_buffer[0])
                {
                    byte* pointer = (byte*)uint32p + _position;
                    *pointer ^= value;
                }
            }

        }
        public void Xor(UInt16 value)
        {
            unsafe
            {
                fixed (UInt32* uint32p = &_buffer[0])
                {
                    UInt16* pointer = (UInt16*)uint32p + _position;
                    *pointer ^= value;
                }
            }
        }
        public void Xor(UInt32 value)
        {
            unsafe
            {
                fixed (UInt32* uint32p = &_buffer[0])
                {
                    UInt32* pointer = (UInt32*)uint32p + _position;
                    *pointer ^= value;
                }
            }
        }
        #endregion

        #region Add
        public void Add(byte value)
        {
            unsafe
            {
                fixed (UInt32* uint32p = &_buffer[0])
                {
                    UInt32* pointer = (UInt32*)uint32p + _position;
                    *pointer += value;
                }
            }
        }
        public void Add(UInt16 value)
        {
            unsafe
            {
                fixed (UInt32* uint32p = &_buffer[0])
                {
                    UInt16* pointer = (UInt16*)uint32p + _position;
                    *pointer += value;
                }
            }
        }
        public void Add(UInt32 value)
        {
            unsafe
            {
                fixed (UInt32* uint32p = &_buffer[0])
                {
                    UInt32* pointer = (UInt32*)uint32p + _position;
                    *pointer += value;
                }
            }
        }
        #endregion

        #region Substract
        public void Substract(byte value)
        {
            unsafe
            {
                fixed (UInt32* uint32p = &_buffer[0])
                {
                    byte* pointer = (byte*)uint32p + _position;
                    *pointer -= value;
                }
            }
        }
        public void Substract(UInt16 value)
        {
            unsafe
            {
                fixed (UInt32* uint32p = &_buffer[0])
                {
                    UInt16* pointer = (UInt16*)uint32p + _position;
                    *pointer -= value;
                }
            }
        }
        public void Substract(UInt32 value)
        {
            unsafe
            {
                fixed (UInt32* uint32p = &_buffer[0])
                {
                    UInt32* pointer = (UInt32*)uint32p + _position;
                    *pointer -= value;
                }
            }
        }
        #endregion

        #region And
        public void And(byte value)
        {
            unsafe
            {
                fixed (UInt32* uint32p = &_buffer[0])
                {
                    byte* pointer = (byte*)uint32p + _position;
                    *pointer &= value;
                }
            }
        }
        public void And(UInt16 value)
        {
            unsafe
            {
                fixed (UInt32* uint32p = &_buffer[0])
                {
                    UInt16* pointer = (UInt16*)uint32p + _position;
                    *pointer &= value;
                }
            }
        }
        public void And(UInt32 value)
        {
            unsafe
            {
                fixed (UInt32* uint32p = &_buffer[0])
                {
                    UInt32* pointer = (UInt32*)uint32p + _position;
                    *pointer &= value;
                }
            }
        }
        #endregion

        #region Func
        public void Func(Func<byte,byte> func)
        {
            unsafe
            {
                fixed (UInt32* uint32p = &_buffer[0])
                {
                    byte* pointer = (byte*)uint32p + _position;
                    *pointer = func(*pointer);
                }
            }
        }
        public void Func(Func<UInt16, UInt16> func)
        {
            unsafe
            {
                fixed (UInt32* uint32p = &_buffer[0])
                {
                    UInt16* pointer = (UInt16*)uint32p + _position;
                    *pointer = func(*pointer);
                }
            }
        }
        public void Func(Func<UInt32, UInt32> func)
        {
            unsafe
            {
                fixed (UInt32* uint32p = &_buffer[0])
                {
                    UInt32* pointer = (UInt32*)uint32p + _position;
                    *pointer = func(*pointer);
                }
            }
        }
        #endregion

        #region Or
        public void Or(byte value)
        {
            unsafe
            {
                fixed (UInt32* uint32p = &_buffer[0])
                {
                    byte* pointer = (byte*)uint32p + _position;
                    *pointer |= value;
                }
            }
        }
        public void Or(UInt16 value)
        {
            unsafe
            {
                fixed (UInt32* uint32p = &_buffer[0])
                {
                    UInt16* pointer = (UInt16*)uint32p + _position;
                    *pointer |= value;
                }
            }
        }
        public void Or(UInt32 value)
        {
            unsafe
            {
                fixed (UInt32* uint32p = &_buffer[0])
                {
                    UInt32* pointer = (UInt32*)uint32p + _position;
                    *pointer |= value;
                }
            }
        }
        #endregion
        public byte[] GetBytes()
        {
            byte[] bytes = new byte[_length];
            var currentPosition = _position;
            Seek(0L, SeekOrigin.Begin);
            Read(bytes, 0, bytes.Length);
            Seek(currentPosition, SeekOrigin.Begin);
            return bytes;
        }
    }
}
