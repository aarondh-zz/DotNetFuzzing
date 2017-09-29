using DotNetFuzzing.Utilities;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotNetFuzzing.Fuzzing.Internal.Models
{
    public class ByteStream : Stream
    {
        public const int BitsPerByte = 8;
        public const int BitsPerInt16 = BitsPerByte * sizeof(Int16);
        public const int BitsPerInt32 = BitsPerByte * sizeof(Int32);
        protected long _length;
        protected long _position;
        protected byte[] _bytes;
        public ByteStream(long capacity = 0)
        {
            SetLength(capacity);
            _length = 0;
            _position = 0;
        }
        public ByteStream(byte[] bytes)
        {
            if ( bytes != null )
            {
                SetLength(bytes.Length);
            }
            Array.Copy(bytes, _bytes, bytes.Length);
        }
        public override bool CanRead => true;

        public override bool CanSeek => true;

        public override bool CanWrite => true;

        protected override void Dispose(bool disposing)
        {
            if ( disposing )
            {
                _bytes = null;
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
                    SetLength(_position+1);
                }
            }
        }

        public override void Flush()
        {
        }
        public UInt32 Hash32()
        {
            return Hasher.Hash32(_bytes);
        }
        public byte this[long index]
        {
            get
            {
                if (index < 0)
                {
                    throw new ArgumentOutOfRangeException(nameof(index));
                }
                if ( index < _length)
                {
                    return _bytes[index];
                }
                else
                {
                    return 0;
                }
            }
            set
            {
                if ( index < 0 )
                {
                    throw new ArgumentOutOfRangeException(nameof(index));
                }
                if ( index >= _length)
                {
                    SetLength(index+1);
                }
                _bytes[index] = value;
            }
        }
        public override int Read(byte[] buffer, int offset, int count)
        {
            if ( buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }
            if (offset < 0 || offset >= buffer.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(offset));
            }
            if (count < 0 || offset + count > buffer.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(count));
            }
            if (_position + count > _bytes.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(count));
            }
            unsafe
            {
                fixed (byte* inp = &buffer[offset])
                {
                    byte* inBytep = inp;
                    fixed (byte* fixedBytePtr = &_bytes[0])
                    {
                        byte* bytep = fixedBytePtr + _position;
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
            if (_bytes == null)
            {
                _bytes = new byte[_length];
            }
            else if (_length <= _bytes.Length)
            {
                return; //shrinking... 
            }
            else
            {
                var origBuffer = _bytes;
                _bytes = new byte[_length];
                Array.Copy(origBuffer, _bytes, origBuffer.Length);
            }
        }
        public override void Write(byte[] buffer, int offset, int count)
        {
            if ( buffer == null )
            {
                throw new ArgumentNullException(nameof(buffer));
            }
            if (offset < 0 || offset >= buffer.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(offset));
            }
            if (count < 0 || offset + count > buffer.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(count));
            }
            if (_position + count > _length)
            {
                SetLength(_position + count);
            }
            while (count-- > 0)
            {
                _bytes[_position++] = buffer[offset++];
            }
        }
        public void WriteBytes(ByteStream source, long position, int count)
        {
            if (source == null)
            {
                throw new ArgumentNullException(nameof(source));
            }
            if ( count == 0)
            {
                return;
            }
            if (position < 0 || position >= source.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(position));
            }
            if (count < 0 || position + count > source._bytes.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(count));
            }
            if (_position + count > _bytes.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(count));
            }
            if (_position + count >= _length)
            {
                SetLength(_position + count);
            }
            unsafe
            {
                long maxInLength = source._length;
                fixed (byte* fixedSourcePtr = &source._bytes[0])
                {
                    byte* inp = fixedSourcePtr + position;
                    fixed (byte* fixedBytePtr = &_bytes[0])
                    {
                        byte* outp = fixedBytePtr + _position;
                        if (this == source && ((position >= _position && position < _position + count) || (position < _position && position + count >= _position)))
                        {
                            //source and destination are the same and the input bytes overlap the output bytes
                            //we need an intermediate buffer
                            byte[] temp = new byte[count];
                            fixed (byte* fixedTempPtr = &temp[0])
                            {
                                byte* pointer = fixedTempPtr;
                                var bytesToMove = count;
                                while (bytesToMove-- > 0)
                                {
                                    if (inp - fixedSourcePtr < maxInLength)
                                    {
                                        *(pointer++) = *(inp++);
                                    }
                                    else
                                    {
                                        *(pointer++) = 0;
                                    }
                                }
                                pointer = fixedTempPtr;
                                _position += count;
                                while (count-- > 0)
                                {
                                    *(outp++) = *(pointer++);
                                }
                            }
                            return;
                        }
                        _position += count;
                        while (count-- > 0)
                        {
                            if (position++ < maxInLength)
                            {
                                *(outp++) = *(inp++);
                            }
                            else
                            {
                                *(outp++) = 0;
                            }
                        }
                    }
                }
            }
        }
        public void Write(UInt32[] buffer, int offset, int count)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }
            if (offset < 0 || offset >= buffer.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(offset));
            }
            if (count < 0 || offset + count > buffer.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(count));
            }
            int byteCount = count * sizeof(UInt32);
            if (_position + byteCount >= _length)
            {
                SetLength(_position + byteCount);
            }
            unsafe
            {
                fixed (UInt32* inp = &buffer[offset])
                {
                    byte* inbytep = (byte*)inp;
                    fixed (byte* fixedBytePtr = &_bytes[0])
                    {
                        byte* bytep = fixedBytePtr + _position;
                        _position += byteCount;
                        while (byteCount-- > 0)
                        {
                            *(bytep++) = *(inbytep++);
                        }
                    }
                }
            }
        }
        public void Write(UInt16[] buffer, int offset, int count)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }
            if (offset < 0 || offset >= buffer.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(offset));
            }
            if (count < 0 || offset + count > buffer.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(count));
            }
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
                    fixed (byte* fixedBytePtr = &_bytes[0])
                    {
                        byte* bytep = fixedBytePtr + _position;
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
            if (count < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(count));
            }
            if (_position + count > _length)
            {
                SetLength(_position + count);
            }
            while (count-- > 0)
            {
                _bytes[_position++] = value;
            }
        }
        public void Write(UInt16 value, int count)
        {
            if (count < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(count));
            }
            int byteCount = count * sizeof(UInt16);
            if (_position + byteCount > _length)
            {
                SetLength(_position + byteCount);
            }
            unsafe
            {
                fixed (byte* fixedBytePtr = &_bytes[0])
                {
                    UInt16* uint16 = (UInt16*)(fixedBytePtr + _position);
                    _position += byteCount;
                    while (count-- > 0)
                    {
                        *(uint16++) = value;
                    }
                }
            }
        }
        public void Write(UInt32 value, int count)
        {
            if (count < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(count));
            }
            int byteCount = count * sizeof(UInt32);
            if (_position + byteCount > _length)
            {
                SetLength(_position + byteCount);
            }
            unsafe
            {
                fixed (byte* fixedBytePtr = &_bytes[0])
                {
                    UInt32* uintp = (UInt32*)(fixedBytePtr + _position);
                    _position += byteCount;
                    while (count-- > 0)
                    {
                        *(uintp++) = value;
                    }
                }
            }
        }
        public bool Equal(byte[] values, long position, int offset, int count)
        {
            if (position + count > _length)
            {
                return false;
            }
            var i = 0;
            while (count-- > 0)
            {
                if (_bytes[i] != values[i++])
                {
                    return false;
                }
            }
            return true;
        }
        #region Bit operations
        public void SetBit(bool bit, long position)
        {
            if (position < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(position));
            }
            var length = position == 0 ? 1 : position / BitsPerByte + (position % BitsPerByte == 0 ? 0 : 1);
            if (length >= _length)
            {
                SetLength(length);
            }
            int intOffset = (int)(position / BitsPerByte);
            int bitOffset = (int)(position % BitsPerByte);
            byte bitMask = (byte)(0x80 >> bitOffset);
            if (bit)
            {
                _bytes[intOffset] |= bitMask;
            }
            else
            {
                _bytes[intOffset] &= (byte)~bitMask;
            }
        }

        public bool GetBit(long position)
        {
            if (position < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(position));
            }
            var length = position  == 0 ? 1 : position / BitsPerByte + (position % BitsPerByte == 0 ? 0 : 1);
            if (length >= _length)
            {
                return false;
            }
            else
            {
                int intOffset = (int)(position / BitsPerByte);
                int bitOffset = (int)(position % BitsPerByte);
                byte bitMask = (byte)(0x80 >> bitOffset);
                return (_bytes[intOffset] & ~bitMask) != 0;
            }
        }
        public void FlipBit(long position)
        {
            if (position < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(position));
            }
            int byteIndex = (int)(position / BitsPerByte);
            int bitOffset = (int)(position % BitsPerByte);
            if (byteIndex >= _length)
            {
                SetLength(byteIndex);
            }
            _bytes[byteIndex] |= (byte)(_bytes[byteIndex] & ~(0x80 >> bitOffset));
        }
#endregion
        public new byte ReadByte()
        {
            if (_position < _length)
            {
                return _bytes[_position++];
            }
            else
            {
                return 0;
            }
        }
        public UInt16 ReadInt16()
        {
            if (_position < _length)
            {
                int byteIndex = (int)(_position * sizeof(UInt16));
                unsafe
                {
                    fixed (byte* pointer = &_bytes[0])
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
            if (_position < _length)
            {
                int byteIndex = (int)(_position * sizeof(UInt32));
                unsafe
                {
                    fixed (byte* pointer = &_bytes[0])
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
            _bytes[_position] ^= value;

        }
        public void Xor(UInt16 value)
        {
            if (_position >= _length - sizeof(UInt16) + 1)
            {
                throw new InvalidOperationException("Invalid position");
            }
            unsafe
            {
                fixed (byte* fixedBytePtr = &_bytes[0])
                {
                    UInt16* pointer = (UInt16*)(fixedBytePtr + _position);
                    *pointer ^= value;
                }
            }
        }
        public void Xor(UInt32 value)
        {
            if (_position >= _length - sizeof(UInt32) + 1)
            {
                throw new InvalidOperationException("Invalid position");
            }
            unsafe
            {
                fixed (byte* fixedBytePtr = &_bytes[0])
                {
                    UInt32* pointer = (UInt32*)(fixedBytePtr + _position);
                    *pointer ^= value;
                }
            }
        }
        #endregion

        #region Add
        public void Add(byte value)
        {
            _bytes[_position] += value;
        }
        public void Add(UInt16 value)
        {
            if (_position >= _length - 1)
            {
                throw new InvalidOperationException("Invalid position");
            }
            unsafe
            {
                fixed (byte* fixedBytePtr = &_bytes[0])
                {
                    UInt16* pointer = (UInt16*)(fixedBytePtr + _position);
                    *pointer += value;
                }
            }
        }
        public void Add(UInt32 value)
        {
            if (_position >= _length - 3)
            {
                throw new InvalidOperationException("Invalid position");
            }
            unsafe
            {
                fixed (byte* fixedBytePtr = &_bytes[0])
                {
                    UInt32* pointer = (UInt32*)(fixedBytePtr + _position);
                    *pointer += value;
                }
            }
        }
        #endregion

        #region Substract
        public void Substract(byte value)
        {
            _bytes[_position] -= value;
        }
        public void Substract(UInt16 value)
        {
            if ( _position >= _length - 1 )
            {
                throw new InvalidOperationException("Invalid position");
            }
            unsafe
            {
                fixed (byte* fixedBytePtr = &_bytes[0])
                {
                    UInt16* pointer = (UInt16*)(fixedBytePtr + _position);
                    *pointer -= value;
                }
            }
        }
        public void Substract(UInt32 value)
        {
            if (_position >= _length - 3)
            {
                throw new InvalidOperationException("Invalid position");
            }
            unsafe
            {
                fixed (byte* fixedBytePtr = &_bytes[0])
                {
                    UInt32* pointer = (UInt32*)(fixedBytePtr + _position);
                    *pointer -= value;
                }
            }
        }
        #endregion

        #region And
        public void And(byte value)
        {
            _bytes[_position] &= value;
        }
        public void And(UInt16 value)
        {
            if (_position >= _length - 1)
            {
                throw new InvalidOperationException("Invalid position");
            }
            unsafe
            {
                fixed (byte* fixedBytePtr = &_bytes[0])
                {
                    UInt16* pointer = (UInt16*)(fixedBytePtr + _position);
                    *pointer &= value;
                }
            }
        }
        public void And(UInt32 value)
        {
            if (_position >= _length - 3)
            {
                throw new InvalidOperationException("Invalid position");
            }
            unsafe
            {
                fixed (byte* fixedBytePtr = &_bytes[0])
                {
                    UInt32* pointer = (UInt32*)(fixedBytePtr + _position);
                    *pointer &= value;
                }
            }
        }
        #endregion

        #region Func
        public void Func(Func<byte,byte> func)
        {
            _bytes[_position] = func(_bytes[_position]);
        }
        public void Func(Func<UInt16, UInt16> func)
        {
            if (_position >= _length - 1)
            {
                throw new InvalidOperationException("Invalid position");
            }
            unsafe
            {
                fixed (byte* fixedBytePtr = &_bytes[0])
                {
                    UInt16* pointer = (UInt16*)(fixedBytePtr + _position);
                    *pointer = func(*pointer);
                }
            }
        }
        public void Func(Func<UInt32, UInt32> func)
        {
            if (_position >= _length - 3)
            {
                throw new InvalidOperationException("Invalid position");
            }
            unsafe
            {
                fixed (byte* fixedBytePtr = &_bytes[0])
                {
                    UInt32* pointer = (UInt32*)(fixedBytePtr + _position);
                    *pointer = func(*pointer);
                }
            }
        }
        #endregion

        #region Or
        public void Or(byte value)
        {
            _bytes[_position] |= value;
        }
        public void Or(UInt16 value)
        {
            if (_position >= _length - 1)
            {
                throw new InvalidOperationException("Invalid position");
            }
            unsafe
            {
                fixed (byte* fixedBytePtr = &_bytes[0])
                {
                    UInt16* pointer = (UInt16*)(fixedBytePtr + _position);
                    *pointer |= value;
                }
            }
        }
        public void Or(UInt32 value)
        {
            if (_position >= _length - 3)
            {
                throw new InvalidOperationException("Invalid position");
            }
            unsafe
            {
                fixed (byte* fixedBytePtr = &_bytes[0])
                {
                    UInt32* pointer = (UInt32*)(fixedBytePtr + _position);
                    *pointer |= value;
                }
            }
        }
        #endregion
        public byte[] GetBytes()
        {
            return _bytes;
        }
    }
}
