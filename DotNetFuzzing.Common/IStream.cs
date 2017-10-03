using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotNetFuzzing.Common
{
    public interface IStream : IDisposable
    {
        void Close();

        void Flush();

        int Read(byte[] buffer, int offset, int count);

        int Write(byte[] buffer, int offset, int count);

        void Write(string text);

        string ReadToEnd();

        string ReadLine();

        long Length { get;  }

        long Position { get; }

        long Seek(long position);

        void SetLength(long length);
    }
}
