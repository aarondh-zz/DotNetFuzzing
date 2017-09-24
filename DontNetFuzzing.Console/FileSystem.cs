using DotNetFuzzing.Common;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace DontNetFuzzing.Console
{
    public class FileSystem : IFileSystem
    {
        public bool CreateDirectory(string directory)
        {
            return Directory.CreateDirectory(directory) != null;
        }

        public bool Delete(string filePath)
        {
            try
            {
                File.Delete(filePath);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public bool DirectoryExists(string directory)
        {
            return Directory.Exists(directory);
        }

        public IEnumerable<string> EnumerateFiles(string directory)
        {
            return Directory.EnumerateFiles(directory);
        }

        public bool FileExists(string filePath)
        {
            return File.Exists(filePath);
        }
        private class FileInfo : IFileInfo
        {
            public DateTime LastWriteTime { get; set; }

            public long Length { get; set; }
        }
        public IFileInfo GetFileInfo(string filePath)
        {
            var fileInfo = new System.IO.FileInfo(filePath);
            return new FileInfo
            {
                LastWriteTime = fileInfo.LastWriteTime,
                Length = fileInfo.Length
            };
        }
        private class Stream : IStream
        {
            private FileStream _fileStream;

            public Stream( string path, FileStream fileStream )
            {
                Path = path;
                _fileStream = fileStream;
            }
            public string Path { get; }
            public long Length => _fileStream.Length;

            public long Position => _fileStream.Position;

            public void Close()
            {
            }

            public void Dispose()
            {
                _fileStream.Dispose();
            }

            public void Flush()
            {
                _fileStream.Flush();
            }

            public int Read(byte[] buffer, int offset, int count)
            {
                return _fileStream.Read(buffer, offset, count);
            }

            public string ReadToEnd(Encoding encoding)
            {
                using (var reader = new StreamReader(_fileStream))
                {
                    return reader.ReadToEnd();
                }
            }

            public long Seek(long position)
            {
                return _fileStream.Seek(position, SeekOrigin.Begin);
            }

            public void SetLength(long length)
            {
                _fileStream.SetLength(length);
            }

            public int Write(byte[] buffer, int offset, int count)
            {
                _fileStream.Write(buffer, offset, count);
                return count;
            }

            public int Write(string text)
            {
                using (var writer = new StreamWriter(_fileStream))
                {
                    writer.Write(text);
                }
                return text.Length;
            }
            public override string ToString()
            {
                return $"{Path}[{Length}]@{Position}";
            }
        }
        public IStream Open(string filePath, OpenOptions options)
        {
            FileAccess access = FileAccess.Read;
            FileMode mode;
            FileShare share;
            if (options.HasFlag(OpenOptions.Exclusive))
            {
                share = FileShare.None;
            }
            else
            {
                share = FileShare.Read;
            }
            if (options.HasFlag(OpenOptions.Create))
            {
                mode = FileMode.Create;
            }
            else
            {
                mode = FileMode.Open;
            }
            if (options.HasFlag(OpenOptions.ReadOnly))
            {
                access = FileAccess.Read;
            }
            else if (options.HasFlag(OpenOptions.ReadWrite))
            {
                access = FileAccess.ReadWrite;
            }
            else if (options.HasFlag(OpenOptions.WriteOnly))
            {
                access = FileAccess.Write;
            }
            return new Stream(filePath, File.Open(filePath, mode, access, share));
        }
    }
}
