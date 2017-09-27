using DotNetFuzzing.Common;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace DontNetFuzzing.Console
{
    public class FileSystem : IFileSystem
    {
        [DllImport("kernel32.dll")]
        private static extern bool CreateSymbolicLink(string symbolicLinkPath, string targetPath, int dwFlags);
  
        public bool CreateDirectory(string directory)
        {
            return Directory.CreateDirectory(directory) != null;
        }
        public bool LinkFile(string symbolicLinkFilePath, string targetFilePath)
        {
            return CreateSymbolicLink(symbolicLinkFilePath, targetFilePath, 0x00);
        }

        public bool LinkDirectory(string symbolicLinkDirectoryPath, string targetDirectoryPath)
        {
            return CreateSymbolicLink(symbolicLinkDirectoryPath, targetDirectoryPath, 0x01);
        }

        public bool EnsureDirectory(string directory)
        {
            if (!Directory.Exists(directory) )
            {
                return Directory.CreateDirectory(directory) != null;
            }
            return true;
        }

        public bool DeleteFile(string filePath)
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

        public bool DeleteDirectory(string filePath)
        {
            try
            {
                Directory.Delete(filePath, false);
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
        public void Copy( string fromPath, string toPath, bool overwrite = false)
        {
            File.Copy(fromPath, toPath, overwrite);
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
            private Encoding _encoding;
            private StreamReader _reader;
            private StreamWriter _writer;

            public Stream( string path, FileStream fileStream, Encoding encoding )
            {
                Path = path;
                _fileStream = fileStream;
                _encoding = encoding;
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
            public string ReadToEnd()
            {
                if (_reader == null)
                {
                    _reader = new StreamReader(_fileStream, _encoding);
                }
                return _reader.ReadToEnd();
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

            public void Write(string text)
            {
                if (_writer == null)
                {
                    _writer = new StreamWriter(_fileStream, _encoding);
                }
                _writer.Write(text);
            }
            public override string ToString()
            {
                return $"{Path}[{Length}]@{Position}";
            }
        }
        public IStream Open(string filePath, OpenOptions options = OpenOptions.ReadOnly, Encoding encoding = null)
        {
            FileAccess access = FileAccess.Read;
            FileMode mode;
            FileShare share;
            if ( encoding == null )
            {
                encoding = Encoding.UTF8;
            }
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
            return new Stream(filePath, File.Open(filePath, mode, access, share), encoding);
        }

        public bool Rename(string oldPath, string newPath)
        {
            try
            {
                File.Move(oldPath, newPath);
                return true;
            }
            catch
            {
                return false;
            }
        }

    }
}
