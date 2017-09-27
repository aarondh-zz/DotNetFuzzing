using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotNetFuzzing.Common
{
    [Flags]
    public enum OpenOptions
    {
        Create = 0x01,
        WriteOnly = 0x02,
        Exclusive = 0x04,
        ReadOnly = 0x08,
        ReadWrite = 0x10
    }
    public interface IFileSystem
    {
        IStream Open(string filePath, OpenOptions options = OpenOptions.ReadOnly, Encoding encoding = null);
        IFileInfo GetFileInfo(string filePath);
        bool DeleteFile(string filePath);
        bool DeleteDirectory(string filePath);
        IEnumerable<string> EnumerateFiles(string directory);
        bool CreateDirectory(string directory);
        bool EnsureDirectory(string directory);
        bool DirectoryExists(string directory);
        bool FileExists(string filePath);
        void Copy(string fromPath, string toPath, bool overwrite = false);
        bool LinkFile(string symbolicLinkFilePath, string targetFilePath);
        bool LinkDirectory(string symbolicLinkDirectoryPath, string targetDirectoryPath);

        bool Rename(string oldPath, string newPath);
    }
}
