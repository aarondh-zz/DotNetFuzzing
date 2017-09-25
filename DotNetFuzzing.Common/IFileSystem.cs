using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotNetFuzzing.Common
{
    public enum OpenOptions
    {
        Create,
        WriteOnly,
        Exclusive,
        ReadOnly,
        ReadWrite
    }
    public interface IFileSystem
    {
        IStream Open(string filePath, OpenOptions options);
        IFileInfo GetFileInfo(string filePath);
        bool Delete(string filePath);
        IEnumerable<string> EnumerateFiles(string directory);
        bool CreateDirectory(string directory);
        bool EnsureDirectory(string directory);
        bool DirectoryExists(string directory);
        bool FileExists(string filePath);
        void Copy(string fromPath, string toPath, bool overwrite = false);
    }
}
