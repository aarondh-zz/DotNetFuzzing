using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotNetFuzzing.Utilities
{
    public static class StringExtensions
    {
        public static string StringAfter(this string source, char character)
        {
            int sep = source.IndexOf(character);
            if (sep < 0)
            {
                return "";
            }
            else
            {
                return source.Substring(sep);
            }
        }
        public static string StringAfterLast(this string source, char character)
        {
            int sep = source.LastIndexOf(character);
            if (sep < 0)
            {
                return "";
            }
            else
            {
                return source.Substring(sep);
            }
        }
    }
}
