using DotNetFuzzing.Common;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;

namespace DontNetFuzzing.Console
{
    public class ConsoleLogger : ILogger
    {
        private class Token
        {
            public enum Types
            {
                Decompose,
                ValueOf,
                Default
            }
            public string Raw { get; }
            public string Name { get; }
            public Types Type { get; }
            public Token( string token)
            {
                this.Raw = token;
                switch( token[0] )
                {
                    case '@':
                        Type = Types.Decompose;
                        break;
                    case '$':
                        Type = Types.ValueOf;
                        break;
                    default:
                        Type = Types.Default;
                        break;
                }
            }
        }
        private class CompileMessageTemplate
        {
            private List<Token> _tokens;
            private string _formatString;
            private const string TokenPattern = @"\{([^\}]+)\}|\{\{|\}\}";
            private static Regex _tokenParser = new Regex(TokenPattern, RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.IgnorePatternWhitespace | RegexOptions.Multiline);
            public string MessageTemplate { get; private set; }
            public IEnumerable<Token> Tokens => _tokens;
            public CompileMessageTemplate( string messageTemplate )
            {
                this.MessageTemplate = messageTemplate;
                this._tokens = new List<Token>();
                _formatString = _tokenParser.Replace(messageTemplate, (match) =>
                {
                    var tokenGroup = match.Groups[1];
                    if (tokenGroup.Success)
                    {
                        var tokenNumber = _tokens.Count;
                        _tokens.Add(new Token(tokenGroup.Value));
                        return "{" + tokenNumber + "}";
                    }
                    else if (match.Value == "{{")
                    {
                        return "{";
                    }
                    else if (match.Value == "}}")
                    {
                        return "}";
                    }
                    return match.Value;
                });
            }
            public string Format(object[] arguments)
            {
                object[] formattedArguments = null;
                if (arguments != null) {
                    formattedArguments = new object[arguments.Length];
                    for (int i = 0; i < _tokens.Count; i++)
                    {
                        var token = _tokens[i];
                        switch (token.Type)
                        {
                            case Token.Types.Decompose:
                                formattedArguments[i] = Decompose(arguments[i]);
                                break;
                            case Token.Types.ValueOf:
                                formattedArguments[i] = ValueOf(arguments[i]);
                                break;
                            case Token.Types.Default:
                            default:
                                formattedArguments[i] = ToDefault(arguments[i]);
                                break;
                        }
                    }
                }
                return string.Format(_formatString, formattedArguments);
            }
            public string Decompose(object value)
            {
                return JsonConvert.SerializeObject(value);
            }
            public string ValueOf(object value)
            {
                return value.ToString();
            }
            public string ToDefault(object value)
            {
                return value.ToString();
            }
            public string ToJson(LogLevel logLevel, Exception exception,  object[] arguments)
            {
                StringBuilder result = new StringBuilder();
                result.Append("{");
                result.Append("@=\"");
                result.Append(logLevel);
                result.Append("\",");
                result.Append("@T=\"");
                result.Append(DateTime.Now.ToString("u"));
                result.Append("\",");
                result.Append("@MT=\"");
                result.Append(this.MessageTemplate);
                result.Append("\",");
                result.Append("@FM=\"");
                result.Append(this.Format(arguments));
                result.Append("\"");
                if ( exception != null)
                {
                    result.Append(",\"@E\"=");
                    result.Append(Decompose(exception));
                }
                for ( int i = 0; i < _tokens.Count; i++)
                {
                    var token = _tokens[i];
                    result.Append(",\"" + token.Name + "\"=");
                    switch( token.Type )
                    {
                        case Token.Types.Decompose:
                            result.Append(Decompose(arguments[i]));
                            break;
                        case Token.Types.ValueOf:
                            result.Append(ValueOf(arguments[i]));
                            break;
                        case Token.Types.Default:
                        default:
                            result.Append(ToDefault(arguments[i]));
                            break;
                    }
                }
                result.Append("}");

                return result.ToString();
            }
        }
        private static Dictionary<string, CompileMessageTemplate> _compiledMessageTemplates;
        static ConsoleLogger()
        {
            _compiledMessageTemplates = new Dictionary<string, CompileMessageTemplate>();

        }
        public ConsoleLogger()
        {
        }
       private static CompileMessageTemplate GetCompiled(string messageTemplate)
        {
            CompileMessageTemplate compiledMessageTemplate;
            if ( !_compiledMessageTemplates.TryGetValue(messageTemplate, out compiledMessageTemplate))
            {
                compiledMessageTemplate = new CompileMessageTemplate(messageTemplate);
                _compiledMessageTemplates[messageTemplate] = compiledMessageTemplate;
            }
            return compiledMessageTemplate;
        }
        public void Error(string messageTemplate, params object[] arguments)
        {
            Log(LogLevel.Error, null, messageTemplate, arguments);
        }

        public void Error(Exception exception, string messageTemplate, params object[] arguments)
        {
            Log(LogLevel.Error, exception, messageTemplate, arguments);
        }

        public void Fatal(string messageTemplate, params object[] arguments)
        {
            Log(LogLevel.Fatal, null, messageTemplate, arguments);
        }

        public void Fatal(Exception exception, string messageTemplate, params object[] arguments)
        {
            Log(LogLevel.Fatal, exception, messageTemplate, arguments);
        }

        public void Information(string messageTemplate, params object[] arguments)
        {
            Log(LogLevel.Information, null, messageTemplate, arguments);
        }

        public void Information(Exception exception, string messageTemplate, params object[] arguments)
        {
            Log(LogLevel.Information, exception, messageTemplate, arguments);
        }

        public void Log(LogLevel level, string messageTemplate, params object[] arguments)
        {
            Log(level, null, messageTemplate, arguments);
        }

        public void Log(LogLevel level, Exception exception, string messageTemplate, params object[] arguments)
        {
            var detail = exception == null ? "" : exception.ToString();
            System.Console.WriteLine($"{DateTime.Now.ToString("u")} {level}: {GetCompiled(messageTemplate).Format(arguments)} {detail}");
        }

        public void Verbose(string messageTemplate, params object[] arguments)
        {
            Log(LogLevel.Verbose, null, messageTemplate, arguments);
        }

        public void Verbose(Exception exception, string messageTemplate, params object[] arguments)
        {
            Log(LogLevel.Verbose, exception, messageTemplate, arguments);
        }

        public void Warning(string messageTemplate, params object[] arguments)
        {
            Log(LogLevel.Warning, null, messageTemplate, arguments);
        }

        public void Warning(Exception exception, string messageTemplate, params object[] arguments)
        {
            Log(LogLevel.Warning, exception, messageTemplate, arguments);
        }
    }
}
