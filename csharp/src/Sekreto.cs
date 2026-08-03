// sekreto: one interface for secrets, wherever they live.
//
// A Sekreto is an ordered chain of providers. `Get` asks each in turn and
// returns the first hit, so an app can be configured from environment
// variables in development and a vault in production without changing a
// line of its own code.
//
// A port of typescript/src/Sekreto.ts, which is canonical.

using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace Voxgig.Sekreto
{
    /// <summary>
    /// Anything sekreto refuses to do: a bad name, a missing secret, a
    /// provider that could not be reached.
    /// </summary>
    public class SekretoError : Exception
    {
        public SekretoError(string message) : base(message)
        {
        }
    }

    public static class Names
    {
        private static readonly Regex NamePart = new Regex("^[a-z0-9_]+$", RegexOptions.Compiled);

        /// <summary>Is this a well-formed secret name?</summary>
        public static bool ValidName(object name)
        {
            if (!(name is string text) || 0 == text.Length)
            {
                return false;
            }

            foreach (string part in text.Split('.'))
            {
                if (!NamePart.IsMatch(part))
                {
                    return false;
                }
            }

            return true;
        }

        public static string CheckName(object name)
        {
            if (!ValidName(name))
            {
                throw new SekretoError("sekreto: invalid name: " + (null == name ? "" : name));
            }

            return (string)name;
        }

        /// <summary>
        /// The environment-variable key for a name: `api.token` ->
        /// `API_TOKEN`.
        /// </summary>
        public static string EnvKey(object name, string prefix = null)
        {
            CheckName(name);

            return (prefix ?? "") + string.Join("_", ((string)name).Split('.')).ToUpperInvariant();
        }

        /// <summary>
        /// Where a name lives in a KV vault: `api.token` -> `api` / `token`.
        ///
        /// A single-segment name has no path of its own, so it becomes a
        /// secret of that name with the conventional field `value`.
        /// </summary>
        public static Dictionary<string, object> VaultRef(object name)
        {
            CheckName(name);

            string[] parts = ((string)name).Split('.');

            var out_ = new Dictionary<string, object>();

            if (1 == parts.Length)
            {
                out_["path"] = parts[0];
                out_["field"] = "value";
                return out_;
            }

            out_["path"] = string.Join("/", parts, 0, parts.Length - 1);
            out_["field"] = parts[parts.Length - 1];

            return out_;
        }
    }

    public static class Dotenv
    {
        /// <summary>
        /// Parse `.env` text into a map of raw keys to values.
        ///
        /// Deliberately small: `KEY=value`, optional `export`, `#` comments
        /// on their own line, and single- or double-quoted values (double
        /// quotes also unescape \n, \r, \t and \\). A line with no `=` is
        /// skipped.
        /// </summary>
        public static Dictionary<string, object> Parse(object text)
        {
            var out_ = new Dictionary<string, object>();

            if (!(text is string source))
            {
                return out_;
            }

            foreach (string rawline in source.Split('\n'))
            {
                string line = rawline.TrimEnd('\r').Trim();

                if (0 == line.Length || line.StartsWith("#", StringComparison.Ordinal))
                {
                    continue;
                }

                string body = line.StartsWith("export ", StringComparison.Ordinal)
                    ? line.Substring(7).Trim()
                    : line;

                int eq = body.IndexOf('=');
                if (0 >= eq)
                {
                    continue;
                }

                string key = body.Substring(0, eq).Trim();
                string value = body.Substring(eq + 1).Trim();

                if (2 <= value.Length && value.StartsWith("\"", StringComparison.Ordinal)
                    && value.EndsWith("\"", StringComparison.Ordinal))
                {
                    value = Unescape(value.Substring(1, value.Length - 2));
                }
                else if (2 <= value.Length && value.StartsWith("'", StringComparison.Ordinal)
                    && value.EndsWith("'", StringComparison.Ordinal))
                {
                    value = value.Substring(1, value.Length - 2);
                }

                out_[key] = value;
            }

            return out_;
        }

        private static string Unescape(string text)
        {
            var out_ = new StringBuilder();

            for (int index = 0; index < text.Length; index++)
            {
                if ('\\' == text[index] && index + 1 < text.Length)
                {
                    char next = text[index + 1];
                    index++;
                    switch (next)
                    {
                        case 'n': out_.Append('\n'); break;
                        case 'r': out_.Append('\r'); break;
                        case 't': out_.Append('\t'); break;
                        case '\\': out_.Append('\\'); break;
                        case '"': out_.Append('"'); break;
                        default: out_.Append('\\').Append(next); break;
                    }
                }
                else
                {
                    out_.Append(text[index]);
                }
            }

            return out_.ToString();
        }
    }

    /// <summary>The secrets facade: a chain of providers plus a cache.</summary>
    public class Sekreto
    {
        private readonly List<IProvider> providers = new List<IProvider>();
        private readonly bool docache;

        // Insertion-ordered by construction: redaction walks the resolved
        // values, and their order must not vary between runs.
        private readonly List<KeyValuePair<string, string>> cache =
            new List<KeyValuePair<string, string>>();

        public Sekreto(IEnumerable<IProvider> useproviders, bool usecache = true)
        {
            if (null != useproviders)
            {
                providers.AddRange(useproviders);
            }

            docache = usecache;
        }

        /// <summary>
        /// Replace known secret values in text with `[redacted]`.
        ///
        /// Only values of four characters or more are replaced: shorter ones
        /// are too likely to appear in ordinary text, and redacting them
        /// would make logs unreadable without making them safer.
        /// </summary>
        public static string Redact(object text, IEnumerable<object> values)
        {
            string out_ = text is string source ? source : "";

            if (null == values)
            {
                return out_;
            }

            foreach (object value in values)
            {
                if (!(value is string secret) || 4 > secret.Length)
                {
                    continue;
                }

                out_ = string.Join("[redacted]", out_.Split(new[] { secret }, StringSplitOptions.None));
            }

            return out_;
        }

        /// <summary>The secret, or a SekretoError if no provider has it.</summary>
        public string Get(string name)
        {
            string found = TryGet(name);

            if (null == found)
            {
                throw new SekretoError("sekreto: unknown secret: " + name);
            }

            return found;
        }

        /// <summary>The secret, or null if no provider has it.</summary>
        public string TryGet(string name)
        {
            Names.CheckName(name);

            if (docache)
            {
                foreach (var entry in cache)
                {
                    if (entry.Key == name)
                    {
                        return entry.Value;
                    }
                }
            }

            foreach (IProvider provider in providers)
            {
                string found = provider.Lookup(name);

                if (null != found)
                {
                    if (docache)
                    {
                        cache.Add(new KeyValuePair<string, string>(name, found));
                    }
                    return found;
                }
            }

            return null;
        }

        /// <summary>Does any provider have this secret?</summary>
        public bool Has(string name)
        {
            return null != TryGet(name);
        }

        /// <summary>Every named secret at once. Missing ones are an error.</summary>
        public Dictionary<string, string> All(IEnumerable<string> names)
        {
            var out_ = new Dictionary<string, string>();

            foreach (string name in names)
            {
                out_[name] = Get(name);
            }

            return out_;
        }

        /// <summary>A description of each provider, in resolution order.</summary>
        public List<object> Sources()
        {
            var out_ = new List<object>();

            foreach (IProvider provider in providers)
            {
                out_.Add(provider.Describe());
            }

            return out_;
        }

        /// <summary>
        /// Replace every value this Sekreto has resolved with `[redacted]`.
        /// </summary>
        public string Redact(string text)
        {
            var values = new List<object>();

            foreach (var entry in cache)
            {
                values.Add(entry.Value);
            }

            return Redact(text, values);
        }

        /// <summary>
        /// Drop cached values, so the next `Get` asks the providers again.
        /// </summary>
        public void Refresh()
        {
            cache.Clear();
        }
    }
}
