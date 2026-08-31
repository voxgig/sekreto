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

        /// <summary>
        /// A name flattened to one segment: `api.token` -> `api_token` (GCP
        /// Secret Manager, `_`) or `api-token` (Azure Key Vault, `-`).
        ///
        /// <para>Those stores have no path hierarchy and reject dots in ids,
        /// so the dots become the store's conventional separator. With `-` as
        /// the separator, underscores flatten too: Azure Key Vault's alphabet
        /// is letters, digits and hyphens only, and a valid sekreto name like
        /// `with_underscore` must still be representable there. (The
        /// resulting `.`/`_` collision mirrors the documented envkey
        /// behaviour, where both already map to `_`.)</para>
        /// </summary>
        public static string FlatName(object name, string sep)
        {
            CheckName(name);

            string flat = string.Join(sep, ((string)name).Split('.'));

            return "-" == sep ? string.Join("-", flat.Split('_')) : flat;
        }

        /// <summary>
        /// The AWS SSM Parameter Store name for a name: dots become the path
        /// hierarchy, rooted at `/` (or at a prefix): `db.pass.main` ->
        /// `/db/pass/main`, or `/app/db/pass/main` under prefix `/app`.
        /// </summary>
        public static string AwsParam(object name, string prefix = null)
        {
            CheckName(name);

            string base_ = prefix ?? "";

            if ("" != base_ && !base_.StartsWith("/", StringComparison.Ordinal))
            {
                base_ = "/" + base_;
            }

            if (base_.EndsWith("/", StringComparison.Ordinal))
            {
                base_ = base_.Substring(0, base_.Length - 1);
            }

            return base_ + "/" + string.Join("/", ((string)name).Split('.'));
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
        /// <summary>One provider in the chain, under the store name it answers to.</summary>
        private sealed class Entry
        {
            public string Store;
            public IProvider Provider;
        }

        /// <summary>One resolved value, with the store it came from.</summary>
        private sealed class Cached
        {
            public string Store;
            public string Name;
            public string Value;
        }

        private readonly List<Entry> entries = new List<Entry>();
        private readonly bool docache;

        // A list, not a dictionary: the store a value came from stays
        // attached, and redaction order does not vary between runs.
        private readonly List<Cached> cache = new List<Cached>();

        // Every value ever resolved, for Redact(). Kept independently of the
        // read cache so that redaction still works when cache is off -
        // otherwise an uncached Sekreto would silently disable Redact() and
        // leak secrets to logs.
        private readonly List<string> seen = new List<string>();

        public Sekreto(IEnumerable<IProvider> useproviders, bool usecache = true)
            : this(useproviders, null, usecache)
        {
        }

        /// <summary>
        /// A Sekreto whose providers answer to the given store names, in the
        /// same order. A name left null or empty falls back to the provider's
        /// kind.
        /// </summary>
        public Sekreto(IEnumerable<IProvider> useproviders, IList<string> names, bool usecache)
        {
            if (null != useproviders)
            {
                int index = 0;

                foreach (IProvider provider in useproviders)
                {
                    string store = StoreName(provider);

                    if (null != names && index < names.Count
                        && !string.IsNullOrEmpty(names[index]))
                    {
                        store = names[index];
                    }

                    entries.Add(new Entry { Store = store, Provider = provider });
                    index++;
                }
            }

            docache = usecache;
        }

        /// <summary>
        /// The store name a provider answers to when nothing says otherwise.
        ///
        /// <para>Describe opens with the provider's kind - hashicorp:...,
        /// dotenv:..., plain env - so the kind is the natural default, and a
        /// custom provider gets a sensible name without implementing anything
        /// extra.</para>
        /// </summary>
        public static string StoreName(IProvider provider)
        {
            return provider.Describe().Split(new[] { ':' }, 2)[0];
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

            // Longest first: a shorter secret that prefixes a longer one used
            // to eat the prefix and leave the rest in the log. Collected into
            // our own list, so the caller's is not reordered.
            var usable = new List<string>();
            foreach (object value in values)
            {
                if (value is string secret && 4 <= secret.Length)
                {
                    usable.Add(secret);
                }
            }
            usable.Sort((left, right) => right.Length - left.Length);

            foreach (string value in usable)
            {
                out_ = string.Join("[redacted]", out_.Split(new[] { value }, StringSplitOptions.None));
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
            return Resolve("", name, entries);
        }

        /// <summary>
        /// The secret from one named store, or a SekretoError if that store
        /// does not have it.
        /// </summary>
        public string GetFrom(string store, string name)
        {
            string found = TryFrom(store, name);

            if (null == found)
            {
                throw new SekretoError("sekreto: unknown secret: " + store + ":" + name);
            }

            return found;
        }

        /// <summary>
        /// The secret from one named store, or null if that store does not
        /// have it.
        ///
        /// <para>Naming a store that is not in the chain is an error, not a
        /// miss: TryGet already means "this store may not have it", so it
        /// cannot also mean "this store may not exist" without hiding a
        /// typo.</para>
        /// </summary>
        public string TryFrom(string store, string name)
        {
            var matching = new List<Entry>();

            foreach (Entry entry in entries)
            {
                if (entry.Store == store)
                {
                    matching.Add(entry);
                }
            }

            if (0 == matching.Count)
            {
                throw new SekretoError("sekreto: unknown store: " + store);
            }

            return Resolve(store, name, matching);
        }

        private string Resolve(string store, string name, List<Entry> useentries)
        {
            Names.CheckName(name);

            if (docache)
            {
                foreach (Cached hit in cache)
                {
                    if (hit.Store == store && hit.Name == name)
                    {
                        return hit.Value;
                    }
                }
            }

            foreach (Entry entry in useentries)
            {
                string found = entry.Provider.Lookup(name);

                if (null != found)
                {
                    if (docache)
                    {
                        cache.Add(new Cached { Store = store, Name = name, Value = found });
                    }
                    seen.Add(found);
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

        /// <summary>Does this named store have this secret?</summary>
        public bool HasIn(string store, string name)
        {
            return null != TryFrom(store, name);
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

            foreach (Entry entry in entries)
            {
                out_.Add(entry.Provider.Describe());
            }

            return out_;
        }

        /// <summary>
        /// The name of each store that can be named by GetFrom, in resolution
        /// order and without repeats.
        /// </summary>
        public List<object> Stores()
        {
            var out_ = new List<object>();

            foreach (Entry entry in entries)
            {
                if (!out_.Contains(entry.Store))
                {
                    out_.Add(entry.Store);
                }
            }

            return out_;
        }

        /// <summary>
        /// Replace every value this Sekreto has resolved with `[redacted]`.
        ///
        /// <para>Works whether or not caching is enabled: the redaction list
        /// is kept independently of the read cache.</para>
        /// </summary>
        public string Redact(string text)
        {
            var values = new List<object>();

            foreach (string value in seen)
            {
                values.Add(value);
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
