// The providers a Sekreto chains together.
//
// A provider answers one question: "do you have this secret?" It returns
// the value, or null to mean "ask the next one". Nothing else about a
// provider is visible to the caller - which is the point: an app reads
// `api.token` and never learns whether it came from the environment, a
// .env file, HashiCorp Vault or a boru vault.
//
// A port of typescript/src/Providers.ts, which is canonical.

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;

namespace Voxgig.Sekreto
{
    /// <summary>A source of secrets.</summary>
    public interface IProvider
    {
        /// <summary>The value, or null if this provider does not have it.</summary>
        string Lookup(string name);

        /// <summary>A short description, shown by `Sekreto.Sources()`.</summary>
        string Describe();
    }

    /// <summary>Environment variables: `api.token` from `API_TOKEN`.</summary>
    public class EnvProvider : IProvider
    {
        private readonly string prefix;
        private readonly Dictionary<string, object> source;

        public EnvProvider(string prefix = null, Dictionary<string, object> source = null)
        {
            this.prefix = prefix;
            this.source = source;
        }

        public string Lookup(string name)
        {
            string key = Names.EnvKey(name, prefix);

            if (null != source)
            {
                return source.TryGetValue(key, out object found) && null != found
                    ? Convert.ToString(found)
                    : null;
            }

            return Environment.GetEnvironmentVariable(key);
        }

        public string Describe()
        {
            return "env" + (string.IsNullOrEmpty(prefix) ? "" : ":" + prefix);
        }
    }

    /// <summary>A `.env` file, read once, keyed exactly like the environment.</summary>
    public class DotenvProvider : IProvider
    {
        private readonly string file;
        private readonly string prefix;
        private Dictionary<string, object> values;

        public DotenvProvider(string file, string prefix = null)
        {
            this.file = file;
            this.prefix = prefix;
        }

        private Dictionary<string, object> Load()
        {
            if (null == values)
            {
                try
                {
                    values = Dotenv.Parse(File.ReadAllText(file));
                }
                catch (IOException)
                {
                    // A missing .env file is not an error: it means "no
                    // secrets here".
                    values = new Dictionary<string, object>();
                }
                catch (UnauthorizedAccessException)
                {
                    values = new Dictionary<string, object>();
                }
            }

            return values;
        }

        public string Lookup(string name)
        {
            return Load().TryGetValue(Names.EnvKey(name, prefix), out object found) && null != found
                ? Convert.ToString(found)
                : null;
        }

        public string Describe()
        {
            return "dotenv:" + file;
        }
    }

    /// <summary>
    /// Literal values, keyed like environment variables. The spec uses this
    /// to test chain behaviour without touching the outside world.
    /// </summary>
    public class MemoryProvider : IProvider
    {
        private readonly Dictionary<string, object> values;
        private readonly string prefix;

        public MemoryProvider(Dictionary<string, object> values, string prefix = null)
        {
            this.values = values ?? new Dictionary<string, object>();
            this.prefix = prefix;
        }

        public string Lookup(string name)
        {
            return values.TryGetValue(Names.EnvKey(name, prefix), out object found) && null != found
                ? Convert.ToString(found)
                : null;
        }

        public string Describe()
        {
            return "memory" + (string.IsNullOrEmpty(prefix) ? "" : ":" + prefix);
        }
    }

    internal static class Http
    {
        private static readonly HttpClient Client =
            new HttpClient { Timeout = TimeSpan.FromSeconds(10) };

        /// <summary>
        /// GET a url with one header. A 404 is a normal answer here, not a
        /// failure: it means the vault does not hold this secret.
        /// </summary>
        internal static (HttpStatusCode Status, string Body) Get(
            string url, string header, string token)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.TryAddWithoutValidation(header, token);

            try
            {
                HttpResponseMessage response = Client.Send(request);
                string body = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                return (response.StatusCode, body);
            }
            catch (Exception err)
            {
                throw new SekretoError("sekreto: cannot reach " + url + ": " + err.Message);
            }
        }
    }

    /// <summary>
    /// HashiCorp Vault, KV v2.
    ///
    /// `api.token` reads `{addr}/v1/{mount}/data/api` and takes the `token`
    /// field of `data.data`. A 404 means "not here", which is a miss rather
    /// than an error, so a vault can sit in a chain with fallbacks.
    /// </summary>
    public class VaultProvider : IProvider
    {
        private readonly string addr;
        private readonly string token;
        private readonly string mount;

        public VaultProvider(string addr, string token, string mount = null)
        {
            this.addr = addr ?? "";
            this.token = token ?? "";
            this.mount = string.IsNullOrEmpty(mount) ? "secret" : mount;
        }

        public string Lookup(string name)
        {
            Dictionary<string, object> reference = Names.VaultRef(name);
            string url = addr.TrimEnd('/') + "/v1/" + mount + "/data/" + reference["path"];

            var (status, body) = Http.Get(url, "X-Vault-Token", token);

            if (HttpStatusCode.NotFound == status)
            {
                return null;
            }

            if (HttpStatusCode.OK != status)
            {
                throw new SekretoError("sekreto: vault error: " + (int)status + ": " + url);
            }

            object outer = (Json.Parse(body) as Dictionary<string, object>)?
                .GetValueOrDefault("data");

            object data = (outer as Dictionary<string, object>)?.GetValueOrDefault("data");

            object value = (data as Dictionary<string, object>)?
                .GetValueOrDefault((string)reference["field"]);

            return null == value ? null : Convert.ToString(value);
        }

        public string Describe()
        {
            return "vault:" + addr + "/" + mount;
        }
    }

    /// <summary>
    /// A boru vault.
    ///
    /// The boru vault protocol as sekreto uses it: a GET of
    /// `{addr}/vault/{path}?field={field}` with an `X-Boru-Token` header,
    /// answering `{"ok":true,"value":"..."}` when the secret exists and
    /// `{"ok":false}` (or 404) when it does not.
    /// </summary>
    public class BoruProvider : IProvider
    {
        private readonly string addr;
        private readonly string token;

        public BoruProvider(string addr, string token)
        {
            this.addr = addr ?? "";
            this.token = token ?? "";
        }

        public string Lookup(string name)
        {
            Dictionary<string, object> reference = Names.VaultRef(name);

            string url = addr.TrimEnd('/') + "/vault/" + reference["path"]
                + "?field=" + Uri.EscapeDataString((string)reference["field"]);

            var (status, body) = Http.Get(url, "X-Boru-Token", token);

            if (HttpStatusCode.NotFound == status)
            {
                return null;
            }

            if (HttpStatusCode.OK != status)
            {
                throw new SekretoError("sekreto: boru vault error: " + (int)status + ": " + url);
            }

            if (!(Json.Parse(body) is Dictionary<string, object> parsed))
            {
                return null;
            }

            if (!true.Equals(parsed.GetValueOrDefault("ok")))
            {
                return null;
            }

            object value = parsed.GetValueOrDefault("value");

            return null == value ? null : Convert.ToString(value);
        }

        public string Describe()
        {
            return "boru:" + addr;
        }
    }

    public static class Providers
    {
        private static string Text(object value)
        {
            return null == value ? null : Convert.ToString(value);
        }

        private static string TextOr(object value, string fallback)
        {
            return null == value ? fallback : Convert.ToString(value);
        }

        /// <summary>Build a provider from its declarative form.</summary>
        public static IProvider MakeProvider(Dictionary<string, object> spec)
        {
            string kind = Text(spec.GetValueOrDefault("kind"));

            switch (kind)
            {
                case "env":
                    return new EnvProvider(Text(spec.GetValueOrDefault("prefix")));

                case "dotenv":
                    return new DotenvProvider(
                        TextOr(spec.GetValueOrDefault("file"), ".env"),
                        Text(spec.GetValueOrDefault("prefix")));

                case "memory":
                    return new MemoryProvider(
                        spec.GetValueOrDefault("values") as Dictionary<string, object>,
                        Text(spec.GetValueOrDefault("prefix")));

                case "vault":
                    return new VaultProvider(
                        TextOr(spec.GetValueOrDefault("addr"), ""),
                        TextOr(spec.GetValueOrDefault("token"), ""),
                        Text(spec.GetValueOrDefault("mount")));

                case "boru":
                    return new BoruProvider(
                        TextOr(spec.GetValueOrDefault("addr"), ""),
                        TextOr(spec.GetValueOrDefault("token"), ""));

                default:
                    throw new SekretoError("sekreto: unknown provider kind: " + (kind ?? ""));
            }
        }

        /// <summary>Build a whole provider chain from its declarative form.</summary>
        public static List<IProvider> MakeChain(object specs)
        {
            var out_ = new List<IProvider>();

            if (!(specs is List<object> entries))
            {
                return out_;
            }

            foreach (object entry in entries)
            {
                if (entry is Dictionary<string, object> spec)
                {
                    out_.Add(MakeProvider(spec));
                }
            }

            return out_;
        }
    }
}
