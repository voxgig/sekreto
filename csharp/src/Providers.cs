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
using System.Diagnostics;
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

    public static class Addr
    {
        /// <summary>
        /// Refuse to send a Vault token in the clear.
        ///
        /// <para>Vault's API is HTTPS in any real deployment; plaintext is a
        /// dev-mode convenience. Sending X-Vault-Token over http to anything
        /// but the local machine puts both the token and the secret it
        /// fetches on the wire for anyone on the path, so sekreto will not do
        /// it. Loopback stays allowed: that is `vault server -dev` and this
        /// repo's own test harness.</para>
        /// </summary>
        public static void Check(string addr)
        {
            if (addr.StartsWith("https://", StringComparison.Ordinal))
            {
                return;
            }

            if (!addr.StartsWith("http://", StringComparison.Ordinal))
            {
                throw new SekretoError("sekreto: not an http(s) address: " + addr);
            }

            string host = addr.Substring("http://".Length).Split('/')[0].Split(':')[0];

            if ("localhost" == host || "127.0.0.1" == host || "::1" == host || "[::1]" == host)
            {
                return;
            }

            throw new SekretoError(
                "sekreto: refusing to send a token in plaintext to " + addr + " (use https)");
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
    public class HashicorpProvider : IProvider
    {
        private readonly string addr;
        private readonly string token;
        private readonly string mount;

        public HashicorpProvider(string addr, string token, string mount = null)
        {
            this.addr = addr ?? "";
            this.token = token ?? "";
            this.mount = string.IsNullOrEmpty(mount) ? "secret" : mount;
        }

        public string Lookup(string name)
        {
            Addr.Check(addr);

            Dictionary<string, object> reference = Names.VaultRef(name);
            string url = addr.TrimEnd('/') + "/v1/" + mount + "/data/" + reference["path"];

            var (status, body) = Http.Get(url, "X-Vault-Token", token);

            if (HttpStatusCode.NotFound == status)
            {
                return null;
            }

            if (HttpStatusCode.OK != status)
            {
                throw new SekretoError("sekreto: hashicorp error: " + (int)status + ": " + url);
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
            return "hashicorp:" + addr + "/" + mount;
        }
    }

    /// <summary>
    /// A boru vault (https://github.com/boru-lang/boru).
    ///
    /// <para>boru keeps secrets in a local encrypted keyring and hands a
    /// value out through its own CLI: `boru vault get --reveal &lt;alias&gt;`
    /// prints the secret on stdout, and nothing else.</para>
    ///
    /// <para>There is deliberately no HTTP read here. boru's `vault proxy`
    /// and `vault mcp` are a *credential broker*: they inject the real secret
    /// into an outbound request and forward it, so an agent can call an API
    /// without ever holding the credential. Handing a value back is the one
    /// thing that broker is built not to do, so sekreto reads the vault the
    /// way boru itself does - through the CLI.</para>
    ///
    /// <para>A sekreto name is already a valid boru alias, so `api.token`
    /// crosses over unchanged. A namespace qualifies it the way boru writes
    /// it, `ns:name`.</para>
    ///
    /// <para>The passphrase is read by boru itself from
    /// BORU_VAULT_PASSPHRASE. sekreto never accepts it as config and never
    /// puts it on a command line, where it would show up in the process
    /// table.</para>
    /// </summary>
    public class BoruProvider : IProvider
    {
        private readonly string command;
        private readonly string namespace_;
        private readonly string home;

        public BoruProvider(string command, string namespace_ = null, string home = null)
        {
            this.command = string.IsNullOrEmpty(command) ? "boru" : command;
            this.namespace_ = namespace_;
            this.home = home;
        }

        public string Lookup(string name)
        {
            Names.CheckName(name);

            string alias = string.IsNullOrEmpty(namespace_) ? name : namespace_ + ":" + name;

            var start = new ProcessStartInfo
            {
                FileName = command,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };

            // Arguments are passed one by one, never through a shell, so an
            // alias is never word-split or interpreted.
            start.ArgumentList.Add("vault");
            start.ArgumentList.Add("get");
            start.ArgumentList.Add("--reveal");
            start.ArgumentList.Add(alias);

            if (!string.IsNullOrEmpty(home))
            {
                start.Environment["BORU_HOME"] = home;
            }

            string outtext;
            string why;
            int status;

            try
            {
                using Process process = Process.Start(start);
                outtext = process.StandardOutput.ReadToEnd();
                why = process.StandardError.ReadToEnd().Trim();
                process.WaitForExit();
                status = process.ExitCode;
            }
            catch (Exception err)
            {
                throw new SekretoError("sekreto: cannot run " + command + ": " + err.Message);
            }

            if (0 == status)
            {
                // boru prints the value and one newline, and nothing else.
                return outtext.EndsWith("\n", StringComparison.Ordinal)
                    ? outtext.Substring(0, outtext.Length - 1)
                    : outtext;
            }

            // "no alias named" is boru saying it does not hold this secret,
            // which is a miss: the chain carries on to the next provider. A
            // locked vault or a wrong passphrase is not a miss - treating it
            // as one would fall through to a weaker store without saying so.
            if (BoruMiss(why))
            {
                return null;
            }

            throw new SekretoError(
                "sekreto: boru vault error: " + (0 == why.Length ? "exit " + status : why));
        }

        public string Describe()
        {
            return "boru" + (string.IsNullOrEmpty(namespace_) ? "" : ":" + namespace_);
        }

        /// <summary>
        /// Does this boru failure mean "no such secret" rather than "I could
        /// not answer"? Matched on boru's own wording for a missing alias.
        /// </summary>
        internal static bool BoruMiss(string why)
        {
            return why.Contains("no alias named");
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

                case "hashicorp":
                    return new HashicorpProvider(
                        TextOr(spec.GetValueOrDefault("addr"), ""),
                        TextOr(spec.GetValueOrDefault("token"), ""),
                        Text(spec.GetValueOrDefault("mount")));

                case "boru":
                    return new BoruProvider(
                        Text(spec.GetValueOrDefault("command")),
                        Text(spec.GetValueOrDefault("namespace")),
                        Text(spec.GetValueOrDefault("home")));

                default:
                    throw new SekretoError("sekreto: unknown provider kind: " + (kind ?? ""));
            }
        }

        /// <summary>
        /// The store name each spec asks for, in order, so Sekreto.GetFrom can
        /// address them. An entry is empty when the spec does not name one.
        /// </summary>
        public static List<string> ChainNames(object specs)
        {
            var out_ = new List<string>();

            if (!(specs is List<object> entries))
            {
                return out_;
            }

            foreach (object entry in entries)
            {
                if (entry is Dictionary<string, object> spec)
                {
                    out_.Add(Text(spec.GetValueOrDefault("name")) ?? "");
                }
            }

            return out_;
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
