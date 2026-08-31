// The providers a Sekreto chains together.
//
// A provider answers one question: "do you have this secret?" It returns
// the value, or null to mean "ask the next one". Nothing else about a
// provider is visible to the caller - which is the point: an app reads
// `api.token` and never learns whether it came from the environment, a
// .env file, HashiCorp Vault, AWS, GCP, Azure or a boru vault.
//
// Two failure shapes, and they are never interchangeable. A store that
// does not hold the secret is a MISS (null) - the chain carries on. A
// store that could not answer - bad credentials, unreachable host,
// missing configuration - is an ERROR: falling through there would
// quietly reach for a weaker store.
//
// A port of typescript/src/Providers.ts, which is canonical.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net.Http;
using System.Text;

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
                catch (FileNotFoundException)
                {
                    // An absent file - or an absent directory - means "no
                    // secrets here", exactly like FileProvider. Anything else
                    // (permission denied, an unreadable mount) is a store
                    // that could not answer, and swallowing it would fall
                    // through to a weaker store.
                    values = new Dictionary<string, object>();
                }
                catch (DirectoryNotFoundException)
                {
                    values = new Dictionary<string, object>();
                }
                catch (Exception err)
                {
                    throw new SekretoError(
                        "sekreto: dotenv provider cannot read " + file + ": " + err.Message);
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

    /// <summary>
    /// A directory of one-secret-per-file entries, keyed like the
    /// environment: `api.token` reads `&lt;dir&gt;/API_TOKEN`.
    ///
    /// <para>This is the shape of a mounted Kubernetes Secret, a Docker or
    /// Swarm secret, and a systemd credentials directory, so those all work
    /// with no further configuration. One trailing newline is stripped -
    /// tools that write these files disagree about it, and a newline is
    /// never part of a secret on purpose.</para>
    /// </summary>
    public class FileProvider : IProvider
    {
        private readonly string dir;
        private readonly string prefix;

        public FileProvider(string dir, string prefix = null)
        {
            this.dir = dir ?? "";
            this.prefix = prefix;
        }

        public string Lookup(string name)
        {
            string file = Path.Combine(dir, Names.EnvKey(name, prefix));

            string text;
            try
            {
                text = File.ReadAllText(file);
            }
            catch (FileNotFoundException)
            {
                // An absent file - or an absent directory - means "no
                // secrets here", exactly like a missing .env. Anything else
                // (permission denied, an unreadable mount) is a store that
                // could not answer.
                return null;
            }
            catch (DirectoryNotFoundException)
            {
                return null;
            }
            catch (Exception err)
            {
                throw new SekretoError(
                    "sekreto: file provider cannot read " + file + ": " + err.Message);
            }

            if (text.EndsWith("\r\n", StringComparison.Ordinal))
            {
                return text.Substring(0, text.Length - 2);
            }
            if (text.EndsWith("\n", StringComparison.Ordinal))
            {
                return text.Substring(0, text.Length - 1);
            }

            return text;
        }

        public string Describe()
        {
            return "file:" + dir;
        }
    }

    public static class Addr
    {
        /// <summary>
        /// Refuse to send a secret-bearing credential in the clear.
        ///
        /// <para>A vault API is HTTPS in any real deployment; plaintext is a
        /// dev-mode convenience. Sending a token over http to anything but
        /// the local machine puts both the token and the secret it fetches
        /// on the wire for anyone on the path, so sekreto will not do it.
        /// Loopback stays allowed: that is `vault server -dev`,
        /// `boru vault serve`, and this repo's own test harness.</para>
        ///
        /// <para>The address is read by hand, in the same handful of steps in
        /// every port, rather than by each platform's URL parser. That is
        /// deliberate. Twelve parsers disagree about malformed input - where
        /// userinfo ends, whether `0177.0.0.1` is loopback, what an unclosed
        /// bracket means - and a check that answers differently in different
        /// ports is not a check.</para>
        ///
        /// <para>The rule this parse obeys, and the reason it can be trusted:
        /// it is never more permissive than the HTTP client that will dial
        /// the address. It ends the authority at `/`, `?` or `#` only, so a
        /// client that also breaks on `\` (WHATWG does) can only ever see a
        /// SHORTER host than this does. It refuses userinfo outright rather
        /// than locating its end. It compares the host literally, so a
        /// numeric form no parser here agrees on is refused rather than
        /// guessed at.</para>
        /// </summary>
        public static void Check(string addr)
        {
            string scheme;
            if (addr.StartsWith("https://", StringComparison.Ordinal))
            {
                scheme = "https://";
            }
            else if (addr.StartsWith("http://", StringComparison.Ordinal))
            {
                scheme = "http://";
            }
            else
            {
                throw new SekretoError("sekreto: not an http(s) address: " + addr);
            }

            string rest = addr.Substring(scheme.Length);
            int end = rest.IndexOfAny(new[] { '/', '?', '#' });
            string authority = -1 == end ? rest : rest.Substring(0, end);

            // Userinfo is refused outright rather than parsed around, and on
            // https as well as http. No store this library speaks
            // authenticates by userinfo - they take a token or a signature -
            // so an address carrying one is a mistake at best. At worst it is
            // the attack this whole method exists to stop:
            // http://localhost:8200@evil.example.com/ is a request to
            // evil.example.com that reads, to anything that splits the
            // authority on ':', as loopback.
            if (authority.Contains('@'))
            {
                throw new SekretoError(
                    "sekreto: refusing an address with embedded credentials: " + addr);
            }

            // An opening bracket with no closing one is not an address at all.
            if (authority.StartsWith("[", StringComparison.Ordinal)
                && !authority.Contains(']'))
            {
                throw new SekretoError("sekreto: not a valid http(s) address: " + addr);
            }

            if ("https://" == scheme)
            {
                return;
            }

            // A bracketed IPv6 literal keeps its brackets. Splitting the
            // authority on the first colon yields "[", so http://[::1]:8200
            // could never match - which made the "[::1]" entry below
            // unreachable, and refused a legitimate local vault.
            string host;
            if (authority.StartsWith("[", StringComparison.Ordinal))
            {
                host = authority.Substring(0, authority.IndexOf(']') + 1);
            }
            else
            {
                int colon = authority.IndexOf(':');
                host = -1 == colon ? authority : authority.Substring(0, colon);
            }
            host = host.ToLowerInvariant();

            if ("localhost" == host || "127.0.0.1" == host || "::1" == host || "[::1]" == host)
            {
                return;
            }

            throw new SekretoError(
                "sekreto: refusing to send a token in plaintext to " + addr + " (use https)");
        }
    }

    internal static class Url
    {
        /// <summary>
        /// Percent-encode a query value the way canonical's
        /// encodeURIComponent does: UTF-8 bytes as uppercase hex, with
        /// `A-Za-z0-9 - _ . ! ~ * ' ( )` left as they are.
        /// </summary>
        internal static string Encode(string text)
        {
            var out_ = new StringBuilder();

            foreach (byte head in Encoding.UTF8.GetBytes(text ?? ""))
            {
                char ch = (char)head;

                if (('A' <= ch && 'Z' >= ch) || ('a' <= ch && 'z' >= ch)
                    || ('0' <= ch && '9' >= ch)
                    || '-' == ch || '_' == ch || '.' == ch || '!' == ch || '~' == ch
                    || '*' == ch || '\'' == ch || '(' == ch || ')' == ch)
                {
                    out_.Append(ch);
                }
                else
                {
                    out_.Append('%').Append(((int)head).ToString("X2"));
                }
            }

            return out_.ToString();
        }
    }

    internal static class Http
    {
        // AllowAutoRedirect = false: a vault API never legitimately
        // redirects, and a followed redirect carries X-Vault-Token to the
        // target host, which checkaddr - it validates only the configured
        // address - cannot see. A 3xx then surfaces as a store error.
        private static readonly HttpClient Client =
            new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
            { Timeout = TimeSpan.FromSeconds(10) };

        /// <summary>
        /// One JSON round-trip. Network failure is always an error - an
        /// unreachable store is a store that could not answer. So is a
        /// status-200 body that fails to parse as JSON: a success status
        /// promised JSON, and treating the garble as a miss would fall
        /// through to a weaker store. Error statuses may carry any body -
        /// they are decided on status alone.
        /// </summary>
        internal static (int Status, object Body) FetchJson(
            string method, string url, Dictionary<string, string> headers, string body = null)
        {
            var request = new HttpRequestMessage(new HttpMethod(method), url);

            if (null != body)
            {
                request.Content = new ByteArrayContent(Encoding.UTF8.GetBytes(body));
            }

            if (null != headers)
            {
                foreach (var entry in headers)
                {
                    // Content headers (content-type) live on the content, not
                    // the request; try the request first and fall through.
                    if (!request.Headers.TryAddWithoutValidation(entry.Key, entry.Value)
                        && null != request.Content)
                    {
                        request.Content.Headers.TryAddWithoutValidation(entry.Key, entry.Value);
                    }
                }
            }

            int status;
            string text;
            try
            {
                using HttpResponseMessage response = Client.Send(request);
                status = (int)response.StatusCode;
                text = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            }
            catch (Exception err)
            {
                throw new SekretoError(
                    "sekreto: cannot reach " + url.Split('?')[0] + ": " + err.Message);
            }

            if (!Json.TryParse(text, out object parsed) && 200 == status)
            {
                throw new SekretoError(
                    "sekreto: malformed response from " + url.Split('?')[0]);
            }

            return (status, parsed);
        }
    }

    /// <summary>
    /// HashiCorp Vault.
    ///
    /// <para>KV v2 (the default): `api.token` reads
    /// `{addr}/v1/{mount}/data/api` and takes the `token` field of
    /// `data.data`. KV v1 (`kv: 1`) reads `{addr}/v1/{mount}/api` and takes
    /// the field of `data`. A 404 means "not here" - a miss - so a vault can
    /// sit in a chain with fallbacks.</para>
    ///
    /// <para>A Vault Enterprise namespace rides the X-Vault-Namespace
    /// header, on logins as well as reads.</para>
    ///
    /// <para>Instead of being handed a token, the provider can log in:
    /// Kubernetes auth (the pod's service-account JWT, from its conventional
    /// path) or AppRole. A failed login is an error, never a miss - it means
    /// this store could not answer at all.</para>
    /// </summary>
    public class HashicorpProvider : IProvider
    {
        private readonly string addr;
        private readonly string mount;
        private readonly int kv;
        private readonly string vaultnamespace;
        private readonly Dictionary<string, object> auth;

        // The working token: a configured token is kept forever, a logged-in
        // token is renewed shortly before its lease runs out - a
        // long-running process must not keep presenting a token the vault
        // already expired.
        private string livetoken;
        private DateTimeOffset renewat = DateTimeOffset.MaxValue;

        public HashicorpProvider(string addr, string token, string mount = null, int kv = 0,
            string vaultnamespace = null, Dictionary<string, object> auth = null)
        {
            this.addr = addr ?? "";
            this.mount = string.IsNullOrEmpty(mount) ? "secret" : mount;
            this.kv = 0 == kv ? 2 : kv;

            // A version typo like kv: 3 must not quietly behave as v2 and
            // turn its 404s into misses; there is nothing safe to assume it
            // meant.
            if (1 != this.kv && 2 != this.kv)
            {
                throw new SekretoError(
                    "sekreto: hashicorp: unsupported kv version: " + this.kv);
            }

            this.vaultnamespace = vaultnamespace;
            this.auth = auth;
            this.livetoken = string.IsNullOrEmpty(token) ? null : token;
        }

        private Dictionary<string, string> BaseHeaders()
        {
            var headers = new Dictionary<string, string>();

            if (!string.IsNullOrEmpty(vaultnamespace))
            {
                headers["X-Vault-Namespace"] = vaultnamespace;
            }

            return headers;
        }

        private string Login()
        {
            if (null == auth)
            {
                throw new SekretoError("sekreto: hashicorp: no token and no auth method");
            }

            string method = Providers.Text(auth.GetValueOrDefault("method"));
            string authmount = Providers.Text(auth.GetValueOrDefault("mount"));
            if (string.IsNullOrEmpty(authmount))
            {
                authmount = method;
            }

            string url = addr.TrimEnd('/') + "/v1/auth/" + authmount + "/login";

            var body = new Dictionary<string, object>();

            if ("kubernetes" == method)
            {
                string jwt = Providers.Text(auth.GetValueOrDefault("jwt"));

                if (null == jwt)
                {
                    string file = Providers.Text(auth.GetValueOrDefault("jwtfile"));
                    if (string.IsNullOrEmpty(file))
                    {
                        file = "/var/run/secrets/kubernetes.io/serviceaccount/token";
                    }

                    try
                    {
                        jwt = File.ReadAllText(file).Trim();
                    }
                    catch (Exception)
                    {
                        throw new SekretoError("sekreto: hashicorp: cannot read jwt file " + file);
                    }
                }

                body["role"] = Providers.Text(auth.GetValueOrDefault("role")) ?? "";
                body["jwt"] = jwt;
            }
            else if ("approle" == method)
            {
                body["role_id"] = Providers.Text(auth.GetValueOrDefault("roleid")) ?? "";
                body["secret_id"] = Providers.Text(auth.GetValueOrDefault("secretid")) ?? "";
            }
            else
            {
                throw new SekretoError(
                    "sekreto: hashicorp: unknown auth method: " + (method ?? ""));
            }

            var (status, resbody) = Http.FetchJson("POST", url, BaseHeaders(), Json.Stringify(body));

            var authbody = (resbody as Dictionary<string, object>)?.GetValueOrDefault("auth")
                as Dictionary<string, object>;
            object got = authbody?.GetValueOrDefault("client_token");
            string token = null == got ? null : Convert.ToString(got);

            if (200 != status || string.IsNullOrEmpty(token))
            {
                throw new SekretoError("sekreto: hashicorp login failed: " + status + ": " + url);
            }

            renewat = Providers.RenewAt(authbody.GetValueOrDefault("lease_duration"));

            return token;
        }

        public string Lookup(string name)
        {
            Addr.Check(addr);

            if (null == livetoken || DateTimeOffset.UtcNow >= renewat)
            {
                livetoken = Login();
            }

            Dictionary<string, object> reference = Names.VaultRef(name);
            string basepath = addr.TrimEnd('/') + "/v1/" + mount;
            string url = 1 == kv
                ? basepath + "/" + reference["path"]
                : basepath + "/data/" + reference["path"];

            var headers = BaseHeaders();
            headers["X-Vault-Token"] = livetoken;

            var (status, body) = Http.FetchJson("GET", url, headers);

            if (404 == status)
            {
                return null;
            }

            if (200 != status)
            {
                throw new SekretoError("sekreto: hashicorp error: " + status + ": " + url);
            }

            object outer = (body as Dictionary<string, object>)?.GetValueOrDefault("data");

            object data = 1 == kv
                ? outer
                : (outer as Dictionary<string, object>)?.GetValueOrDefault("data");

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
    /// <para>Two ways in, both boru's own.</para>
    ///
    /// <para>With no addr, the CLI: `boru vault get --reveal &lt;alias&gt;`
    /// prints the secret on stdout and nothing else. The passphrase is read
    /// by boru itself from BORU_VAULT_PASSPHRASE; sekreto never accepts it
    /// as config and never puts it on a command line, where it would show up
    /// in the process table.</para>
    ///
    /// <para>With an addr, boru's wire protocol: `boru vault serve`
    /// publishes a read-only, HashiCorp-shaped provision API (boru's
    /// design/VAULT-WIRE-PROTOCOL.0.md), authenticated by a capability token
    /// from `boru vault grant`. A sekreto name is already a valid boru
    /// alias, and boru aliases keep their dots, so `api.token` is the single
    /// path segment `api.token` - not the `api`/`token` split a HashiCorp KV
    /// gets. The value is the `value` field. A 404 is a miss; anything else
    /// the server refuses (a revoked capability, a sealed vault) is an
    /// error.</para>
    ///
    /// <para>boru's `vault proxy` and `vault mcp` remain out of bounds: they
    /// are a credential *broker*, built precisely so the caller never
    /// receives the credential. `vault serve` is the provision endpoint,
    /// built to hand the value back - that is the one sekreto uses.</para>
    /// </summary>
    public class BoruProvider : IProvider
    {
        private readonly string command;
        private readonly string namespace_;
        private readonly string home;
        private readonly string addr;
        private readonly string token;
        private readonly string mount;

        public BoruProvider(string command, string namespace_ = null, string home = null,
            string addr = null, string token = null, string mount = null)
        {
            this.command = string.IsNullOrEmpty(command) ? "boru" : command;
            this.namespace_ = namespace_;
            this.home = home;
            this.addr = string.IsNullOrEmpty(addr) ? null : addr.TrimEnd('/');
            this.token = token;
            this.mount = string.IsNullOrEmpty(mount) ? "secret" : mount;
        }

        public string Lookup(string name)
        {
            Names.CheckName(name);

            if (null != addr)
            {
                return WireLookup(name);
            }

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

        private string WireLookup(string name)
        {
            Addr.Check(addr);

            // The DOTTED name stays one segment: boru aliases keep their
            // dots, so there is no vaultref split here.
            string alias = string.IsNullOrEmpty(namespace_) ? name : namespace_ + "/" + name;
            string url = addr + "/v1/" + mount + "/data/" + alias;

            var (status, body) = Http.FetchJson("GET", url,
                new Dictionary<string, string> { ["X-Vault-Token"] = token ?? "" });

            if (404 == status)
            {
                return null;
            }

            if (200 != status)
            {
                throw new SekretoError("sekreto: boru serve error: " + status + ": " + url);
            }

            object data = ((body as Dictionary<string, object>)?.GetValueOrDefault("data")
                as Dictionary<string, object>)?.GetValueOrDefault("data");

            object value = (data as Dictionary<string, object>)?.GetValueOrDefault("value");

            return null == value ? null : Convert.ToString(value);
        }

        public string Describe()
        {
            if (null != addr)
            {
                return "boru:" + addr;
            }

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

    /// <summary>
    /// SecretSpec (https://secretspec.dev).
    ///
    /// <para>SecretSpec is a declaration - a `secretspec.toml` naming the
    /// secrets a project needs - plus a chain of its own backends to satisfy
    /// them from. That makes it the same shape as sekreto one level down, and
    /// the reason to support it is the same reason sekreto exists: a project
    /// that has already declared its secrets there should not have to declare
    /// them again here.</para>
    ///
    /// <para>Read through its CLI, as boru is, because that is the interface
    /// it offers a program in another language: `secretspec get API_TOKEN`
    /// prints the value on stdout and nothing else. A sekreto name maps to a
    /// SecretSpec key exactly as it maps to an environment variable -
    /// `api.token` is `API_TOKEN` - which is the convention SecretSpec's own
    /// examples use.</para>
    ///
    /// <para>backend selects one of SecretSpec's backends (`--provider`, e.g.
    /// `keyring` or `dotenv://.env`) and is called backend here only because
    /// `provider` already means something else in this library.</para>
    ///
    /// <para>A reason is required, not optional: SecretSpec records every
    /// read in an audit log and refuses to read at all without one. sekreto
    /// sends `sekreto` unless told otherwise, so the audit trail says which
    /// tool asked.</para>
    /// </summary>
    public class SecretSpecProvider : IProvider
    {
        private readonly string command;
        private readonly string file;
        private readonly string profile;
        private readonly string backend;
        private readonly string reason;
        private readonly string prefix;

        public SecretSpecProvider(string command = null, string file = null,
            string profile = null, string backend = null, string reason = null,
            string prefix = null)
        {
            this.command = string.IsNullOrEmpty(command) ? "secretspec" : command;
            this.file = file;
            this.profile = profile;
            this.backend = backend;
            this.reason = reason;
            this.prefix = prefix;
        }

        public string Lookup(string name)
        {
            string key = Names.EnvKey(name, prefix);

            var start = new ProcessStartInfo
            {
                FileName = command,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };

            // Arguments are passed one by one, never through a shell.
            if (!string.IsNullOrEmpty(file))
            {
                start.ArgumentList.Add("--file");
                start.ArgumentList.Add(file);
            }

            start.ArgumentList.Add("get");
            start.ArgumentList.Add(key);

            if (!string.IsNullOrEmpty(backend))
            {
                start.ArgumentList.Add("--provider");
                start.ArgumentList.Add(backend);
            }

            if (!string.IsNullOrEmpty(profile))
            {
                start.ArgumentList.Add("--profile");
                start.ArgumentList.Add(profile);
            }

            start.ArgumentList.Add("--reason");
            start.ArgumentList.Add(string.IsNullOrEmpty(reason) ? "sekreto" : reason);

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
                // The value and one newline, and nothing else.
                return outtext.EndsWith("\n", StringComparison.Ordinal)
                    ? outtext.Substring(0, outtext.Length - 1)
                    : outtext;
            }

            if (SecretSpecMiss(why, key))
            {
                return null;
            }

            throw new SekretoError(
                "sekreto: secretspec error: " + (0 == why.Length ? "exit " + status : why));
        }

        public string Describe()
        {
            return "secretspec" + (string.IsNullOrEmpty(backend) ? "" : ":" + backend);
        }

        /// <summary>
        /// Does this SecretSpec failure mean "no such secret" rather than "I
        /// could not answer"?
        ///
        /// <para>SecretSpec says `Secret 'API_TOKEN' not found` for both a
        /// name it does not declare and one declared with no value, and both
        /// are misses: this store does not hold it, so the chain carries
        /// on.</para>
        ///
        /// <para>MATCHED ON THE WHOLE PHRASE, NOT ON "not found". SecretSpec
        /// also says `Provider backend 'keyring' not found`, which is a store
        /// that could not answer at all - and reading that as a miss is the
        /// worst failure this library has, because the chain then falls
        /// through to a weaker store without saying so. The key is required
        /// to appear, so the two cannot be confused.</para>
        /// </summary>
        internal static bool SecretSpecMiss(string why, string key)
        {
            return why.Contains("Secret '" + key + "' not found");
        }
    }

    /// <summary>Region, credentials and endpoint shared by the AWS providers.</summary>
    internal sealed class AwsOptions
    {
        public string Region;
        public string Keyid;
        public string Secret;
        public string Session;
        public string Addr;
        public string Prefix;
    }

    internal static class Aws
    {
        /// <summary>The `YYYYMMDDTHHMMSSZ` timestamp SigV4 wants, for now.</summary>
        internal static string Now()
        {
            return DateTime.UtcNow.ToString("yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture);
        }

        /// <summary>
        /// Region and credentials, from config first and the standard AWS_*
        /// environment variables second - those are AWS's own convention,
        /// and a pod or CI job that has them set should just work. Missing
        /// either is an error: an AWS store with no credentials could not
        /// answer.
        /// </summary>
        internal static (string Region, string Keyid, string Secret, string Session) Auth(
            AwsOptions opts)
        {
            string region = opts.Region;
            if (string.IsNullOrEmpty(region))
            {
                region = Environment.GetEnvironmentVariable("AWS_REGION");
            }
            if (string.IsNullOrEmpty(region))
            {
                region = Environment.GetEnvironmentVariable("AWS_DEFAULT_REGION");
            }

            string keyid = string.IsNullOrEmpty(opts.Keyid)
                ? Environment.GetEnvironmentVariable("AWS_ACCESS_KEY_ID")
                : opts.Keyid;

            string secret = string.IsNullOrEmpty(opts.Secret)
                ? Environment.GetEnvironmentVariable("AWS_SECRET_ACCESS_KEY")
                : opts.Secret;

            string session = string.IsNullOrEmpty(opts.Session)
                ? Environment.GetEnvironmentVariable("AWS_SESSION_TOKEN")
                : opts.Session;

            if (string.IsNullOrEmpty(region))
            {
                throw new SekretoError("sekreto: aws: no region (set region or AWS_REGION)");
            }

            if (string.IsNullOrEmpty(keyid) || string.IsNullOrEmpty(secret))
            {
                throw new SekretoError(
                    "sekreto: aws: no credentials"
                    + " (set keyid/secret or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY)");
            }

            return (region, keyid, secret, session);
        }

        /// <summary>One signed call to an AWS JSON-1.1 API.</summary>
        internal static (int Status, object Body) Call(
            AwsOptions opts, string service, string target, Dictionary<string, object> payload)
        {
            var (region, keyid, secret, session) = Auth(opts);

            // The China partition lives under its own suffix; every other
            // commercial region is plain amazonaws.com.
            string suffix = region.StartsWith("cn-", StringComparison.Ordinal)
                ? ".amazonaws.com.cn"
                : ".amazonaws.com";
            string addr = string.IsNullOrEmpty(opts.Addr)
                ? "https://" + service + "." + region + suffix
                : opts.Addr;
            Addr.Check(addr);

            string url = addr.TrimEnd('/') + "/";
            string body = Json.Stringify(payload);

            var headers = new Dictionary<string, string>
            {
                ["content-type"] = "application/x-amz-json-1.1",
                ["x-amz-target"] = target,
            };

            var sigheaders = new Dictionary<string, object>();
            foreach (var entry in headers)
            {
                sigheaders[entry.Key] = entry.Value;
            }

            var input = new Dictionary<string, object>
            {
                ["method"] = "POST",
                ["url"] = url,
                ["headers"] = sigheaders,
                ["body"] = body,
                ["service"] = service,
                ["region"] = region,
                ["keyid"] = keyid,
                ["secret"] = secret,
                ["datetime"] = Now(),
            };
            if (!string.IsNullOrEmpty(session))
            {
                input["session"] = session;
            }

            var all = new Dictionary<string, string>(headers);
            foreach (var entry in Sigv4.Sign(input))
            {
                all[entry.Key] = Convert.ToString(entry.Value);
            }

            return Http.FetchJson("POST", url, all, body);
        }

        /// <summary>
        /// Does this AWS error body name the not-found type? That is a miss;
        /// every other failure is a store that could not answer.
        /// </summary>
        internal static bool Miss(object body, string type)
        {
            object errtype = (body as Dictionary<string, object>)?.GetValueOrDefault("__type");
            return errtype is string text && text.Contains(type);
        }
    }

    /// <summary>
    /// AWS Secrets Manager.
    ///
    /// <para>`api.token` reads the secret named `api` (the vaultref path, so
    /// `db.pass.main` reads `db/pass`) and takes the `token` field of its
    /// JSON SecretString - the AWS idiom of one JSON map per secret. A
    /// SecretString that is not JSON is the value itself, under the
    /// conventional field `value`. Requests are SigV4-signed in-tree; see
    /// Sigv4.cs.</para>
    /// </summary>
    public class AwsSecretsProvider : IProvider
    {
        private readonly AwsOptions opts;

        public AwsSecretsProvider(string region = null, string keyid = null, string secret = null,
            string session = null, string addr = null)
        {
            opts = new AwsOptions
            {
                Region = region,
                Keyid = keyid,
                Secret = secret,
                Session = session,
                Addr = addr,
            };
        }

        public string Lookup(string name)
        {
            Dictionary<string, object> reference = Names.VaultRef(name);

            var (status, body) = Aws.Call(opts, "secretsmanager", "secretsmanager.GetSecretValue",
                new Dictionary<string, object> { ["SecretId"] = reference["path"] });

            if (400 == status && Aws.Miss(body, "ResourceNotFoundException"))
            {
                return null;
            }

            if (200 != status)
            {
                throw new SekretoError("sekreto: aws secretsmanager error: " + status);
            }

            string field = (string)reference["field"];
            object text = (body as Dictionary<string, object>)?.GetValueOrDefault("SecretString");

            if (!(text is string secretstring))
            {
                // A binary secret has no fields to address; only the
                // conventional `value` field can mean "the bytes themselves".
                object bin = (body as Dictionary<string, object>)?.GetValueOrDefault("SecretBinary");
                if (bin is string encoded && "value" == field)
                {
                    return Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
                }
                return null;
            }

            object parsed = Json.Parse(secretstring);

            if (parsed is Dictionary<string, object> fields)
            {
                object value = fields.GetValueOrDefault(field);
                return null == value ? null : Convert.ToString(value);
            }

            // A plain-string secret is the whole value; it has no named
            // fields.
            return "value" == field ? secretstring : null;
        }

        // Config only, never the environment: Describe feeds the spec's
        // sources group, which must answer the same everywhere.
        public string Describe()
        {
            return "awssecrets:" + (opts.Region ?? "");
        }
    }

    /// <summary>
    /// AWS SSM Parameter Store.
    ///
    /// <para>`db.pass.main` reads the parameter `/db/pass/main` (under an
    /// optional prefix path), decrypted. Parameter Store carries flat
    /// strings, so there is no field indirection.</para>
    /// </summary>
    public class AwsParamsProvider : IProvider
    {
        private readonly AwsOptions opts;

        public AwsParamsProvider(string region = null, string keyid = null, string secret = null,
            string session = null, string addr = null, string prefix = null)
        {
            opts = new AwsOptions
            {
                Region = region,
                Keyid = keyid,
                Secret = secret,
                Session = session,
                Addr = addr,
                Prefix = prefix,
            };
        }

        public string Lookup(string name)
        {
            var (status, body) = Aws.Call(opts, "ssm", "AmazonSSM.GetParameter",
                new Dictionary<string, object>
                {
                    ["Name"] = Names.AwsParam(name, opts.Prefix),
                    ["WithDecryption"] = true,
                });

            if (400 == status && Aws.Miss(body, "ParameterNotFound"))
            {
                return null;
            }

            if (200 != status)
            {
                throw new SekretoError("sekreto: aws ssm error: " + status);
            }

            object value = ((body as Dictionary<string, object>)?.GetValueOrDefault("Parameter")
                as Dictionary<string, object>)?.GetValueOrDefault("Value");

            return null == value ? null : Convert.ToString(value);
        }

        public string Describe()
        {
            return "awsparams:" + (opts.Region ?? "") + (opts.Prefix ?? "");
        }
    }

    /// <summary>
    /// GCP Secret Manager.
    ///
    /// <para>`api.token` reads secret `api_token` (dots flattened to `_`;
    /// Secret Manager ids have no hierarchy and reject dots), latest
    /// version. The token comes from config, then
    /// GOOGLE_OAUTH_ACCESS_TOKEN, then the GCE/GKE metadata server - so on
    /// Google's own platform no credential configuration is needed at
    /// all.</para>
    ///
    /// <para>The metadata call itself is plain http to a link-local host by
    /// platform design; no credential rides on it, so Addr.Check guards the
    /// Secret Manager address instead.</para>
    /// </summary>
    public class GcpSecretsProvider : IProvider
    {
        private readonly string project;
        private readonly string token;
        private readonly string addr;
        private readonly string metadataaddr;

        // A configured token is kept forever; a metadata-server token
        // carries expires_in and is renewed shortly before it runs out.
        private string livetoken;
        private DateTimeOffset renewat = DateTimeOffset.MaxValue;

        public GcpSecretsProvider(string project = null, string token = null,
            string addr = null, string metadataaddr = null)
        {
            this.project = project;
            this.token = token;
            this.addr = addr;
            this.metadataaddr = metadataaddr;
        }

        private string MetadataAddr()
        {
            if (!string.IsNullOrEmpty(metadataaddr))
            {
                return metadataaddr;
            }

            string host = Environment.GetEnvironmentVariable("GCE_METADATA_HOST");
            return string.IsNullOrEmpty(host) ? "http://metadata.google.internal" : "http://" + host;
        }

        private string Login()
        {
            string configured = token;
            if (string.IsNullOrEmpty(configured))
            {
                configured = Environment.GetEnvironmentVariable("GOOGLE_OAUTH_ACCESS_TOKEN");
            }
            if (!string.IsNullOrEmpty(configured))
            {
                return configured;
            }

            string url = MetadataAddr().TrimEnd('/')
                + "/computeMetadata/v1/instance/service-accounts/default/token";

            var (status, body) = Http.FetchJson("GET", url,
                new Dictionary<string, string> { ["Metadata-Flavor"] = "Google" });

            object got = (body as Dictionary<string, object>)?.GetValueOrDefault("access_token");
            string text = null == got ? null : Convert.ToString(got);

            if (200 != status || string.IsNullOrEmpty(text))
            {
                throw new SekretoError("sekreto: gcp: no token and metadata server did not answer");
            }

            renewat = Providers.RenewAt(
                (body as Dictionary<string, object>)?.GetValueOrDefault("expires_in"));

            return text;
        }

        public string Lookup(string name)
        {
            if (string.IsNullOrEmpty(project))
            {
                throw new SekretoError("sekreto: gcp: no project");
            }

            string useaddr = string.IsNullOrEmpty(addr) ? "https://secretmanager.googleapis.com" : addr;
            Addr.Check(useaddr);

            if (null == livetoken || DateTimeOffset.UtcNow >= renewat)
            {
                livetoken = Login();
            }

            string url = useaddr.TrimEnd('/') + "/v1/projects/" + project + "/secrets/"
                + Names.FlatName(name, "_") + "/versions/latest:access";

            var (status, body) = Http.FetchJson("GET", url,
                new Dictionary<string, string> { ["authorization"] = "Bearer " + livetoken });

            if (404 == status)
            {
                return null;
            }

            if (200 != status)
            {
                throw new SekretoError("sekreto: gcp error: " + status + ": " + url);
            }

            object data = ((body as Dictionary<string, object>)?.GetValueOrDefault("payload")
                as Dictionary<string, object>)?.GetValueOrDefault("data");

            if (!(data is string encoded))
            {
                return null;
            }

            return Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
        }

        public string Describe()
        {
            return "gcpsecrets:" + (project ?? "");
        }
    }

    /// <summary>
    /// Azure Key Vault.
    ///
    /// <para>`api.token` reads secret `api-token` (dots flattened to `-`;
    /// Key Vault names allow nothing else), current version. The token comes
    /// from config, then a client-credentials login when
    /// tenant/clientid/clientsecret are given, then the IMDS
    /// managed-identity endpoint - so on Azure's own platform no credential
    /// configuration is needed.</para>
    ///
    /// <para>As with GCP, the IMDS call is plain http to a link-local host
    /// by platform design and carries no credential; the login and vault
    /// addresses are Addr.Check-guarded.</para>
    /// </summary>
    public class AzureSecretsProvider : IProvider
    {
        private const string Resource = "https://vault.azure.net";

        private readonly string vault;
        private readonly string token;
        private readonly string tenant;
        private readonly string clientid;
        private readonly string clientsecret;
        private readonly string loginaddr;
        private readonly string imdsaddr;
        private readonly string apiversion;

        // A configured token is kept forever; logged-in and IMDS tokens
        // carry expires_in and are renewed shortly before they run out.
        private string livetoken;
        private DateTimeOffset renewat = DateTimeOffset.MaxValue;

        public AzureSecretsProvider(string vault = null, string token = null, string tenant = null,
            string clientid = null, string clientsecret = null, string loginaddr = null,
            string imdsaddr = null, string apiversion = null)
        {
            this.vault = vault;
            this.token = token;
            this.tenant = tenant;
            this.clientid = clientid;
            this.clientsecret = clientsecret;
            this.loginaddr = loginaddr;
            this.imdsaddr = imdsaddr;
            this.apiversion = apiversion;
        }

        private string Login()
        {
            if (!string.IsNullOrEmpty(token))
            {
                return token;
            }

            if (!string.IsNullOrEmpty(tenant) && !string.IsNullOrEmpty(clientid)
                && !string.IsNullOrEmpty(clientsecret))
            {
                string uselogin = string.IsNullOrEmpty(loginaddr)
                    ? "https://login.microsoftonline.com"
                    : loginaddr;
                Addr.Check(uselogin);

                string url = uselogin.TrimEnd('/') + "/" + tenant + "/oauth2/v2.0/token";
                string form = "grant_type=client_credentials&client_id=" + Url.Encode(clientid)
                    + "&client_secret=" + Url.Encode(clientsecret)
                    + "&scope=" + Url.Encode(Resource + "/.default");

                var (status, body) = Http.FetchJson("POST", url,
                    new Dictionary<string, string>
                    {
                        ["content-type"] = "application/x-www-form-urlencoded",
                    },
                    form);

                object got = (body as Dictionary<string, object>)?.GetValueOrDefault("access_token");
                string text = null == got ? null : Convert.ToString(got);

                if (200 != status || string.IsNullOrEmpty(text))
                {
                    throw new SekretoError("sekreto: azure login failed: " + status);
                }

                renewat = Providers.RenewAt(
                    (body as Dictionary<string, object>)?.GetValueOrDefault("expires_in"));

                return text;
            }

            string imds = (string.IsNullOrEmpty(imdsaddr) ? "http://169.254.169.254" : imdsaddr)
                .TrimEnd('/')
                + "/metadata/identity/oauth2/token?api-version=2018-02-01&resource="
                + Url.Encode(Resource);

            var (imdsstatus, imdsbody) = Http.FetchJson("GET", imds,
                new Dictionary<string, string> { ["Metadata"] = "true" });

            object found = (imdsbody as Dictionary<string, object>)?.GetValueOrDefault("access_token");
            string foundtext = null == found ? null : Convert.ToString(found);

            if (200 != imdsstatus || string.IsNullOrEmpty(foundtext))
            {
                throw new SekretoError(
                    "sekreto: azure: no token, no client credentials, and IMDS did not answer");
            }

            renewat = Providers.RenewAt(
                (imdsbody as Dictionary<string, object>)?.GetValueOrDefault("expires_in"));

            return foundtext;
        }

        public string Lookup(string name)
        {
            if (string.IsNullOrEmpty(vault))
            {
                throw new SekretoError("sekreto: azure: no vault");
            }

            // Only an explicit scheme is a URL; a vault NAMED httpvault must
            // still become https://httpvault.vault.azure.net.
            string vaulturl = vault.StartsWith("http://", StringComparison.Ordinal)
                || vault.StartsWith("https://", StringComparison.Ordinal)
                ? vault
                : "https://" + vault + ".vault.azure.net";
            Addr.Check(vaulturl);

            if (null == livetoken || DateTimeOffset.UtcNow >= renewat)
            {
                livetoken = Login();
            }

            string url = vaulturl.TrimEnd('/') + "/secrets/" + Names.FlatName(name, "-")
                + "?api-version=" + (string.IsNullOrEmpty(apiversion) ? "7.4" : apiversion);

            var (status, body) = Http.FetchJson("GET", url,
                new Dictionary<string, string> { ["authorization"] = "Bearer " + livetoken });

            if (404 == status)
            {
                return null;
            }

            if (200 != status)
            {
                throw new SekretoError(
                    "sekreto: azure error: " + status + ": " + url.Split('?')[0]);
            }

            object value = (body as Dictionary<string, object>)?.GetValueOrDefault("value");

            return null == value ? null : Convert.ToString(value);
        }

        public string Describe()
        {
            return "azuresecrets:" + (vault ?? "");
        }
    }

    /// <summary>
    /// 1Password, through a Connect server.
    ///
    /// <para>The item titled `api.token` (titles keep their dots), in the
    /// named vault. The value is the field with purpose PASSWORD, or the
    /// field labelled `value`. A vault that cannot be found is an error -
    /// config names it, so its absence is a broken store, not a missing
    /// secret.</para>
    /// </summary>
    public class OnePasswordProvider : IProvider
    {
        private readonly string addr;
        private readonly string token;
        private readonly string vault;

        private string vaultid;

        public OnePasswordProvider(string addr = null, string token = null, string vault = null)
        {
            this.addr = addr;
            this.token = token;
            this.vault = vault;
        }

        private Dictionary<string, string> Auth()
        {
            return new Dictionary<string, string>
            {
                ["authorization"] = "Bearer " + (token ?? ""),
            };
        }

        private string ResolveVault(string useaddr)
        {
            string want = vault ?? "";
            if ("" == want)
            {
                throw new SekretoError("sekreto: onepassword: no vault");
            }

            var (status, body) = Http.FetchJson("GET", useaddr + "/v1/vaults", Auth());

            if (200 != status || !(body is List<object> listing))
            {
                throw new SekretoError("sekreto: onepassword error: " + status + ": listing vaults");
            }

            foreach (object entry in listing)
            {
                if (entry is Dictionary<string, object> found)
                {
                    object id = found.GetValueOrDefault("id");
                    if (want.Equals(id) || want.Equals(found.GetValueOrDefault("name")))
                    {
                        return Convert.ToString(id);
                    }
                }
            }

            throw new SekretoError("sekreto: onepassword: no vault named " + want);
        }

        public string Lookup(string name)
        {
            Names.CheckName(name);

            string useaddr = (addr ?? "").TrimEnd('/');
            if ("" == useaddr)
            {
                throw new SekretoError("sekreto: onepassword: no addr");
            }
            Addr.Check(useaddr);

            if (null == vaultid)
            {
                vaultid = ResolveVault(useaddr);
            }

            string filter = Url.Encode("title eq \"" + name + "\"");

            var (foundstatus, foundbody) = Http.FetchJson("GET",
                useaddr + "/v1/vaults/" + vaultid + "/items?filter=" + filter, Auth());

            if (200 != foundstatus || !(foundbody is List<object> matches))
            {
                throw new SekretoError(
                    "sekreto: onepassword error: " + foundstatus + ": finding " + name);
            }

            if (0 == matches.Count)
            {
                return null;
            }

            string itemid = Convert.ToString(
                (matches[0] as Dictionary<string, object>)?.GetValueOrDefault("id"));

            var (itemstatus, itembody) = Http.FetchJson("GET",
                useaddr + "/v1/vaults/" + vaultid + "/items/" + itemid, Auth());

            if (200 != itemstatus)
            {
                throw new SekretoError(
                    "sekreto: onepassword error: " + itemstatus + ": reading " + name);
            }

            var fields = (itembody as Dictionary<string, object>)?.GetValueOrDefault("fields")
                as List<object> ?? new List<object>();

            foreach (object entry in fields)
            {
                if (entry is Dictionary<string, object> field
                    && "PASSWORD".Equals(field.GetValueOrDefault("purpose")))
                {
                    object value = field.GetValueOrDefault("value");
                    return null == value ? null : Convert.ToString(value);
                }
            }
            foreach (object entry in fields)
            {
                if (entry is Dictionary<string, object> field
                    && "value".Equals(field.GetValueOrDefault("label")))
                {
                    object value = field.GetValueOrDefault("value");
                    return null == value ? null : Convert.ToString(value);
                }
            }

            return null;
        }

        public string Describe()
        {
            return "onepassword:" + (vault ?? "");
        }
    }

    /// <summary>
    /// Doppler.
    ///
    /// <para>The whole config is downloaded once - Doppler's own bulk
    /// endpoint - and answered from memory, like a remote .env: `api.token`
    /// is the `API_TOKEN` entry. A service token is config-scoped, so
    /// project and config are only needed with broader tokens.</para>
    /// </summary>
    public class DopplerProvider : IProvider
    {
        private readonly string token;
        private readonly string project;
        private readonly string config;
        private readonly string addr;

        private Dictionary<string, string> values;

        public DopplerProvider(string token = null, string project = null,
            string config = null, string addr = null)
        {
            this.token = token;
            this.project = project;
            this.config = config;
            this.addr = addr;
        }

        private Dictionary<string, string> Load()
        {
            if (null != values)
            {
                return values;
            }

            string useaddr = (string.IsNullOrEmpty(addr) ? "https://api.doppler.com" : addr)
                .TrimEnd('/');
            Addr.Check(useaddr);

            string url = useaddr + "/v3/configs/config/secrets/download?format=json";
            if (!string.IsNullOrEmpty(project))
            {
                url += "&project=" + Url.Encode(project);
            }
            if (!string.IsNullOrEmpty(config))
            {
                url += "&config=" + Url.Encode(config);
            }

            var (status, body) = Http.FetchJson("GET", url,
                new Dictionary<string, string> { ["authorization"] = "Bearer " + (token ?? "") });

            if (200 != status || !(body is Dictionary<string, object> entries))
            {
                throw new SekretoError("sekreto: doppler error: " + status);
            }

            values = new Dictionary<string, string>();
            foreach (var entry in entries)
            {
                if (null != entry.Value)
                {
                    values[entry.Key] = Convert.ToString(entry.Value);
                }
            }

            return values;
        }

        public string Lookup(string name)
        {
            return Load().TryGetValue(Names.EnvKey(name), out string found) ? found : null;
        }

        public string Describe()
        {
            return "doppler"
                + (string.IsNullOrEmpty(project) ? "" : ":" + project + "/" + (config ?? ""));
        }
    }

    /// <summary>
    /// Infisical.
    ///
    /// <para>`api.token` reads the secret keyed `API_TOKEN` (Infisical's own
    /// convention is environment-style keys) at a secret path in one
    /// environment of a project. Auth is a token, or a universal-auth
    /// (machine identity) login with clientid/clientsecret.</para>
    /// </summary>
    public class InfisicalProvider : IProvider
    {
        private readonly string addr;
        private readonly string token;
        private readonly string clientid;
        private readonly string clientsecret;
        private readonly string project;
        private readonly string environment;
        private readonly string path;

        // A configured token is kept forever; a universal-auth token
        // carries expiresIn and is renewed shortly before it runs out.
        private string livetoken;
        private DateTimeOffset renewat = DateTimeOffset.MaxValue;

        public InfisicalProvider(string addr = null, string token = null, string clientid = null,
            string clientsecret = null, string project = null, string environment = null,
            string path = null)
        {
            this.addr = addr;
            this.token = token;
            this.clientid = clientid;
            this.clientsecret = clientsecret;
            this.project = project;
            this.environment = environment;
            this.path = path;
        }

        private string Login(string useaddr)
        {
            if (!string.IsNullOrEmpty(token))
            {
                return token;
            }

            if (string.IsNullOrEmpty(clientid) || string.IsNullOrEmpty(clientsecret))
            {
                throw new SekretoError("sekreto: infisical: no token and no client credentials");
            }

            var payload = new Dictionary<string, object>
            {
                ["clientId"] = clientid,
                ["clientSecret"] = clientsecret,
            };

            var (status, body) = Http.FetchJson("POST",
                useaddr + "/api/v1/auth/universal-auth/login",
                new Dictionary<string, string> { ["content-type"] = "application/json" },
                Json.Stringify(payload));

            object got = (body as Dictionary<string, object>)?.GetValueOrDefault("accessToken");
            string text = null == got ? null : Convert.ToString(got);

            if (200 != status || string.IsNullOrEmpty(text))
            {
                throw new SekretoError("sekreto: infisical login failed: " + status);
            }

            renewat = Providers.RenewAt(
                (body as Dictionary<string, object>)?.GetValueOrDefault("expiresIn"));

            return text;
        }

        public string Lookup(string name)
        {
            string useaddr = (string.IsNullOrEmpty(addr) ? "https://app.infisical.com" : addr)
                .TrimEnd('/');
            Addr.Check(useaddr);

            if (string.IsNullOrEmpty(project) || string.IsNullOrEmpty(environment))
            {
                throw new SekretoError("sekreto: infisical: no project/environment");
            }

            if (null == livetoken || DateTimeOffset.UtcNow >= renewat)
            {
                livetoken = Login(useaddr);
            }

            string url = useaddr + "/api/v3/secrets/raw/" + Names.EnvKey(name)
                + "?workspaceId=" + Url.Encode(project)
                + "&environment=" + Url.Encode(environment)
                + "&secretPath=" + Url.Encode(string.IsNullOrEmpty(path) ? "/" : path);

            var (status, body) = Http.FetchJson("GET", url,
                new Dictionary<string, string> { ["authorization"] = "Bearer " + livetoken });

            if (404 == status)
            {
                return null;
            }

            if (200 != status)
            {
                throw new SekretoError("sekreto: infisical error: " + status);
            }

            object value = ((body as Dictionary<string, object>)?.GetValueOrDefault("secret")
                as Dictionary<string, object>)?.GetValueOrDefault("secretValue");

            return null == value ? null : Convert.ToString(value);
        }

        public string Describe()
        {
            return "infisical:" + (project ?? "") + "/" + (environment ?? "");
        }
    }

    public static class Providers
    {
        internal static string Text(object value)
        {
            return null == value ? null : Convert.ToString(value);
        }

        internal static string TextOr(object value, string fallback)
        {
            return null == value ? fallback : Convert.ToString(value);
        }

        /// <summary>
        /// The instant a logged-in token should be renewed: shortly before
        /// an expiry given in seconds runs out (now + max(seconds - 60, 1)),
        /// or never when the expiry is missing, zero or unreadable. Azure's
        /// endpoints may send expires_in as a string, so numeric text
        /// counts.
        /// </summary>
        internal static DateTimeOffset RenewAt(object expires)
        {
            double seconds;

            try
            {
                seconds = null == expires
                    ? 0
                    : Convert.ToDouble(expires, CultureInfo.InvariantCulture);
            }
            catch (FormatException)
            {
                seconds = 0;
            }
            catch (InvalidCastException)
            {
                seconds = 0;
            }
            catch (OverflowException)
            {
                seconds = 0;
            }

            // A century outruns any real lease; anything longer (or NaN)
            // simply never renews, like a missing expiry - and stays
            // representable as a timestamp.
            if (double.IsNaN(seconds) || 0 >= seconds || 3153600000d < seconds)
            {
                return DateTimeOffset.MaxValue;
            }

            return DateTimeOffset.UtcNow.AddSeconds(Math.Max(seconds - 60, 1));
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

                case "file":
                    return new FileProvider(
                        TextOr(spec.GetValueOrDefault("dir"), ""),
                        Text(spec.GetValueOrDefault("prefix")));

                case "hashicorp":
                    return new HashicorpProvider(
                        TextOr(spec.GetValueOrDefault("addr"), ""),
                        TextOr(spec.GetValueOrDefault("token"), ""),
                        Text(spec.GetValueOrDefault("mount")),
                        null == spec.GetValueOrDefault("kv")
                            ? 0
                            : Convert.ToInt32(spec.GetValueOrDefault("kv"), CultureInfo.InvariantCulture),
                        Text(spec.GetValueOrDefault("vaultnamespace")),
                        spec.GetValueOrDefault("auth") as Dictionary<string, object>);

                case "boru":
                    return new BoruProvider(
                        Text(spec.GetValueOrDefault("command")),
                        Text(spec.GetValueOrDefault("namespace")),
                        Text(spec.GetValueOrDefault("home")),
                        Text(spec.GetValueOrDefault("addr")),
                        Text(spec.GetValueOrDefault("token")),
                        Text(spec.GetValueOrDefault("mount")));

                case "awssecrets":
                    return new AwsSecretsProvider(
                        Text(spec.GetValueOrDefault("region")),
                        Text(spec.GetValueOrDefault("keyid")),
                        Text(spec.GetValueOrDefault("secret")),
                        Text(spec.GetValueOrDefault("session")),
                        Text(spec.GetValueOrDefault("addr")));

                case "awsparams":
                    return new AwsParamsProvider(
                        Text(spec.GetValueOrDefault("region")),
                        Text(spec.GetValueOrDefault("keyid")),
                        Text(spec.GetValueOrDefault("secret")),
                        Text(spec.GetValueOrDefault("session")),
                        Text(spec.GetValueOrDefault("addr")),
                        Text(spec.GetValueOrDefault("prefix")));

                case "gcpsecrets":
                    return new GcpSecretsProvider(
                        Text(spec.GetValueOrDefault("project")),
                        Text(spec.GetValueOrDefault("token")),
                        Text(spec.GetValueOrDefault("addr")),
                        Text(spec.GetValueOrDefault("metadataaddr")));

                case "azuresecrets":
                    return new AzureSecretsProvider(
                        Text(spec.GetValueOrDefault("vault")),
                        Text(spec.GetValueOrDefault("token")),
                        Text(spec.GetValueOrDefault("tenant")),
                        Text(spec.GetValueOrDefault("clientid")),
                        Text(spec.GetValueOrDefault("clientsecret")),
                        Text(spec.GetValueOrDefault("loginaddr")),
                        Text(spec.GetValueOrDefault("imdsaddr")),
                        Text(spec.GetValueOrDefault("apiversion")));

                case "onepassword":
                    return new OnePasswordProvider(
                        Text(spec.GetValueOrDefault("addr")),
                        Text(spec.GetValueOrDefault("token")),
                        Text(spec.GetValueOrDefault("vault")));

                case "doppler":
                    return new DopplerProvider(
                        Text(spec.GetValueOrDefault("token")),
                        Text(spec.GetValueOrDefault("project")),
                        Text(spec.GetValueOrDefault("config")),
                        Text(spec.GetValueOrDefault("addr")));

                case "infisical":
                    return new InfisicalProvider(
                        Text(spec.GetValueOrDefault("addr")),
                        Text(spec.GetValueOrDefault("token")),
                        Text(spec.GetValueOrDefault("clientid")),
                        Text(spec.GetValueOrDefault("clientsecret")),
                        Text(spec.GetValueOrDefault("project")),
                        Text(spec.GetValueOrDefault("environment")),
                        Text(spec.GetValueOrDefault("path")));

                case "secretspec":
                    return new SecretSpecProvider(
                        Text(spec.GetValueOrDefault("command")),
                        Text(spec.GetValueOrDefault("file")),
                        Text(spec.GetValueOrDefault("profile")),
                        Text(spec.GetValueOrDefault("backend")),
                        Text(spec.GetValueOrDefault("reason")),
                        Text(spec.GetValueOrDefault("prefix")));

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
