// The providers a Sekreto chains together.
//
// A provider answers one question: "do you have this secret?" It returns
// the value, or null to mean "ask the next one". Nothing else about a
// provider is visible to the caller - which is the point: an app reads
// `api.token` and never learns whether it came from the environment, a
// .env file, HashiCorp Vault, AWS, GCP, Azure or a boru vault.
//
// Two failure shapes, and they are never interchangeable. A store that does
// not hold the secret is a MISS (null) - the chain carries on. A store that
// could not answer - bad credentials, unreachable host, missing
// configuration - is an ERROR: falling through there would quietly reach
// for a weaker store.
//
// A port of typescript/src/Providers.ts, which is canonical.

package com.voxgig.sekreto

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.NoSuchFileException
import java.nio.file.Path
import java.nio.file.Paths
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Base64

/**
 * Logging in to a vault instead of being handed a token. `method` is
 * `kubernetes` or `approle`; `mount` defaults to the method name.
 */
data class AuthSpec(
    val method: String,
    val mount: String? = null,
    /** kubernetes: the Vault role to log in as. */
    val role: String? = null,
    /** kubernetes: the service-account JWT itself (tests). */
    val jwt: String? = null,
    /** kubernetes: where the JWT lives; the conventional pod path by default. */
    val jwtfile: String? = null,
    /** approle: the role and secret ids. */
    val roleid: String? = null,
    val secretid: String? = null,
) {
    /**
     * Printed without its credentials.
     *
     * A `data class` generates a `toString` that prints every field, so
     * `logger.error("bad chain: $specs")` - which is what someone writes
     * when a chain will not build - would put the service-account JWT and
     * the AppRole secret id in the log. Fields that hold a credential
     * report whether they are set, never what they are.
     */
    override fun toString(): String =
        "AuthSpec(method=$method, mount=$mount, role=$role, jwtfile=$jwtfile, " +
            "roleid=$roleid, jwt=${setornot(jwt)}, secretid=${setornot(secretid)})"
}

/** What a credential field reports about itself. */
internal fun setornot(value: String?): String =
    if (value.isNullOrEmpty()) "[unset]" else "[set]"

/**
 * The declarative form of a provider, as used in config and in the shared
 * spec. `kind` picks the provider; everything else is that kind's own.
 */
data class ProviderSpec(
    val kind: String,
    /** The store name `Sekreto.getfrom` addresses. Defaults to `kind`. */
    val name: String? = null,
    val prefix: String? = null,
    /** dotenv: the file to read. secretspec: the declaration to read. */
    val file: String? = null,
    /** memory: literal values, keyed like environment variables. */
    val values: Map<String, String>? = null,
    /** file: the directory of one-secret-per-file entries. */
    val dir: String? = null,
    /** hashicorp / boru (wire) / gcp / 1password / doppler / infisical: the base URL. */
    val addr: String? = null,
    /** hashicorp / boru (wire) / gcp / azure / 1password / doppler / infisical: the token. */
    val token: String? = null,
    /** hashicorp / boru (wire): the KV mount (default `secret`). */
    val mount: String? = null,
    /** hashicorp: KV engine version, 1 or 2 (default 2). */
    val kv: Int? = null,
    /** hashicorp: Vault Enterprise namespace (X-Vault-Namespace). */
    val vaultnamespace: String? = null,
    /** hashicorp: log in for a token instead of being handed one. */
    val auth: AuthSpec? = null,
    /** boru / secretspec: the executable to run (default: the kind's own
     * name). */
    val command: String? = null,
    /** secretspec: the profile to read (`--profile`). */
    val profile: String? = null,
    /** secretspec: which of ITS backends to read from (`--provider`), e.g.
     * `keyring` or `dotenv://.env`. Named `backend` here because `provider`
     * already means a sekreto provider. */
    val backend: String? = null,
    /** secretspec: the audit reason recorded for the read (`--reason`).
     * SecretSpec refuses to read without one. */
    val reason: String? = null,
    /** boru: the namespace qualifying the alias. */
    val namespace: String? = null,
    /** boru: the vault home, passed as BORU_HOME. */
    val home: String? = null,
    /** aws: region and credentials; the standard AWS_* variables fill the rest. */
    val region: String? = null,
    val keyid: String? = null,
    val secret: String? = null,
    val session: String? = null,
    /** gcp / doppler / infisical: the project, however that store names it. */
    val project: String? = null,
    /** azure: the Key Vault name or full URL. 1password: the vault name or id. */
    val vault: String? = null,
    /** azure: client-credential login. infisical: universal-auth login. */
    val tenant: String? = null,
    val clientid: String? = null,
    val clientsecret: String? = null,
    /** azure: where to log in / where IMDS answers. gcp: the metadata server. */
    val loginaddr: String? = null,
    val imdsaddr: String? = null,
    val metadataaddr: String? = null,
    /** azure: the Key Vault API version (default 7.4). */
    val apiversion: String? = null,
    /** doppler: the config slug (with `project`). */
    val config: String? = null,
    /** infisical: the environment slug and secret path. */
    val environment: String? = null,
    val path: String? = null,
) {
    /**
     * Printed without its credentials. See AuthSpec.toString: the generated
     * one would put the Vault token, the AWS secret access key and the
     * Azure client secret into whatever formatted it.
     */
    override fun toString(): String =
        "ProviderSpec(kind=$kind, name=$name, addr=$addr, token=${setornot(token)}, " +
            "secret=${setornot(secret)}, clientsecret=${setornot(clientsecret)}, auth=$auth)"
}

object Providers {

    /** How long any single vault round-trip may take before it is treated
     * as unreachable. Ports carry the same bound. */
    private val TIMEOUT: Duration = Duration.ofSeconds(10)

    /**
     * Does this read failure mean "no secrets here", rather than "I could not
     * answer"?
     *
     * Absence is a MISS and the chain carries on; anything else - permission
     * denied, an unreadable mount, a failing disk - is an ERROR, because
     * returning a miss there falls silently through to a weaker store.
     *
     * Asked of the directory, not of the file. The obvious spelling,
     * `!Files.exists(file)`, is wrong in exactly the case the rule exists
     * for: `Files.exists` is "did checkAccess throw", so it answers *false*
     * for an `AccessDeniedException` and turned a locked directory - the
     * canonical "unreadable mount" - into a miss. A path whose parent is a
     * plain file (ENOTDIR) really is "no secrets here", and that is what this
     * asks. The reason string is not consulted: it comes from the C library's
     * strerror and follows the machine's locale.
     */
    internal fun absent(file: Path): Boolean {
        val dir = file.parent
        return null != dir && !Files.isDirectory(dir)
    }

    /** What a finished child process left behind. */
    internal data class Ran(val out: String, val why: String, val status: Int)

    /**
     * Run a child to completion and collect both its streams.
     *
     * The two streams are drained CONCURRENTLY. Reading stdout to EOF and
     * only then reading stderr deadlocks the moment the child writes more
     * than one pipe buffer (64 KiB on Linux) to stderr: the parent is blocked
     * waiting for stdout, the child is blocked waiting for room on stderr,
     * and neither can move. Nothing in this library sets a timeout, so that
     * hang is permanent - `get()` simply never returns. secretspec's
     * diagnostics are box-drawn and reach that size easily.
     *
     * The child's stdin is closed rather than left open on a pipe nobody
     * writes to, so a CLI that reads it - one prompting for a passphrase when
     * its environment variable is absent - sees EOF and gives up instead of
     * waiting forever.
     */
    internal fun runcmd(builder: ProcessBuilder, command: String): Ran {
        try {
            val process = builder.start()

            process.outputStream.close()

            val errbuf = ByteArrayOutputStream()
            val drain = Thread {
                try {
                    process.errorStream.transferTo(errbuf)
                } catch (err: IOException) {
                    // The child went away mid-write; waitFor reports how.
                }
            }
            drain.isDaemon = true
            drain.start()

            val out = String(process.inputStream.readAllBytes(), StandardCharsets.UTF_8)
            val status = process.waitFor()
            drain.join()

            return Ran(out, String(errbuf.toByteArray(), StandardCharsets.UTF_8).trim(), status)
        } catch (err: IOException) {
            throw SekretoError("sekreto: cannot run $command: ${err.message}")
        } catch (err: InterruptedException) {
            Thread.currentThread().interrupt()
            throw SekretoError("sekreto: interrupted running $command")
        }
    }

    // HTTP/1.1, explicitly.
    //
    // java.net.http defaults to HTTP_2, and over cleartext that means an h2c
    // upgrade: the first request goes out with `Upgrade: h2c`, the declared
    // Content-Length, and NO BODY, and the body follows only after the
    // server declines. A server that checks the two against each other -
    // Fastify does, and Infisical is Fastify - rejects that request outright
    // with "Request body size did not match Content-Length", so every POST
    // this port makes to such a server fails before it is even read.
    //
    // The mocks in test/ are Node's own http module, which does not object,
    // which is why this survived until the same code met a real Infisical.
    // No vault API this library speaks needs HTTP/2.
    //
    // Redirects are never followed: a vault API does not legitimately
    // redirect, and a followed redirect would carry X-Vault-Token to the
    // redirect's host (and could downgrade https to http), which checkaddr -
    // it only validates the configured address - cannot see.
    private val CLIENT: HttpClient = HttpClient.newBuilder()
        .version(HttpClient.Version.HTTP_1_1)
        .followRedirects(HttpClient.Redirect.NEVER)
        .connectTimeout(TIMEOUT)
        .build()

    /** One JSON round-trip's result: the status, and the parsed body. */
    internal data class Answer(val status: Int, val body: Json?)

    /**
     * An address with any userinfo replaced by `[redacted]`, for messages.
     *
     * Every refusal below names the address it refused, and one of them fires
     * precisely because the address carries a credential - so printing it
     * verbatim wrote the password to stderr and into the logs. It cannot be
     * cleaned up afterwards either: that password was never resolved as a
     * secret, so redact() has never seen it and never will. The host is what
     * a reader needs to identify which chain entry is at fault; the userinfo
     * is not.
     */
    internal fun safeaddr(addr: String): String {
        val mark = addr.indexOf("://")
        if (-1 == mark) {
            return addr
        }

        val rest = addr.substring(mark + 3)
        val stop = rest.indexOfFirst { it in "/?#" }
        val authority = if (-1 == stop) rest else rest.substring(0, stop)

        val at = authority.lastIndexOf('@')
        if (-1 == at) {
            return addr
        }

        return addr.substring(0, mark + 3) + "[redacted]" + addr.substring(mark + 3 + at)
    }

    /**
     * Refuse to send a secret-bearing credential in the clear.
     *
     * A vault API is HTTPS in any real deployment; plaintext is a dev-mode
     * convenience. Sending a token over http to anything but the local
     * machine puts both the token and the secret it fetches on the wire for
     * anyone on the path, so sekreto will not do it. Loopback stays allowed:
     * that is `vault server -dev`, `boru vault serve`, and this repo's own
     * test harness.
     *
     * The address is read by hand, in the same handful of steps in every
     * port, rather than by each platform's URL parser. That is deliberate.
     * Twelve parsers disagree about malformed input - where userinfo ends,
     * whether `0177.0.0.1` is loopback, what an unclosed bracket means - and
     * a check that answers differently in different ports is not a check.
     *
     * The rule this parse obeys, and the reason it can be trusted: it is
     * never more permissive than the HTTP client that will dial the address.
     * It ends the authority at `/`, `?` or `#` only, so a client that also
     * breaks on `\` (WHATWG does) can only ever see a SHORTER host than this
     * does. It refuses userinfo outright rather than locating its end. It
     * compares the host literally, so a numeric form no parser here agrees
     * on is refused rather than guessed at.
     */
    fun checkaddr(addr: String) {
        val scheme = when {
            addr.startsWith("https://") -> "https://"
            addr.startsWith("http://") -> "http://"
            else -> throw SekretoError("sekreto: not an http(s) address: ${safeaddr(addr)}")
        }

        val rest = addr.substring(scheme.length)
        val end = rest.indexOfFirst { it in "/?#" }
        val authority = if (-1 == end) rest else rest.substring(0, end)

        // Userinfo is refused outright rather than parsed around, and on
        // https as well as http. No store this library speaks authenticates
        // by userinfo - they take a token or a signature - so an address
        // carrying one is a mistake at best. At worst it is the attack this
        // whole function exists to stop:
        // `http://localhost:8200@evil.example.com/` is a request to
        // evil.example.com that reads, to anything that splits the authority
        // on ':', as loopback.
        if (authority.contains("@")) {
            throw SekretoError("sekreto: refusing an address with embedded credentials: ${safeaddr(addr)}")
        }

        // An opening bracket with no closing one is not an address at all.
        if (authority.startsWith("[") && !authority.contains("]")) {
            throw SekretoError("sekreto: not a valid http(s) address: ${safeaddr(addr)}")
        }

        if ("https://" == scheme) {
            return
        }

        // A bracketed IPv6 literal keeps its brackets. Splitting the
        // authority on the first colon yields '[', so `http://[::1]:8200`
        // could never match - which made the '[::1]' entry below unreachable,
        // and refused a legitimate local vault.
        val host = (
            if (authority.startsWith("[")) {
                authority.substring(0, authority.indexOf("]") + 1)
            } else {
                authority.substringBefore(':')
            }
            ).lowercase()

        if ("localhost" == host || "127.0.0.1" == host || "::1" == host || "[::1]" == host) {
            return
        }

        throw SekretoError(
            "sekreto: refusing to send a token in plaintext to ${safeaddr(addr)} (use https)",
        )
    }

    /**
     * One JSON round-trip. Network failure is always an error - an
     * unreachable store is a store that could not answer.
     */
    internal fun fetchjson(
        method: String,
        url: String,
        headers: Map<String, String> = emptyMap(),
        body: String? = null,
    ): Answer {
        val builder = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .timeout(TIMEOUT)
            .method(
                method,
                if (null == body) {
                    HttpRequest.BodyPublishers.noBody()
                } else {
                    HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8)
                },
            )

        for ((key, value) in headers) {
            builder.header(key, value)
        }

        val response: HttpResponse<String> = try {
            CLIENT.send(builder.build(), HttpResponse.BodyHandlers.ofString())
        } catch (err: IOException) {
            // A refused connection arrives with a null message, so the class
            // name stands in - "cannot reach ...: null" says nothing at all.
            throw SekretoError(
                "sekreto: cannot reach ${bare(url)}: ${err.message ?: err.toString()}",
            )
        } catch (err: InterruptedException) {
            Thread.currentThread().interrupt()
            throw SekretoError("sekreto: cannot reach ${bare(url)}: interrupted")
        }

        // A success status promised JSON; a body that does not parse means
        // the store could not answer coherently, and treating it as a miss
        // would fall through to a weaker store. Error statuses may carry any
        // body - they are decided on status alone.
        val parsed = Json.parse(response.body())
        if (200 == response.statusCode() && null == parsed) {
            throw SekretoError("sekreto: malformed response from ${bare(url)}")
        }

        return Answer(response.statusCode(), parsed)
    }

    /** A URL without its query string, for a message that must not leak one. */
    private fun bare(url: String): String = url.substringBefore('?')

    /** The first candidate that is set and non-empty, or empty. */
    internal fun first(vararg candidates: String?): String =
        candidates.firstOrNull { !it.isNullOrEmpty() } ?: ""

    private fun trimslash(text: String): String = text.removeSuffix("/")

    /**
     * When a logged-in token must be renewed, from its expiry in seconds (a
     * JSON number, or a string as Azure IMDS sends it): now + max(seconds -
     * 60, 1). A missing or zero expiry means never renew.
     */
    internal fun renewtime(expires: Json?): Long {
        val seconds = when (expires) {
            is Json.Num -> expires.value
            is Json.Str -> expires.value.toDoubleOrNull() ?: 0.0
            else -> 0.0
        }

        if (seconds.isNaN() || 0 >= seconds) {
            return Long.MAX_VALUE
        }

        return System.currentTimeMillis() + (maxOf(seconds - 60, 1.0) * 1000).toLong()
    }

    /** Environment variables: `api.token` from `API_TOKEN`. */
    class Env(
        private val prefix: String? = null,
        private val source: Map<String, String>? = null,
    ) : Provider {

        override fun lookup(name: String): String? {
            val key = envkey(name, prefix)
            return if (null == source) System.getenv(key) else source[key]
        }

        override fun describe(): String =
            "env" + if (prefix.isNullOrEmpty()) "" else ":$prefix"
    }

    /** A `.env` file, read once, keyed exactly like the environment. */
    class Dotenv(private val file: String, private val prefix: String? = null) : Provider {

        private var values: Map<String, String>? = null

        private fun load(): Map<String, String> {
            values?.let { return it }

            val path = Paths.get(file)

            val loaded: Map<String, String> = try {
                parsedotenv(String(Files.readAllBytes(path), StandardCharsets.UTF_8))
            } catch (err: NoSuchFileException) {
                // An absent file - or an absent directory - means "no secrets
                // here", exactly like the file provider.
                emptyMap()
            } catch (err: IOException) {
                if (absent(path)) {
                    emptyMap()
                } else {
                    throw SekretoError(
                        "sekreto: dotenv provider cannot read $file: ${err.message}",
                    )
                }
            }

            values = loaded
            return loaded
        }

        override fun lookup(name: String): String? = load()[envkey(name, prefix)]

        override fun describe(): String = "dotenv:$file"
    }

    /**
     * Literal values, keyed like environment variables. The spec uses this
     * to test chain behaviour without touching the outside world.
     */
    class Memory(
        values: Map<String, String>? = null,
        private val prefix: String? = null,
    ) : Provider {

        private val values: Map<String, String> = values ?: emptyMap()

        override fun lookup(name: String): String? = values[envkey(name, prefix)]

        override fun describe(): String =
            "memory" + if (prefix.isNullOrEmpty()) "" else ":$prefix"
    }

    /**
     * A directory of one-secret-per-file entries, keyed like the
     * environment: `api.token` reads `<dir>/API_TOKEN`.
     *
     * This is the shape of a mounted Kubernetes Secret, a Docker or Swarm
     * secret, and a systemd credentials directory, so those all work with no
     * further configuration. One trailing newline is stripped - tools that
     * write these files disagree about it, and a newline is never part of a
     * secret on purpose.
     */
    class File(dir: String?, private val prefix: String? = null) : Provider {

        private val dir: String = dir ?: ""

        override fun lookup(name: String): String? {
            val file = Paths.get(dir, envkey(name, prefix))

            val text = try {
                String(Files.readAllBytes(file), StandardCharsets.UTF_8)
            } catch (err: NoSuchFileException) {
                // An absent file - or an absent directory - means "no secrets
                // here", exactly like a missing .env.
                return null
            } catch (err: IOException) {
                if (absent(file)) {
                    return null
                }
                throw SekretoError("sekreto: file provider cannot read $file: ${err.message}")
            }

            if (text.endsWith("\r\n")) {
                return text.dropLast(2)
            }
            if (text.endsWith("\n")) {
                return text.dropLast(1)
            }

            return text
        }

        override fun describe(): String = "file:$dir"
    }

    /**
     * HashiCorp Vault.
     *
     * KV v2 (the default): `api.token` reads `{addr}/v1/{mount}/data/api` and
     * takes the `token` field of `data.data`. KV v1 (`kv: 1`) reads
     * `{addr}/v1/{mount}/api` and takes the field of `data`. A 404 means "not
     * here" - a miss - so a vault can sit in a chain with fallbacks.
     *
     * A Vault Enterprise namespace rides the X-Vault-Namespace header, on
     * logins as well as reads.
     *
     * Instead of being handed a token, the provider can log in: Kubernetes
     * auth (the pod's service-account JWT, from its conventional path) or
     * AppRole. A failed login is an error, never a miss - it means this store
     * could not answer at all.
     */
    class Hashicorp(
        addr: String?,
        token: String? = null,
        mount: String? = null,
        kv: Int? = null,
        private val vaultnamespace: String? = null,
        private val auth: AuthSpec? = null,
    ) : Provider {

        private val addr: String = addr ?: ""
        private val mount: String = if (mount.isNullOrEmpty()) "secret" else mount
        private val kv: Int = kv ?: 2

        // The working token: a configured token is kept forever, a logged-in
        // token is renewed shortly before its lease runs out - a long-running
        // process must not keep presenting a token the vault already expired.
        private var livetoken: String? = if (token.isNullOrEmpty()) null else token
        private var renewat: Long = Long.MAX_VALUE

        init {
            // A version typo like kv: 3 must not quietly behave as v2 and
            // turn its 404s into misses; there is nothing safe to assume it
            // meant.
            if (1 != this.kv && 2 != this.kv) {
                throw SekretoError("sekreto: hashicorp: unsupported kv version: ${this.kv}")
            }
        }

        private fun baseheaders(): MutableMap<String, String> {
            val out = LinkedHashMap<String, String>()
            if (!vaultnamespace.isNullOrEmpty()) {
                out["X-Vault-Namespace"] = vaultnamespace
            }
            return out
        }

        private fun login(): String {
            val use = auth ?: throw SekretoError("sekreto: hashicorp: no token and no auth method")

            val authmount = first(use.mount, use.method)
            val url = trimslash(addr) + "/v1/auth/" + authmount + "/login"

            val body = when (use.method) {
                "kubernetes" -> {
                    val jwt = use.jwt ?: run {
                        val file = use.jwtfile
                            ?: "/var/run/secrets/kubernetes.io/serviceaccount/token"
                        try {
                            String(
                                Files.readAllBytes(Paths.get(file)),
                                StandardCharsets.UTF_8,
                            ).trim()
                        } catch (err: IOException) {
                            throw SekretoError("sekreto: hashicorp: cannot read jwt file $file")
                        }
                    }
                    Json.obj("role" to Json.str(use.role ?: ""), "jwt" to Json.str(jwt))
                }
                "approle" -> Json.obj(
                    "role_id" to Json.str(use.roleid ?: ""),
                    "secret_id" to Json.str(use.secretid ?: ""),
                )
                else -> throw SekretoError(
                    "sekreto: hashicorp: unknown auth method: ${use.method}",
                )
            }

            val res = fetchjson("POST", url, baseheaders(), Json.stringify(body))

            val got = res.body?.dig("auth", "client_token")?.text
            if (200 != res.status || got.isNullOrEmpty()) {
                throw SekretoError("sekreto: hashicorp login failed: ${res.status}: $url")
            }

            renewat = renewtime(res.body?.dig("auth", "lease_duration"))

            return got
        }

        override fun lookup(name: String): String? {
            checkaddr(addr)

            if (null == livetoken || System.currentTimeMillis() >= renewat) {
                livetoken = login()
            }

            val ref = vaultref(name)
            val base = trimslash(addr) + "/v1/" + mount
            val url = if (1 == kv) "$base/${ref.path}" else "$base/data/${ref.path}"

            val headers = baseheaders()
            headers["X-Vault-Token"] = livetoken ?: ""

            val res = fetchjson("GET", url, headers)

            if (404 == res.status) {
                return null
            }

            if (200 != res.status) {
                throw SekretoError("sekreto: hashicorp error: ${res.status}: $url")
            }

            val data = if (1 == kv) res.body?.dig("data") else res.body?.dig("data", "data")

            return data?.dig(ref.field)?.text
        }

        override fun describe(): String = "hashicorp:$addr/$mount"
    }

    /**
     * A boru vault (https://github.com/boru-lang/boru).
     *
     * Two ways in, both boru's own.
     *
     * With no `addr`, the CLI: `boru vault get --reveal <alias>` prints the
     * secret on stdout and nothing else. The passphrase is read by boru
     * itself from `BORU_VAULT_PASSPHRASE`; sekreto never accepts it as config
     * and never puts it on a command line, where it would show up in the
     * process table.
     *
     * With an `addr`, boru's wire protocol: `boru vault serve` publishes a
     * read-only, HashiCorp-shaped provision API (boru's
     * design/VAULT-WIRE-PROTOCOL.0.md), authenticated by a capability token
     * from `boru vault grant`. A sekreto name is already a valid boru alias,
     * and boru aliases keep their dots, so `api.token` is the single path
     * segment `api.token` - not the `api`/`token` split a HashiCorp KV gets.
     * The value is the `value` field. A 404 is a miss; anything else the
     * server refuses (a revoked capability, a sealed vault) is an error.
     *
     * boru's `vault proxy` and `vault mcp` remain out of bounds: they are a
     * credential *broker*, built precisely so the caller never receives the
     * credential. `vault serve` is the provision endpoint, built to hand the
     * value back - that is the one sekreto uses.
     */
    class Boru(
        command: String? = null,
        private val namespace: String? = null,
        private val home: String? = null,
        addr: String? = null,
        token: String? = null,
        mount: String? = null,
    ) : Provider {

        private val command: String = if (command.isNullOrEmpty()) "boru" else command
        private val addr: String = if (null == addr) "" else trimslash(addr)
        private val token: String = token ?: ""
        private val mount: String = if (mount.isNullOrEmpty()) "secret" else mount

        override fun lookup(name: String): String? {
            checkname(name)

            if (addr.isNotEmpty()) {
                return wirelookup(name)
            }

            val alias = if (namespace.isNullOrEmpty()) name else "$namespace:$name"

            val builder = ProcessBuilder(command, "vault", "get", "--reveal", alias)

            if (!home.isNullOrEmpty()) {
                builder.environment()["BORU_HOME"] = home
            }

            val (out, why, status) = runcmd(builder, command)

            if (0 == status) {
                // boru prints the value and one newline, and nothing else.
                return out.removeSuffix("\n")
            }

            // "no alias named" is boru saying it does not hold this secret,
            // which is a miss: the chain carries on to the next provider. A
            // locked vault or a wrong passphrase is not a miss - treating it
            // as one would fall through to a weaker store without saying so.
            if (borumiss(why)) {
                return null
            }

            throw SekretoError(
                "sekreto: boru vault error: " + why.ifEmpty { "exit $status" },
            )
        }

        private fun wirelookup(name: String): String? {
            checkaddr(addr)

            // The dotted name stays one path segment: boru aliases keep dots.
            val alias = if (namespace.isNullOrEmpty()) name else "$namespace/$name"
            val url = "$addr/v1/$mount/data/$alias"

            val res = fetchjson("GET", url, mapOf("X-Vault-Token" to token))

            if (404 == res.status) {
                return null
            }

            if (200 != res.status) {
                throw SekretoError("sekreto: boru serve error: ${res.status}: $url")
            }

            return res.body?.dig("data", "data", "value")?.text
        }

        override fun describe(): String {
            if (addr.isNotEmpty()) {
                return "boru:$addr"
            }
            return "boru" + if (namespace.isNullOrEmpty()) "" else ":$namespace"
        }
    }

    /**
     * Does this boru failure mean "no such secret" rather than "I could not
     * answer"? Matched on boru's own wording for a missing alias.
     */
    internal fun borumiss(why: String): Boolean = why.contains("no alias named")

    /**
     * SecretSpec (https://secretspec.dev).
     *
     * SecretSpec is a declaration - a `secretspec.toml` naming the secrets a
     * project needs - plus a chain of its own backends to satisfy them from.
     * That makes it the same shape as sekreto one level down, and the reason
     * to support it is the same reason sekreto exists: a project that has
     * already declared its secrets there should not have to declare them
     * again here.
     *
     * Read through its CLI, as boru is, because that is the interface it
     * offers a program in another language: `secretspec get API_TOKEN`
     * prints the value on stdout and nothing else. A sekreto name maps to a
     * SecretSpec key exactly as it maps to an environment variable -
     * `api.token` is `API_TOKEN` - which is the convention SecretSpec's own
     * examples use.
     *
     * `backend` selects one of SecretSpec's backends (`--provider`, e.g.
     * `keyring` or `dotenv://.env`) and is called `backend` here only
     * because `provider` already means something else in this library.
     *
     * A reason is required, not optional: SecretSpec records every read in
     * an audit log and refuses to read at all without one. sekreto sends
     * `sekreto` unless told otherwise, so the audit trail says which tool
     * asked.
     */
    class Secretspec(
        command: String? = null,
        private val file: String? = null,
        private val profile: String? = null,
        private val backend: String? = null,
        private val reason: String? = null,
        private val prefix: String? = null,
    ) : Provider {

        private val command: String =
            if (command.isNullOrEmpty()) "secretspec" else command

        override fun lookup(name: String): String? {
            val key = envkey(name, prefix)

            val args = mutableListOf(command)
            if (!file.isNullOrEmpty()) {
                args.add("--file")
                args.add(file)
            }
            args.add("get")
            args.add(key)
            if (!backend.isNullOrEmpty()) {
                args.add("--provider")
                args.add(backend)
            }
            if (!profile.isNullOrEmpty()) {
                args.add("--profile")
                args.add(profile)
            }
            args.add("--reason")
            args.add(first(reason, "sekreto"))

            val (out, why, status) = runcmd(ProcessBuilder(args), command)

            if (0 == status) {
                // The value and one newline, and nothing else.
                return out.removeSuffix("\n")
            }

            if (secretspecmiss(why, key)) {
                return null
            }

            throw SekretoError(
                "sekreto: secretspec error: " + why.ifEmpty { "exit $status" },
            )
        }

        override fun describe(): String =
            "secretspec" + if (backend.isNullOrEmpty()) "" else ":$backend"
    }

    /**
     * Does this SecretSpec failure mean "no such secret" rather than "I could
     * not answer"?
     *
     * SecretSpec says `Secret 'API_TOKEN' not found` for both a name it does
     * not declare and one declared with no value, and both are misses: this
     * store does not hold it, so the chain carries on.
     *
     * MATCHED ON THE WHOLE PHRASE, NOT ON "not found". SecretSpec also says
     * `Provider backend 'keyring' not found`, which is a store that could not
     * answer at all - and reading that as a miss is the worst failure this
     * library has, because the chain then falls through to a weaker store
     * without saying so. The key is required to appear, so the two cannot be
     * confused.
     */
    internal fun secretspecmiss(why: String, key: String): Boolean =
        why.contains("Secret '$key' not found")

    /** The `YYYYMMDDTHHMMSSZ` timestamp SigV4 wants, for now. */
    internal fun awsnow(): String =
        DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'")
            .withZone(ZoneOffset.UTC)
            .format(Instant.now())

    /** Region and credentials, resolved for one call. */
    internal data class Awsauth(
        val region: String,
        val keyid: String,
        val secret: String,
        val session: String?,
    )

    /**
     * Region and credentials, from config first and the standard AWS_*
     * environment variables second - those are AWS's own convention, and a
     * pod or CI job that has them set should just work. Missing either is an
     * error: an AWS store with no credentials could not answer.
     */
    internal fun awsauth(
        region: String?,
        keyid: String?,
        secret: String?,
        session: String?,
    ): Awsauth {
        val useregion =
            first(region, System.getenv("AWS_REGION"), System.getenv("AWS_DEFAULT_REGION"))
        val usekeyid = first(keyid, System.getenv("AWS_ACCESS_KEY_ID"))
        val usesecret = first(secret, System.getenv("AWS_SECRET_ACCESS_KEY"))
        val usesession = first(session, System.getenv("AWS_SESSION_TOKEN"))

        if (useregion.isEmpty()) {
            throw SekretoError("sekreto: aws: no region (set region or AWS_REGION)")
        }
        if (usekeyid.isEmpty() || usesecret.isEmpty()) {
            throw SekretoError(
                "sekreto: aws: no credentials" +
                    " (set keyid/secret or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY)",
            )
        }

        return Awsauth(useregion, usekeyid, usesecret, usesession.ifEmpty { null })
    }

    /** One signed call to an AWS JSON-1.1 API. */
    internal fun awscall(
        region: String?,
        keyid: String?,
        secret: String?,
        session: String?,
        addr: String?,
        service: String,
        target: String,
        payload: String,
    ): Answer {
        val auth = awsauth(region, keyid, secret, session)

        // The China partition lives under its own suffix; every other
        // commercial region is plain amazonaws.com.
        val suffix =
            if (auth.region.startsWith("cn-")) ".amazonaws.com.cn" else ".amazonaws.com"
        val useaddr = first(addr, "https://$service.${auth.region}$suffix")
        checkaddr(useaddr)

        val url = trimslash(useaddr) + "/"

        val extras = linkedMapOf(
            "content-type" to "application/x-amz-json-1.1",
            "x-amz-target" to target,
        )

        val signed = sigv4(
            Signing(
                method = "POST",
                url = url,
                service = service,
                region = auth.region,
                keyid = auth.keyid,
                secret = auth.secret,
                datetime = awsnow(),
                headers = extras,
                body = payload,
                session = auth.session,
            ),
        )

        return fetchjson("POST", url, extras + signed, payload)
    }

    /**
     * Does this AWS error body name one of the not-found types? Those are a
     * miss; every other failure is a store that could not answer.
     */
    internal fun awsmiss(body: Json?, vararg types: String): Boolean {
        val errtype = body?.dig("__type")?.asstr ?: return false
        return types.any { errtype.contains(it) }
    }

    /**
     * AWS Secrets Manager.
     *
     * `api.token` reads the secret named `api` (the vaultref path, so
     * `db.pass.main` reads `db/pass`) and takes the `token` field of its JSON
     * SecretString - the AWS idiom of one JSON map per secret. A SecretString
     * that is not JSON is the value itself, under the conventional field
     * `value`. Requests are SigV4-signed in-tree; see Sigv4.kt.
     */
    class Awssecrets(
        private val region: String? = null,
        private val keyid: String? = null,
        private val secret: String? = null,
        private val session: String? = null,
        private val addr: String? = null,
    ) : Provider {

        override fun lookup(name: String): String? {
            val ref = vaultref(name)

            val res = awscall(
                region, keyid, secret, session, addr,
                "secretsmanager", "secretsmanager.GetSecretValue",
                Json.stringify(Json.obj("SecretId" to Json.str(ref.path))),
            )

            if (400 == res.status && awsmiss(res.body, "ResourceNotFoundException")) {
                return null
            }

            if (200 != res.status) {
                throw SekretoError("sekreto: aws secretsmanager error: ${res.status}")
            }

            val text = res.body?.dig("SecretString")?.asstr

            if (null == text) {
                // A binary secret has no fields to address; only the
                // conventional `value` field can mean "the bytes themselves".
                val bin = res.body?.dig("SecretBinary")?.asstr
                if (null != bin && "value" == ref.field) {
                    return String(Base64.getDecoder().decode(bin), StandardCharsets.UTF_8)
                }
                return null
            }

            val parsed = Json.parse(text)

            if (parsed is Json.Obj) {
                return parsed.value[ref.field]?.text
            }

            // A plain-string secret is the whole value; it has no named fields.
            return if ("value" == ref.field) text else null
        }

        // Config only, never the environment: describe() feeds the spec's
        // sources group, which must answer the same everywhere.
        override fun describe(): String = "awssecrets:${region ?: ""}"
    }

    /**
     * AWS SSM Parameter Store.
     *
     * `db.pass.main` reads the parameter `/db/pass/main` (under an optional
     * prefix path), decrypted. Parameter Store carries flat strings, so there
     * is no field indirection.
     */
    class Awsparams(
        private val region: String? = null,
        private val keyid: String? = null,
        private val secret: String? = null,
        private val session: String? = null,
        private val addr: String? = null,
        private val prefix: String? = null,
    ) : Provider {

        override fun lookup(name: String): String? {
            val payload = Json.obj(
                "Name" to Json.str(awsparam(name, prefix)),
                "WithDecryption" to Json.bool(true),
            )

            val res = awscall(
                region, keyid, secret, session, addr,
                "ssm", "AmazonSSM.GetParameter", Json.stringify(payload),
            )

            if (400 == res.status && awsmiss(res.body, "ParameterNotFound")) {
                return null
            }

            if (200 != res.status) {
                throw SekretoError("sekreto: aws ssm error: ${res.status}")
            }

            return res.body?.dig("Parameter", "Value")?.text
        }

        override fun describe(): String = "awsparams:${region ?: ""}${prefix ?: ""}"
    }

    /**
     * GCP Secret Manager.
     *
     * `api.token` reads secret `api_token` (dots flattened to `_`; Secret
     * Manager ids have no hierarchy and reject dots), latest version. The
     * token comes from config, then `GOOGLE_OAUTH_ACCESS_TOKEN`, then the
     * GCE/GKE metadata server - so on Google's own platform no credential
     * configuration is needed at all.
     *
     * The metadata call itself is plain http to a link-local host by platform
     * design; no credential rides on it, so `checkaddr` guards the Secret
     * Manager address instead.
     */
    class Gcpsecrets(
        private val project: String? = null,
        private val token: String? = null,
        private val addr: String? = null,
        private val metadataaddr: String? = null,
    ) : Provider {

        // A configured token is kept forever; a metadata-server token carries
        // expires_in and is renewed shortly before it runs out.
        private var livetoken: String? = null
        private var renewat: Long = Long.MAX_VALUE

        private fun usemetadataaddr(): String {
            if (!metadataaddr.isNullOrEmpty()) {
                return metadataaddr
            }

            val host = System.getenv("GCE_METADATA_HOST")
            return if (host.isNullOrEmpty()) "http://metadata.google.internal" else "http://$host"
        }

        private fun login(): String {
            val configured = first(token, System.getenv("GOOGLE_OAUTH_ACCESS_TOKEN"))
            if (configured.isNotEmpty()) {
                return configured
            }

            val url = trimslash(usemetadataaddr()) +
                "/computeMetadata/v1/instance/service-accounts/default/token"

            val res = fetchjson("GET", url, mapOf("Metadata-Flavor" to "Google"))

            val got = res.body?.dig("access_token")?.text
            if (200 != res.status || got.isNullOrEmpty()) {
                throw SekretoError("sekreto: gcp: no token and metadata server did not answer")
            }

            renewat = renewtime(res.body?.dig("expires_in"))

            return got
        }

        override fun lookup(name: String): String? {
            val useproject = project ?: ""
            if (useproject.isEmpty()) {
                throw SekretoError("sekreto: gcp: no project")
            }

            val useaddr = first(addr, "https://secretmanager.googleapis.com")
            checkaddr(useaddr)

            if (null == livetoken || System.currentTimeMillis() >= renewat) {
                livetoken = login()
            }

            val url = trimslash(useaddr) + "/v1/projects/" + useproject + "/secrets/" +
                flatname(name, "_") + "/versions/latest:access"

            val res = fetchjson("GET", url, mapOf("authorization" to "Bearer $livetoken"))

            if (404 == res.status) {
                return null
            }

            if (200 != res.status) {
                throw SekretoError("sekreto: gcp error: ${res.status}: $url")
            }

            val data = res.body?.dig("payload", "data")?.asstr ?: return null

            return String(Base64.getDecoder().decode(data), StandardCharsets.UTF_8)
        }

        override fun describe(): String = "gcpsecrets:${project ?: ""}"
    }

    /**
     * Azure Key Vault.
     *
     * `api.token` reads secret `api-token` (dots flattened to `-`; Key Vault
     * names allow nothing else), current version. The token comes from
     * config, then a client-credentials login when tenant/clientid/
     * clientsecret are given, then the IMDS managed-identity endpoint - so on
     * Azure's own platform no credential configuration is needed.
     *
     * As with GCP, the IMDS call is plain http to a link-local host by
     * platform design and carries no credential; the login and vault
     * addresses are `checkaddr`-guarded.
     */
    class Azuresecrets(
        private val vault: String? = null,
        private val token: String? = null,
        private val tenant: String? = null,
        private val clientid: String? = null,
        private val clientsecret: String? = null,
        private val loginaddr: String? = null,
        private val imdsaddr: String? = null,
        private val apiversion: String? = null,
    ) : Provider {

        // A configured token is kept forever; logged-in and IMDS tokens carry
        // expires_in and are renewed shortly before they run out.
        private var livetoken: String? = null
        private var renewat: Long = Long.MAX_VALUE

        private fun login(): String {
            if (!token.isNullOrEmpty()) {
                return token
            }

            if (!tenant.isNullOrEmpty() &&
                !clientid.isNullOrEmpty() &&
                !clientsecret.isNullOrEmpty()
            ) {
                val useloginaddr = first(loginaddr, "https://login.microsoftonline.com")
                checkaddr(useloginaddr)

                val url = trimslash(useloginaddr) + "/" + tenant + "/oauth2/v2.0/token"
                val form = "grant_type=client_credentials&client_id=" + uriescape(clientid) +
                    "&client_secret=" + uriescape(clientsecret) +
                    "&scope=" + uriescape("$RESOURCE/.default")

                val res = fetchjson(
                    "POST",
                    url,
                    mapOf("content-type" to "application/x-www-form-urlencoded"),
                    form,
                )

                val got = res.body?.dig("access_token")?.text
                if (200 != res.status || got.isNullOrEmpty()) {
                    throw SekretoError("sekreto: azure login failed: ${res.status}")
                }

                renewat = renewtime(res.body?.dig("expires_in"))
                return got
            }

            val imds = trimslash(first(imdsaddr, "http://169.254.169.254")) +
                "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=" +
                uriescape(RESOURCE)

            val res = fetchjson("GET", imds, mapOf("Metadata" to "true"))

            val got = res.body?.dig("access_token")?.text
            if (200 != res.status || got.isNullOrEmpty()) {
                throw SekretoError(
                    "sekreto: azure: no token, no client credentials, and IMDS did not answer",
                )
            }

            renewat = renewtime(res.body?.dig("expires_in"))
            return got
        }

        override fun lookup(name: String): String? {
            val usevault = vault ?: ""
            if (usevault.isEmpty()) {
                throw SekretoError("sekreto: azure: no vault")
            }

            // Only an explicit scheme is a URL; a vault NAMED httpvault must
            // still become https://httpvault.vault.azure.net.
            val vaulturl =
                if (usevault.startsWith("http://") || usevault.startsWith("https://")) {
                    usevault
                } else {
                    "https://$usevault.vault.azure.net"
                }
            checkaddr(vaulturl)

            if (null == livetoken || System.currentTimeMillis() >= renewat) {
                livetoken = login()
            }

            val url = trimslash(vaulturl) + "/secrets/" + flatname(name, "-") +
                "?api-version=" + first(apiversion, "7.4")

            val res = fetchjson("GET", url, mapOf("authorization" to "Bearer $livetoken"))

            if (404 == res.status) {
                return null
            }

            if (200 != res.status) {
                throw SekretoError("sekreto: azure error: ${res.status}: ${bare(url)}")
            }

            return res.body?.dig("value")?.text
        }

        override fun describe(): String = "azuresecrets:${vault ?: ""}"

        private companion object {
            const val RESOURCE = "https://vault.azure.net"
        }
    }

    /**
     * 1Password, through a Connect server.
     *
     * The item titled `api.token` (titles keep their dots), in the named
     * vault. The value is the field with purpose PASSWORD, or the field
     * labelled `value`. A vault that cannot be found is an error - config
     * names it, so its absence is a broken store, not a missing secret.
     */
    class Onepassword(
        private val addr: String? = null,
        private val token: String? = null,
        private val vault: String? = null,
    ) : Provider {

        private var vaultid: String? = null

        private fun auth(): Map<String, String> =
            mapOf("authorization" to "Bearer ${token ?: ""}")

        private fun resolvevault(useaddr: String): String {
            val want = vault ?: ""
            if (want.isEmpty()) {
                throw SekretoError("sekreto: onepassword: no vault")
            }

            val res = fetchjson("GET", "$useaddr/v1/vaults", auth())

            val list = res.body?.asarr
            if (200 != res.status || null == list) {
                throw SekretoError("sekreto: onepassword error: ${res.status}: listing vaults")
            }

            for (entry in list) {
                val id = entry.dig("id")?.text
                if (want == id || want == entry.dig("name")?.text) {
                    return id ?: ""
                }
            }

            throw SekretoError("sekreto: onepassword: no vault named $want")
        }

        override fun lookup(name: String): String? {
            checkname(name)

            val useaddr = trimslash(addr ?: "")
            if (useaddr.isEmpty()) {
                throw SekretoError("sekreto: onepassword: no addr")
            }
            checkaddr(useaddr)

            val id = vaultid ?: resolvevault(useaddr).also { vaultid = it }

            val filter = uriescape("title eq \"$name\"")
            val found = fetchjson("GET", "$useaddr/v1/vaults/$id/items?filter=$filter", auth())

            val items = found.body?.asarr
            if (200 != found.status || null == items) {
                throw SekretoError("sekreto: onepassword error: ${found.status}: finding $name")
            }

            if (items.isEmpty()) {
                return null
            }

            val item = fetchjson(
                "GET",
                "$useaddr/v1/vaults/$id/items/${items[0].dig("id")?.text}",
                auth(),
            )

            if (200 != item.status) {
                throw SekretoError("sekreto: onepassword error: ${item.status}: reading $name")
            }

            val fields = item.body?.dig("fields")?.asarr ?: emptyList()

            for (field in fields) {
                if ("PASSWORD" == field.dig("purpose")?.asstr) {
                    return field.dig("value")?.text
                }
            }
            for (field in fields) {
                if ("value" == field.dig("label")?.asstr) {
                    return field.dig("value")?.text
                }
            }

            return null
        }

        override fun describe(): String = "onepassword:${vault ?: ""}"
    }

    /**
     * Doppler.
     *
     * The whole config is downloaded once - Doppler's own bulk endpoint - and
     * answered from memory, like a remote .env: `api.token` is the
     * `API_TOKEN` entry. A service token is config-scoped, so project and
     * config are only needed with broader tokens.
     */
    class Doppler(
        private val token: String? = null,
        private val project: String? = null,
        private val config: String? = null,
        private val addr: String? = null,
    ) : Provider {

        private var values: Map<String, String>? = null

        private fun load(): Map<String, String> {
            values?.let { return it }

            val useaddr = trimslash(first(addr, "https://api.doppler.com"))
            checkaddr(useaddr)

            var url = "$useaddr/v3/configs/config/secrets/download?format=json"
            if (!project.isNullOrEmpty()) {
                url += "&project=" + uriescape(project)
            }
            if (!config.isNullOrEmpty()) {
                url += "&config=" + uriescape(config)
            }

            val res = fetchjson(
                "GET",
                url,
                mapOf("authorization" to "Bearer ${token ?: ""}"),
            )

            val body = res.body?.asobj
            if (200 != res.status || null == body) {
                throw SekretoError("sekreto: doppler error: ${res.status}")
            }

            val loaded = LinkedHashMap<String, String>()
            for ((key, value) in body) {
                value.text?.let { loaded[key] = it }
            }

            values = loaded
            return loaded
        }

        override fun lookup(name: String): String? = load()[envkey(name)]

        override fun describe(): String =
            "doppler" + if (project.isNullOrEmpty()) "" else ":$project/${config ?: ""}"
    }

    /**
     * Infisical.
     *
     * `api.token` reads the secret keyed `API_TOKEN` (Infisical's own
     * convention is environment-style keys) at a secret path in one
     * environment of a project. Auth is a token, or a universal-auth (machine
     * identity) login with clientid/clientsecret.
     */
    class Infisical(
        private val addr: String? = null,
        private val token: String? = null,
        private val clientid: String? = null,
        private val clientsecret: String? = null,
        private val project: String? = null,
        private val environment: String? = null,
        private val path: String? = null,
    ) : Provider {

        // A configured token is kept forever; a universal-auth token carries
        // expiresIn and is renewed shortly before it runs out.
        private var livetoken: String? = null
        private var renewat: Long = Long.MAX_VALUE

        private fun login(useaddr: String): String {
            if (!token.isNullOrEmpty()) {
                return token
            }

            if (clientid.isNullOrEmpty() || clientsecret.isNullOrEmpty()) {
                throw SekretoError("sekreto: infisical: no token and no client credentials")
            }

            val body = Json.obj(
                "clientId" to Json.str(clientid),
                "clientSecret" to Json.str(clientsecret),
            )

            val res = fetchjson(
                "POST",
                "$useaddr/api/v1/auth/universal-auth/login",
                mapOf("content-type" to "application/json"),
                Json.stringify(body),
            )

            val got = res.body?.dig("accessToken")?.text
            if (200 != res.status || got.isNullOrEmpty()) {
                throw SekretoError("sekreto: infisical login failed: ${res.status}")
            }

            renewat = renewtime(res.body?.dig("expiresIn"))

            return got
        }

        override fun lookup(name: String): String? {
            val useaddr = trimslash(first(addr, "https://app.infisical.com"))
            checkaddr(useaddr)

            val useproject = project ?: ""
            val useenvironment = environment ?: ""
            if (useproject.isEmpty() || useenvironment.isEmpty()) {
                throw SekretoError("sekreto: infisical: no project/environment")
            }

            if (null == livetoken || System.currentTimeMillis() >= renewat) {
                livetoken = login(useaddr)
            }

            val url = "$useaddr/api/v3/secrets/raw/" + envkey(name) +
                "?workspaceId=" + uriescape(useproject) +
                "&environment=" + uriescape(useenvironment) +
                "&secretPath=" + uriescape(first(path, "/"))

            val res = fetchjson("GET", url, mapOf("authorization" to "Bearer $livetoken"))

            if (404 == res.status) {
                return null
            }

            if (200 != res.status) {
                throw SekretoError("sekreto: infisical error: ${res.status}")
            }

            return res.body?.dig("secret", "secretValue")?.text
        }

        override fun describe(): String =
            "infisical:${project ?: ""}/${environment ?: ""}"
    }

    /**
     * Build a provider from its declarative form - the same shape the shared
     * spec and an app's config file use.
     */
    fun makeprovider(spec: ProviderSpec): Provider = when (spec.kind) {
        "env" -> Env(spec.prefix)
        "dotenv" -> Dotenv(spec.file ?: ".env", spec.prefix)
        "memory" -> Memory(spec.values, spec.prefix)
        "file" -> File(spec.dir ?: "", spec.prefix)
        "hashicorp" -> Hashicorp(
            spec.addr, spec.token, spec.mount, spec.kv, spec.vaultnamespace, spec.auth,
        )
        "boru" -> Boru(
            spec.command, spec.namespace, spec.home, spec.addr, spec.token, spec.mount,
        )
        "awssecrets" -> Awssecrets(
            spec.region, spec.keyid, spec.secret, spec.session, spec.addr,
        )
        "awsparams" -> Awsparams(
            spec.region, spec.keyid, spec.secret, spec.session, spec.addr, spec.prefix,
        )
        "gcpsecrets" -> Gcpsecrets(
            spec.project, spec.token, spec.addr, spec.metadataaddr,
        )
        "azuresecrets" -> Azuresecrets(
            spec.vault, spec.token, spec.tenant, spec.clientid, spec.clientsecret,
            spec.loginaddr, spec.imdsaddr, spec.apiversion,
        )
        "onepassword" -> Onepassword(spec.addr, spec.token, spec.vault)
        "doppler" -> Doppler(spec.token, spec.project, spec.config, spec.addr)
        "infisical" -> Infisical(
            spec.addr, spec.token, spec.clientid, spec.clientsecret,
            spec.project, spec.environment, spec.path,
        )
        "secretspec" -> Secretspec(
            spec.command, spec.file, spec.profile, spec.backend, spec.reason, spec.prefix,
        )
        else -> throw SekretoError("sekreto: unknown provider kind: ${spec.kind}")
    }
}
