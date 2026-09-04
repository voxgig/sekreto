// The providers a Sekreto chains together.
//
// A provider answers one question: "do you have this secret?" It returns
// the value, or None to mean "ask the next one". Nothing else about a
// provider is visible to the caller - which is the point: an app reads
// `api.token` and never learns whether it came from the environment, a
// .env file, HashiCorp Vault, AWS, GCP, Azure or a boru vault.
//
// Two failure shapes, and they are never interchangeable. A store that does
// not hold the secret is a MISS (None) - the chain carries on. A store that
// could not answer - bad credentials, unreachable host, missing
// configuration - is an ERROR: falling through there would quietly reach
// for a weaker store.
//
// A port of typescript/src/Providers.ts, which is canonical.

package com.voxgig.sekreto

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
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
import java.util.Locale
import scala.collection.immutable.ListMap
import scala.jdk.CollectionConverters.*

/** Logging in to a vault instead of being handed a token. `method` is
  * `kubernetes` or `approle`; `mount` defaults to the method name.
  */
case class AuthSpec(
    method: String,
    mount: Option[String] = None,
    /** kubernetes: the Vault role to log in as. */
    role: Option[String] = None,
    /** kubernetes: the service-account JWT itself (tests). */
    jwt: Option[String] = None,
    /** kubernetes: where the JWT lives; the conventional pod path by default. */
    jwtfile: Option[String] = None,
    /** approle: the role and secret ids. */
    roleid: Option[String] = None,
    secretid: Option[String] = None,
):

  /** Printed without its credentials.
    *
    * A `case class` generates a `toString` that prints every field, so
    * `logger.error(s"bad chain: $specs")` - which is what someone writes
    * when a chain will not build - would put the service-account JWT and the
    * AppRole secret id in the log. Fields that hold a credential report
    * whether they are set, never what they are.
    */
  override def toString: String =
    s"AuthSpec(method=$method, mount=$mount, role=$role, jwtfile=$jwtfile, " +
      s"roleid=$roleid, jwt=${setornot(jwt)}, secretid=${setornot(secretid)})"

/** What a credential field reports about itself. */
private[sekreto] def setornot(value: Option[String]): String =
  if value.exists(_.nonEmpty) then "[set]" else "[unset]"

/** The declarative form of a provider, as used in config and in the shared
  * spec. `kind` picks the provider; everything else is that kind's own.
  */
case class ProviderSpec(
    kind: String,
    /** The store name `Sekreto.getfrom` addresses. Defaults to `kind`. */
    name: Option[String] = None,
    prefix: Option[String] = None,
    /** dotenv: the file to read. secretspec: the declaration to read. */
    file: Option[String] = None,
    /** memory: literal values, keyed like environment variables. */
    values: Option[Map[String, String]] = None,
    /** file: the directory of one-secret-per-file entries. */
    dir: Option[String] = None,
    /** hashicorp / boru (wire) / gcp / 1password / doppler / infisical: the base URL. */
    addr: Option[String] = None,
    /** hashicorp / boru (wire) / gcp / azure / 1password / doppler / infisical: the token. */
    token: Option[String] = None,
    /** hashicorp / boru (wire): the KV mount (default `secret`). */
    mount: Option[String] = None,
    /** hashicorp: KV engine version, 1 or 2 (default 2). */
    kv: Option[Int] = None,
    /** hashicorp: Vault Enterprise namespace (X-Vault-Namespace). */
    vaultnamespace: Option[String] = None,
    /** hashicorp: log in for a token instead of being handed one. */
    auth: Option[AuthSpec] = None,
    /** boru / secretspec: the executable to run (default: the kind's own name). */
    command: Option[String] = None,
    /** secretspec: the profile to read (`--profile`). */
    profile: Option[String] = None,
    /** secretspec: which of ITS backends to read from (`--provider`), e.g.
      * `keyring` or `dotenv://.env`. Named `backend` here because `provider`
      * already means a sekreto provider.
      */
    backend: Option[String] = None,
    /** secretspec: the audit reason recorded for the read (`--reason`).
      * SecretSpec refuses to read without one.
      */
    reason: Option[String] = None,
    /** boru: the namespace qualifying the alias. */
    namespace: Option[String] = None,
    /** boru: the vault home, passed as BORU_HOME. */
    home: Option[String] = None,
    /** aws: region and credentials; the standard AWS_* variables fill the rest. */
    region: Option[String] = None,
    keyid: Option[String] = None,
    secret: Option[String] = None,
    session: Option[String] = None,
    /** gcp / doppler / infisical: the project, however that store names it. */
    project: Option[String] = None,
    /** azure: the Key Vault name or full URL. 1password: the vault name or id. */
    vault: Option[String] = None,
    /** azure: client-credential login. infisical: universal-auth login. */
    tenant: Option[String] = None,
    clientid: Option[String] = None,
    clientsecret: Option[String] = None,
    /** azure: where to log in / where IMDS answers. gcp: the metadata server. */
    loginaddr: Option[String] = None,
    imdsaddr: Option[String] = None,
    metadataaddr: Option[String] = None,
    /** azure: the Key Vault API version (default 7.4). */
    apiversion: Option[String] = None,
    /** doppler: the config slug (with `project`). */
    config: Option[String] = None,
    /** infisical: the environment slug and secret path. */
    environment: Option[String] = None,
    path: Option[String] = None,
):

  /** Printed without its credentials. See AuthSpec.toString: the generated
    * one would put the Vault token, the AWS secret access key and the Azure
    * client secret into whatever formatted it.
    */
  override def toString: String =
    s"ProviderSpec(kind=$kind, name=$name, addr=$addr, token=${setornot(token)}, " +
      s"secret=${setornot(secret)}, clientsecret=${setornot(clientsecret)}, auth=$auth)"

object Providers:

  /** How long any single vault round-trip may take before it is treated as
    * unreachable. Ports carry the same bound.
    */
  private val TIMEOUT: Duration = Duration.ofSeconds(10)

  /** How much of a response body will be read before the store is treated as
    * having answered incoherently. Ports carry the same bound.
    *
    * Far above anything real - the largest legitimate payload this library
    * fetches is Doppler's whole-config download, measured in kilobytes. A
    * bound is needed because the TIMEOUT is not one: ten seconds on a
    * loopback or datacentre link is gigabytes, and the body is accumulated
    * in memory before it is parsed. This runs on an application's startup
    * path, so the failure is the application never starting.
    */
  private val MAXBODY: Int = 8 * 1024 * 1024

  /** An environment variable, or None. */
  private def getenv(name: String): Option[String] = Option(System.getenv(name))

  /** Does this read failure mean "no secrets here", rather than "I could not
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
  private[sekreto] def absent(file: Path): Boolean =
    val dir = file.getParent
    null != dir && !Files.isDirectory(dir)

  /** What a finished child process left behind. */
  private[sekreto] case class Ran(out: String, why: String, status: Int)

  /** Run a child to completion and collect both its streams.
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
  private[sekreto] def runcmd(builder: ProcessBuilder, command: String): Ran =
    try
      val process = builder.start()

      process.getOutputStream.close()

      val errbuf = ByteArrayOutputStream()

      val pump: Runnable = () =>
        try process.getErrorStream.transferTo(errbuf)
        catch
          // The child went away mid-write; waitFor reports how.
          case _: IOException => ()

      val drain = Thread(pump)
      drain.setDaemon(true)
      drain.start()

      val out = String(process.getInputStream.readAllBytes, StandardCharsets.UTF_8)
      val status = process.waitFor()
      drain.join()

      Ran(out, String(errbuf.toByteArray, StandardCharsets.UTF_8).trim, status)
    catch
      case err: IOException =>
        throw SekretoError(s"sekreto: cannot run $command: ${err.getMessage}")
      case err: InterruptedException =>
        Thread.currentThread.interrupt()
        throw SekretoError(s"sekreto: interrupted running $command")

  // HTTP/1.1, explicitly.
  //
  // java.net.http defaults to HTTP_2, and over cleartext that means an h2c
  // upgrade: the first request goes out with `Upgrade: h2c`, the declared
  // Content-Length, and NO BODY, and the body follows only after the server
  // declines. A server that checks the two against each other - Fastify
  // does, and Infisical is Fastify - rejects that request outright with
  // "Request body size did not match Content-Length", so every POST this
  // port makes to such a server fails before it is even read.
  //
  // The mocks in test/ are Node's own http module, which does not object,
  // which is why this survived until the same code met a real Infisical. No
  // vault API this library speaks needs HTTP/2.
  //
  // Redirects are never followed: a vault API does not legitimately
  // redirect, and a followed redirect would carry X-Vault-Token to the
  // redirect's host (and could downgrade https to http), which checkaddr -
  // it only validates the configured address - cannot see.
  private val CLIENT: HttpClient = HttpClient
    .newBuilder()
    .version(HttpClient.Version.HTTP_1_1)
    .followRedirects(HttpClient.Redirect.NEVER)
    .connectTimeout(TIMEOUT)
    .build()

  /** One JSON round-trip's result: the status, and the parsed body. */
  private[sekreto] case class Answer(status: Int, body: Option[Json])

  /** An address with any userinfo replaced by `[redacted]`, for messages.
    *
    * Every refusal below names the address it refused, and one of them fires
    * precisely because the address carries a credential - so printing it
    * verbatim wrote the password to stderr and into the logs. It cannot be
    * cleaned up afterwards either: that password was never resolved as a
    * secret, so redact() has never seen it and never will. The host is what
    * a reader needs to identify which chain entry is at fault; the userinfo
    * is not.
    */
  private[sekreto] def safeaddr(addr: String): String =
    val mark = addr.indexOf("://")

    if -1 == mark then addr
    else
      val rest = addr.substring(mark + 3)
      val stop = rest.indexWhere(ch => "/?#".contains(ch))
      val authority = if -1 == stop then rest else rest.substring(0, stop)

      val at = authority.lastIndexOf('@')

      if -1 == at then addr
      else addr.substring(0, mark + 3) + "[redacted]" + addr.substring(mark + 3 + at)

  /** Refuse to send a secret-bearing credential in the clear.
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
    * A dozen parsers disagree about malformed input - where userinfo ends,
    * whether `0177.0.0.1` is loopback, what an unclosed bracket means - and
    * a check that answers differently in different ports is not a check.
    *
    * The rule this parse obeys, and the reason it can be trusted: it is
    * never more permissive than the HTTP client that will dial the address.
    * It ends the authority at `/`, `?` or `#` only, so a client that also
    * breaks on `\` (WHATWG does) can only ever see a SHORTER host than this
    * does. It refuses userinfo outright rather than locating its end. It
    * compares the host literally, so a numeric form no parser here agrees on
    * is refused rather than guessed at.
    */
  def checkaddr(addr: String): Unit =
    val scheme =
      if addr.startsWith("https://") then "https://"
      else if addr.startsWith("http://") then "http://"
      else throw SekretoError(s"sekreto: not an http(s) address: ${safeaddr(addr)}")

    val rest = addr.substring(scheme.length)
    val end = rest.indexWhere(ch => "/?#".contains(ch))
    val authority = if -1 == end then rest else rest.substring(0, end)

    // Userinfo is refused outright rather than parsed around, and on https
    // as well as http. No store this library speaks authenticates by
    // userinfo - they take a token or a signature - so an address carrying
    // one is a mistake at best. At worst it is the attack this whole
    // function exists to stop: `http://localhost:8200@evil.example.com/` is
    // a request to evil.example.com that reads, to anything that splits the
    // authority on ':', as loopback.
    if authority.contains("@") then
      throw SekretoError(
        s"sekreto: refusing an address with embedded credentials: ${safeaddr(addr)}",
      )

    // An opening bracket with no closing one is not an address at all.
    if authority.startsWith("[") && !authority.contains("]") then
      throw SekretoError(s"sekreto: not a valid http(s) address: ${safeaddr(addr)}")

    if "https://" != scheme then
      // A bracketed IPv6 literal keeps its brackets. Splitting the authority
      // on the first colon yields '[', so `http://[::1]:8200` could never
      // match - which made the '[::1]' entry below unreachable, and refused
      // a legitimate local vault.
      val host =
        (if authority.startsWith("[") then authority.substring(0, authority.indexOf("]") + 1)
         else authority.takeWhile(_ != ':')).toLowerCase(Locale.ROOT)

      if "localhost" != host && "127.0.0.1" != host && "::1" != host && "[::1]" != host then
        throw SekretoError(
          s"sekreto: refusing to send a token in plaintext to ${safeaddr(addr)} (use https)",
        )

  /** One JSON round-trip. Network failure is always an error - an
    * unreachable store is a store that could not answer.
    */
  private[sekreto] def fetchjson(
      method: String,
      url: String,
      headers: Map[String, String] = Map.empty,
      body: Option[String] = None,
  ): Answer =
    val builder = HttpRequest
      .newBuilder()
      .uri(URI.create(url))
      .timeout(TIMEOUT)
      .method(
        method,
        body match
          case None       => HttpRequest.BodyPublishers.noBody()
          case Some(text) => HttpRequest.BodyPublishers.ofString(text, StandardCharsets.UTF_8),
      )

    for (key, value) <- headers do builder.header(key, value)

    // ofInputStream, not ofString: ofString buffers whatever arrives, so an
    // endless body would be accumulated in memory until the deadline - which
    // on a loopback or datacentre link is gigabytes.
    val response: HttpResponse[InputStream] =
      try CLIENT.send(builder.build(), HttpResponse.BodyHandlers.ofInputStream())
      catch
        // A refused connection arrives with a null message, so the class
        // name stands in - "cannot reach ...: null" says nothing at all.
        case err: IOException =>
          throw SekretoError(s"sekreto: cannot reach ${bare(url)}: ${why(err)}")
        case err: InterruptedException =>
          Thread.currentThread.interrupt()
          throw SekretoError(s"sekreto: cannot reach ${bare(url)}: interrupted")

    // A success status promised JSON; a body that does not parse means the
    // store could not answer coherently, and treating it as a miss would
    // fall through to a weaker store. Error statuses may carry any body -
    // they are decided on status alone.
    // One byte over the bound is enough to know it was exceeded. An endless
    // body is a store that could not answer, so this raises rather than
    // returning a miss - the latter would fall through to a weaker store on
    // an attacker's cue.
    val stream = response.body()
    val text =
      try
        val raw = stream.readNBytes(MAXBODY + 1)
        if MAXBODY < raw.length then
          throw SekretoError(s"sekreto: oversized response from ${bare(url)}")
        String(raw, StandardCharsets.UTF_8)
      catch
        case err: IOException =>
          throw SekretoError(s"sekreto: cannot reach ${bare(url)}: ${why(err)}")
      finally stream.close()

    val parsed = Json.parse(text)
    if 200 == response.statusCode() && parsed.isEmpty then
      throw SekretoError(s"sekreto: malformed response from ${bare(url)}")

    Answer(response.statusCode(), parsed)

  /** What an exception has to say for itself, never the empty string. */
  private def why(err: Throwable): String =
    Option(err.getMessage).getOrElse(err.toString)

  /** A URL without its query string, for a message that must not leak one. */
  private def bare(url: String): String = url.takeWhile(_ != '?')

  /** The first candidate that is set and non-empty, or empty. */
  private[sekreto] def first(candidates: Option[String]*): String =
    candidates.iterator.flatten.find(_.nonEmpty).getOrElse("")

  private def trimslash(text: String): String = dropsuffix(text, "/")

  /** When a logged-in token must be renewed, from its expiry in seconds (a
    * JSON number, or a string as Azure IMDS sends it): now + max(seconds -
    * 60, 1). A missing or zero expiry means never renew.
    */
  private[sekreto] def renewtime(expires: Option[Json]): Long =
    val seconds = expires match
      case Some(Json.Num(value)) => value
      case Some(Json.Str(value)) => value.toDoubleOption.getOrElse(0.0)
      case _                     => 0.0

    if seconds.isNaN || 0 >= seconds then Long.MaxValue
    else System.currentTimeMillis + (math.max(seconds - 60, 1.0) * 1000).toLong

  /** Environment variables: `api.token` from `API_TOKEN`. */
  class Env(prefix: Option[String] = None, source: Option[Map[String, String]] = None)
      extends Provider:

    override def lookup(name: String): Option[String] =
      val key = envkey(name, prefix)
      source match
        case None         => getenv(key)
        case Some(values) => values.get(key)

    override def describe(): String =
      "env" + (if prefix.exists(_.nonEmpty) then s":${prefix.get}" else "")

  /** A `.env` file, read once, keyed exactly like the environment. */
  class Dotenv(file: String, prefix: Option[String] = None) extends Provider:

    private var values: Option[Map[String, String]] = None

    private def load(): Map[String, String] =
      values match
        case Some(loaded) => loaded
        case None =>
          val path = Paths.get(file)

          val loaded: Map[String, String] =
            try parsedotenv(String(Files.readAllBytes(path), StandardCharsets.UTF_8))
            catch
              // An absent file - or an absent directory - means "no secrets
              // here", exactly like the file provider.
              case _: NoSuchFileException => Map.empty
              case err: IOException =>
                if absent(path) then Map.empty
                else
                  throw SekretoError(
                    s"sekreto: dotenv provider cannot read $file: ${err.getMessage}",
                  )

          values = Some(loaded)
          loaded

    override def lookup(name: String): Option[String] = load().get(envkey(name, prefix))

    override def describe(): String = s"dotenv:$file"

  /** Literal values, keyed like environment variables. The spec uses this to
    * test chain behaviour without touching the outside world.
    */
  class Memory(source: Option[Map[String, String]] = None, prefix: Option[String] = None)
      extends Provider:

    private val values: Map[String, String] = source.getOrElse(Map.empty)

    override def lookup(name: String): Option[String] = values.get(envkey(name, prefix))

    override def describe(): String =
      "memory" + (if prefix.exists(_.nonEmpty) then s":${prefix.get}" else "")

  /** A directory of one-secret-per-file entries, keyed like the environment:
    * `api.token` reads `<dir>/API_TOKEN`.
    *
    * This is the shape of a mounted Kubernetes Secret, a Docker or Swarm
    * secret, and a systemd credentials directory, so those all work with no
    * further configuration. One trailing newline is stripped - tools that
    * write these files disagree about it, and a newline is never part of a
    * secret on purpose.
    */
  class File(dir: String, prefix: Option[String] = None) extends Provider:

    override def lookup(name: String): Option[String] =
      val file = Paths.get(dir, envkey(name, prefix))

      val text =
        try Some(String(Files.readAllBytes(file), StandardCharsets.UTF_8))
        catch
          // An absent file - or an absent directory - means "no secrets
          // here", exactly like a missing .env.
          case _: NoSuchFileException => None
          case err: IOException =>
            if absent(file) then None
            else throw SekretoError(s"sekreto: file provider cannot read $file: ${err.getMessage}")

      text.map: body =>
        if body.endsWith("\r\n") then body.dropRight(2)
        else if body.endsWith("\n") then body.dropRight(1)
        else body

    override def describe(): String = s"file:$dir"

  /** HashiCorp Vault.
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
      addr: String,
      token: Option[String] = None,
      mountgiven: Option[String] = None,
      kvgiven: Option[Int] = None,
      vaultnamespace: Option[String] = None,
      auth: Option[AuthSpec] = None,
  ) extends Provider:

    private val mount: String = mountgiven.filter(_.nonEmpty).getOrElse("secret")
    private val kv: Int = kvgiven.getOrElse(2)

    // The working token: a configured token is kept forever, a logged-in
    // token is renewed shortly before its lease runs out - a long-running
    // process must not keep presenting a token the vault already expired.
    private var livetoken: Option[String] = token.filter(_.nonEmpty)
    private var renewat: Long = Long.MaxValue

    // A version typo like kv: 3 must not quietly behave as v2 and turn its
    // 404s into misses; there is nothing safe to assume it meant.
    if 1 != kv && 2 != kv then
      throw SekretoError(s"sekreto: hashicorp: unsupported kv version: $kv")

    private def baseheaders(): ListMap[String, String] =
      vaultnamespace.filter(_.nonEmpty) match
        case Some(value) => ListMap("X-Vault-Namespace" -> value)
        case None        => ListMap.empty

    private def login(): String =
      val use = auth.getOrElse(
        throw SekretoError("sekreto: hashicorp: no token and no auth method"),
      )

      val authmount = first(use.mount, Some(use.method))
      val url = trimslash(addr) + "/v1/auth/" + authmount + "/login"

      val body = use.method match
        case "kubernetes" =>
          val jwt = use.jwt.getOrElse:
            val file = use.jwtfile.getOrElse("/var/run/secrets/kubernetes.io/serviceaccount/token")
            try String(Files.readAllBytes(Paths.get(file)), StandardCharsets.UTF_8).trim
            catch
              case _: IOException =>
                throw SekretoError(s"sekreto: hashicorp: cannot read jwt file $file")

          Json.obj("role" -> Json.str(use.role.getOrElse("")), "jwt" -> Json.str(jwt))

        case "approle" =>
          Json.obj(
            "role_id" -> Json.str(use.roleid.getOrElse("")),
            "secret_id" -> Json.str(use.secretid.getOrElse("")),
          )

        case other => throw SekretoError(s"sekreto: hashicorp: unknown auth method: $other")

      val res = fetchjson("POST", url, baseheaders(), Some(Json.stringify(body)))

      val got = res.body.dig("auth", "client_token").text
      if 200 != res.status || !got.exists(_.nonEmpty) then
        throw SekretoError(s"sekreto: hashicorp login failed: ${res.status}: $url")

      renewat = renewtime(res.body.dig("auth", "lease_duration"))

      got.get

    override def lookup(name: String): Option[String] =
      checkaddr(addr)

      if livetoken.isEmpty || System.currentTimeMillis >= renewat then livetoken = Some(login())

      val ref = vaultref(name)
      val base = trimslash(addr) + "/v1/" + mount
      val url = if 1 == kv then s"$base/${ref.path}" else s"$base/data/${ref.path}"

      val headers = baseheaders().updated("X-Vault-Token", livetoken.getOrElse(""))

      val res = fetchjson("GET", url, headers)

      if 404 == res.status then None
      else if 200 != res.status then
        throw SekretoError(s"sekreto: hashicorp error: ${res.status}: $url")
      else
        val data = if 1 == kv then res.body.dig("data") else res.body.dig("data", "data")
        data.dig(ref.field).text

    override def describe(): String = s"hashicorp:$addr/$mount"

  /** A boru vault (https://github.com/boru-lang/boru).
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
      commandgiven: Option[String] = None,
      namespace: Option[String] = None,
      home: Option[String] = None,
      addrgiven: Option[String] = None,
      tokengiven: Option[String] = None,
      mountgiven: Option[String] = None,
  ) extends Provider:

    private val command: String = commandgiven.filter(_.nonEmpty).getOrElse("boru")
    private val addr: String = addrgiven.map(trimslash).getOrElse("")
    private val token: String = tokengiven.getOrElse("")
    private val mount: String = mountgiven.filter(_.nonEmpty).getOrElse("secret")

    override def lookup(name: String): Option[String] =
      checkname(name)

      if addr.nonEmpty then wirelookup(name)
      else
        val alias = namespace.filter(_.nonEmpty).map(space => s"$space:$name").getOrElse(name)

        val builder = ProcessBuilder(command, "vault", "get", "--reveal", alias)

        home.filter(_.nonEmpty).foreach(value => builder.environment().put("BORU_HOME", value))

        val ran = runcmd(builder, command)

        if 0 == ran.status then
          // boru prints the value and one newline, and nothing else.
          Some(dropsuffix(ran.out, "\n"))
        // "no alias named" is boru saying it does not hold this secret,
        // which is a miss: the chain carries on to the next provider. A
        // locked vault or a wrong passphrase is not a miss - treating it as
        // one would fall through to a weaker store without saying so.
        else if borumiss(ran.why) then None
        else
          throw SekretoError(
            "sekreto: boru vault error: " +
              (if ran.why.isEmpty then s"exit ${ran.status}" else ran.why),
          )

    private def wirelookup(name: String): Option[String] =
      checkaddr(addr)

      // The dotted name stays one path segment: boru aliases keep dots.
      val alias = namespace.filter(_.nonEmpty).map(space => s"$space/$name").getOrElse(name)
      val url = s"$addr/v1/$mount/data/$alias"

      val res = fetchjson("GET", url, Map("X-Vault-Token" -> token))

      if 404 == res.status then None
      else if 200 != res.status then
        throw SekretoError(s"sekreto: boru serve error: ${res.status}: $url")
      else res.body.dig("data", "data", "value").text

    override def describe(): String =
      if addr.nonEmpty then s"boru:$addr"
      else "boru" + (if namespace.exists(_.nonEmpty) then s":${namespace.get}" else "")

  /** Does this boru failure mean "no such secret" rather than "I could not
    * answer"? Matched on boru's own wording for a missing alias.
    */
  private[sekreto] def borumiss(why: String): Boolean = why.contains("no alias named")

  /** SecretSpec (https://secretspec.dev).
    *
    * SecretSpec is a declaration - a `secretspec.toml` naming the secrets a
    * project needs - plus a chain of its own backends to satisfy them from.
    * That makes it the same shape as sekreto one level down, and the reason
    * to support it is the same reason sekreto exists: a project that has
    * already declared its secrets there should not have to declare them
    * again here.
    *
    * Read through its CLI, as boru is, because that is the interface it
    * offers a program in another language: `secretspec get API_TOKEN` prints
    * the value on stdout and nothing else. A sekreto name maps to a
    * SecretSpec key exactly as it maps to an environment variable -
    * `api.token` is `API_TOKEN` - which is the convention SecretSpec's own
    * examples use.
    *
    * `backend` selects one of SecretSpec's backends (`--provider`, e.g.
    * `keyring` or `dotenv://.env`) and is called `backend` here only because
    * `provider` already means something else in this library.
    *
    * A reason is required, not optional: SecretSpec records every read in an
    * audit log and refuses to read at all without one. sekreto sends
    * `sekreto` unless told otherwise, so the audit trail says which tool
    * asked.
    */
  class Secretspec(
      commandgiven: Option[String] = None,
      file: Option[String] = None,
      profile: Option[String] = None,
      backend: Option[String] = None,
      reason: Option[String] = None,
      prefix: Option[String] = None,
  ) extends Provider:

    private val command: String = commandgiven.filter(_.nonEmpty).getOrElse("secretspec")

    override def lookup(name: String): Option[String] =
      val key = envkey(name, prefix)

      val args = scala.collection.mutable.ListBuffer(command)
      file.filter(_.nonEmpty).foreach(value => args ++= List("--file", value))
      args ++= List("get", key)
      backend.filter(_.nonEmpty).foreach(value => args ++= List("--provider", value))
      profile.filter(_.nonEmpty).foreach(value => args ++= List("--profile", value))
      args ++= List("--reason", first(reason, Some("sekreto")))

      val ran = runcmd(ProcessBuilder(args.asJava), command)

      if 0 == ran.status then
        // The value and one newline, and nothing else.
        Some(dropsuffix(ran.out, "\n"))
      else if secretspecmiss(ran.why, key) then None
      else
        throw SekretoError(
          "sekreto: secretspec error: " +
            (if ran.why.isEmpty then s"exit ${ran.status}" else ran.why),
        )

    override def describe(): String =
      "secretspec" + (if backend.exists(_.nonEmpty) then s":${backend.get}" else "")

  /** Does this SecretSpec failure mean "no such secret" rather than "I could
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
  private[sekreto] def secretspecmiss(why: String, key: String): Boolean =
    why.contains(s"Secret '$key' not found")

  /** The `YYYYMMDDTHHMMSSZ` timestamp SigV4 wants, for now. */
  private[sekreto] def awsnow(): String =
    DateTimeFormatter
      .ofPattern("yyyyMMdd'T'HHmmss'Z'")
      .withZone(ZoneOffset.UTC)
      .format(Instant.now)

  /** Region and credentials, resolved for one call. */
  private[sekreto] case class Awsauth(
      region: String,
      keyid: String,
      secret: String,
      session: Option[String],
  )

  /** Region and credentials, from config first and the standard AWS_*
    * environment variables second - those are AWS's own convention, and a
    * pod or CI job that has them set should just work. Missing either is an
    * error: an AWS store with no credentials could not answer.
    */
  private[sekreto] def awsauth(
      region: Option[String],
      keyid: Option[String],
      secret: Option[String],
      session: Option[String],
  ): Awsauth =
    val useregion = first(region, getenv("AWS_REGION"), getenv("AWS_DEFAULT_REGION"))
    val usekeyid = first(keyid, getenv("AWS_ACCESS_KEY_ID"))
    val usesecret = first(secret, getenv("AWS_SECRET_ACCESS_KEY"))
    val usesession = first(session, getenv("AWS_SESSION_TOKEN"))

    if useregion.isEmpty then
      throw SekretoError("sekreto: aws: no region (set region or AWS_REGION)")

    if usekeyid.isEmpty || usesecret.isEmpty then
      throw SekretoError(
        "sekreto: aws: no credentials" +
          " (set keyid/secret or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY)",
      )

    Awsauth(useregion, usekeyid, usesecret, Some(usesession).filter(_.nonEmpty))

  /** One signed call to an AWS JSON-1.1 API. */
  private[sekreto] def awscall(
      region: Option[String],
      keyid: Option[String],
      secret: Option[String],
      session: Option[String],
      addr: Option[String],
      service: String,
      target: String,
      payload: String,
  ): Answer =
    val auth = awsauth(region, keyid, secret, session)

    // The China partition lives under its own suffix; every other commercial
    // region is plain amazonaws.com.
    val suffix = if auth.region.startsWith("cn-") then ".amazonaws.com.cn" else ".amazonaws.com"
    val useaddr = first(addr, Some(s"https://$service.${auth.region}$suffix"))
    checkaddr(useaddr)

    val url = trimslash(useaddr) + "/"

    val extras = ListMap(
      "content-type" -> "application/x-amz-json-1.1",
      "x-amz-target" -> target,
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

    fetchjson("POST", url, extras ++ signed, Some(payload))

  /** Does this AWS error body name one of the not-found types? Those are a
    * miss; every other failure is a store that could not answer.
    */
  private[sekreto] def awsmiss(body: Option[Json], types: String*): Boolean =
    body.dig("__type").asstr match
      case Some(errtype) => types.exists(errtype.contains)
      case None          => false

  /** AWS Secrets Manager.
    *
    * `api.token` reads the secret named `api` (the vaultref path, so
    * `db.pass.main` reads `db/pass`) and takes the `token` field of its JSON
    * SecretString - the AWS idiom of one JSON map per secret. A SecretString
    * that is not JSON is the value itself, under the conventional field
    * `value`. Requests are SigV4-signed in-tree; see Sigv4.scala.
    */
  class Awssecrets(
      region: Option[String] = None,
      keyid: Option[String] = None,
      secret: Option[String] = None,
      session: Option[String] = None,
      addr: Option[String] = None,
  ) extends Provider:

    override def lookup(name: String): Option[String] =
      val ref = vaultref(name)

      val res = awscall(
        region,
        keyid,
        secret,
        session,
        addr,
        "secretsmanager",
        "secretsmanager.GetSecretValue",
        Json.stringify(Json.obj("SecretId" -> Json.str(ref.path))),
      )

      if 400 == res.status && awsmiss(res.body, "ResourceNotFoundException") then None
      else if 200 != res.status then
        throw SekretoError(s"sekreto: aws secretsmanager error: ${res.status}")
      else
        res.body.dig("SecretString").asstr match
          case None =>
            // A binary secret has no fields to address; only the
            // conventional `value` field can mean "the bytes themselves".
            val bin = res.body.dig("SecretBinary").asstr

            if bin.isDefined && "value" == ref.field then
              // decode() throws IllegalArgumentException on a bad payload,
              // which is not a SekretoError and so escaped the library's own
              // error type. A store that answered incoherently is an error.
              try Some(String(Base64.getDecoder.decode(bin.get), StandardCharsets.UTF_8))
              catch
                case _: IllegalArgumentException =>
                  throw SekretoError("sekreto: aws secretsmanager: undecodable secret")
            else None

          case Some(text) =>
            Json.parse(text) match
              case Some(Json.Obj(fields)) => fields.get(ref.field).flatMap(_.text)
              // A plain-string secret is the whole value; it has no named
              // fields.
              case _ => if "value" == ref.field then Some(text) else None

    // Config only, never the environment: describe() feeds the spec's
    // sources group, which must answer the same everywhere.
    override def describe(): String = s"awssecrets:${region.getOrElse("")}"

  /** AWS SSM Parameter Store.
    *
    * `db.pass.main` reads the parameter `/db/pass/main` (under an optional
    * prefix path), decrypted. Parameter Store carries flat strings, so there
    * is no field indirection.
    */
  class Awsparams(
      region: Option[String] = None,
      keyid: Option[String] = None,
      secret: Option[String] = None,
      session: Option[String] = None,
      addr: Option[String] = None,
      prefix: Option[String] = None,
  ) extends Provider:

    override def lookup(name: String): Option[String] =
      val payload = Json.obj(
        "Name" -> Json.str(awsparam(name, prefix)),
        "WithDecryption" -> Json.bool(true),
      )

      val res = awscall(
        region,
        keyid,
        secret,
        session,
        addr,
        "ssm",
        "AmazonSSM.GetParameter",
        Json.stringify(payload),
      )

      if 400 == res.status && awsmiss(res.body, "ParameterNotFound") then None
      else if 200 != res.status then throw SekretoError(s"sekreto: aws ssm error: ${res.status}")
      else res.body.dig("Parameter", "Value").text

    override def describe(): String =
      s"awsparams:${region.getOrElse("")}${prefix.getOrElse("")}"

  /** GCP Secret Manager.
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
      project: Option[String] = None,
      token: Option[String] = None,
      addr: Option[String] = None,
      metadataaddr: Option[String] = None,
  ) extends Provider:

    // A configured token is kept forever; a metadata-server token carries
    // expires_in and is renewed shortly before it runs out.
    private var livetoken: Option[String] = None
    private var renewat: Long = Long.MaxValue

    private def usemetadataaddr(): String =
      metadataaddr.filter(_.nonEmpty) match
        case Some(value) => value
        case None =>
          getenv("GCE_METADATA_HOST").filter(_.nonEmpty) match
            case Some(host) => s"http://$host"
            case None       => "http://metadata.google.internal"

    private def login(): String =
      val configured = first(token, getenv("GOOGLE_OAUTH_ACCESS_TOKEN"))
      if configured.nonEmpty then configured
      else
        val url = trimslash(usemetadataaddr()) +
          "/computeMetadata/v1/instance/service-accounts/default/token"

        val res = fetchjson("GET", url, Map("Metadata-Flavor" -> "Google"))

        val got = res.body.dig("access_token").text
        if 200 != res.status || !got.exists(_.nonEmpty) then
          throw SekretoError("sekreto: gcp: no token and metadata server did not answer")

        renewat = renewtime(res.body.dig("expires_in"))

        got.get

    override def lookup(name: String): Option[String] =
      val useproject = project.getOrElse("")
      if useproject.isEmpty then throw SekretoError("sekreto: gcp: no project")

      val useaddr = first(addr, Some("https://secretmanager.googleapis.com"))
      checkaddr(useaddr)

      if livetoken.isEmpty || System.currentTimeMillis >= renewat then livetoken = Some(login())

      val url = trimslash(useaddr) + "/v1/projects/" + useproject + "/secrets/" +
        flatname(name, "_") + "/versions/latest:access"

      val res = fetchjson("GET", url, Map("authorization" -> s"Bearer ${livetoken.getOrElse("")}"))

      if 404 == res.status then None
      else if 200 != res.status then
        throw SekretoError(s"sekreto: gcp error: ${res.status}: $url")
      else
        res.body.dig("payload", "data").asstr match
          case None => None
          // See the aws provider: an undecodable payload is a SekretoError.
          case Some(data) =>
            try Some(String(Base64.getDecoder.decode(data), StandardCharsets.UTF_8))
            catch
              case _: IllegalArgumentException =>
                throw SekretoError("sekreto: gcp: undecodable secret")

    override def describe(): String = s"gcpsecrets:${project.getOrElse("")}"

  /** The Key Vault audience an Azure token is minted for. */
  private val RESOURCE = "https://vault.azure.net"

  /** Azure Key Vault.
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
      vault: Option[String] = None,
      token: Option[String] = None,
      tenant: Option[String] = None,
      clientid: Option[String] = None,
      clientsecret: Option[String] = None,
      loginaddr: Option[String] = None,
      imdsaddr: Option[String] = None,
      apiversion: Option[String] = None,
  ) extends Provider:

    // A configured token is kept forever; logged-in and IMDS tokens carry
    // expires_in and are renewed shortly before they run out.
    private var livetoken: Option[String] = None
    private var renewat: Long = Long.MaxValue

    private def login(): String =
      if token.exists(_.nonEmpty) then token.get
      else if tenant.exists(_.nonEmpty) &&
        clientid.exists(_.nonEmpty) &&
        clientsecret.exists(_.nonEmpty)
      then
        val useloginaddr = first(loginaddr, Some("https://login.microsoftonline.com"))
        checkaddr(useloginaddr)

        val url = trimslash(useloginaddr) + "/" + tenant.get + "/oauth2/v2.0/token"
        val form = "grant_type=client_credentials&client_id=" + uriescape(clientid.get) +
          "&client_secret=" + uriescape(clientsecret.get) +
          "&scope=" + uriescape(s"$RESOURCE/.default")

        val res = fetchjson(
          "POST",
          url,
          Map("content-type" -> "application/x-www-form-urlencoded"),
          Some(form),
        )

        val got = res.body.dig("access_token").text
        if 200 != res.status || !got.exists(_.nonEmpty) then
          throw SekretoError(s"sekreto: azure login failed: ${res.status}")

        renewat = renewtime(res.body.dig("expires_in"))
        got.get
      else
        val imds = trimslash(first(imdsaddr, Some("http://169.254.169.254"))) +
          "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=" +
          uriescape(RESOURCE)

        val res = fetchjson("GET", imds, Map("Metadata" -> "true"))

        val got = res.body.dig("access_token").text
        if 200 != res.status || !got.exists(_.nonEmpty) then
          throw SekretoError(
            "sekreto: azure: no token, no client credentials, and IMDS did not answer",
          )

        renewat = renewtime(res.body.dig("expires_in"))
        got.get

    override def lookup(name: String): Option[String] =
      val usevault = vault.getOrElse("")
      if usevault.isEmpty then throw SekretoError("sekreto: azure: no vault")

      // Only an explicit scheme is a URL; a vault NAMED httpvault must still
      // become https://httpvault.vault.azure.net.
      val vaulturl =
        if usevault.startsWith("http://") || usevault.startsWith("https://") then usevault
        else s"https://$usevault.vault.azure.net"
      checkaddr(vaulturl)

      if livetoken.isEmpty || System.currentTimeMillis >= renewat then livetoken = Some(login())

      val url = trimslash(vaulturl) + "/secrets/" + flatname(name, "-") +
        "?api-version=" + first(apiversion, Some("7.4"))

      val res = fetchjson("GET", url, Map("authorization" -> s"Bearer ${livetoken.getOrElse("")}"))

      if 404 == res.status then None
      else if 200 != res.status then
        throw SekretoError(s"sekreto: azure error: ${res.status}: ${bare(url)}")
      else res.body.dig("value").text

    override def describe(): String = s"azuresecrets:${vault.getOrElse("")}"

  /** 1Password, through a Connect server.
    *
    * The item titled `api.token` (titles keep their dots), in the named
    * vault. The value is the field with purpose PASSWORD, or the field
    * labelled `value`. A vault that cannot be found is an error - config
    * names it, so its absence is a broken store, not a missing secret.
    */
  class Onepassword(
      addr: Option[String] = None,
      token: Option[String] = None,
      vault: Option[String] = None,
  ) extends Provider:

    private var vaultid: Option[String] = None

    private def auth(): Map[String, String] =
      Map("authorization" -> s"Bearer ${token.getOrElse("")}")

    private def resolvevault(useaddr: String): String =
      val want = vault.getOrElse("")
      if want.isEmpty then throw SekretoError("sekreto: onepassword: no vault")

      val res = fetchjson("GET", s"$useaddr/v1/vaults", auth())

      val list = res.body.asarr
      if 200 != res.status || list.isEmpty then
        throw SekretoError(s"sekreto: onepassword error: ${res.status}: listing vaults")

      val found = list.get.find: entry =>
        val id = entry.dig("id").text
        id.contains(want) || entry.dig("name").text.contains(want)

      found match
        case Some(entry) => entry.dig("id").text.getOrElse("")
        case None        => throw SekretoError(s"sekreto: onepassword: no vault named $want")

    override def lookup(name: String): Option[String] =
      checkname(name)

      val useaddr = trimslash(addr.getOrElse(""))
      if useaddr.isEmpty then throw SekretoError("sekreto: onepassword: no addr")
      checkaddr(useaddr)

      val id = vaultid.getOrElse:
        val resolved = resolvevault(useaddr)
        vaultid = Some(resolved)
        resolved

      val filter = uriescape(s"""title eq "$name"""")
      val found = fetchjson("GET", s"$useaddr/v1/vaults/$id/items?filter=$filter", auth())

      val items = found.body.asarr
      if 200 != found.status || items.isEmpty then
        throw SekretoError(s"sekreto: onepassword error: ${found.status}: finding $name")

      if items.get.isEmpty then None
      else
        val itemid = items.get.head.dig("id").text.getOrElse("")
        val item = fetchjson("GET", s"$useaddr/v1/vaults/$id/items/$itemid", auth())

        if 200 != item.status then
          throw SekretoError(s"sekreto: onepassword error: ${item.status}: reading $name")

        val fields = item.body.dig("fields").asarr.getOrElse(List.empty)

        fields.find(field => field.dig("purpose").asstr.contains("PASSWORD")) match
          case Some(field) => field.dig("value").text
          case None =>
            fields.find(field => field.dig("label").asstr.contains("value")) match
              case Some(field) => field.dig("value").text
              case None        => None

    override def describe(): String = s"onepassword:${vault.getOrElse("")}"

  /** Doppler.
    *
    * The whole config is downloaded once - Doppler's own bulk endpoint - and
    * answered from memory, like a remote .env: `api.token` is the
    * `API_TOKEN` entry. A service token is config-scoped, so project and
    * config are only needed with broader tokens.
    */
  class Doppler(
      token: Option[String] = None,
      project: Option[String] = None,
      config: Option[String] = None,
      addr: Option[String] = None,
  ) extends Provider:

    private var values: Option[Map[String, String]] = None

    private def load(): Map[String, String] =
      values match
        case Some(loaded) => loaded
        case None =>
          val useaddr = trimslash(first(addr, Some("https://api.doppler.com")))
          checkaddr(useaddr)

          var url = s"$useaddr/v3/configs/config/secrets/download?format=json"
          project.filter(_.nonEmpty).foreach(value => url += "&project=" + uriescape(value))
          config.filter(_.nonEmpty).foreach(value => url += "&config=" + uriescape(value))

          val res = fetchjson(
            "GET",
            url,
            Map("authorization" -> s"Bearer ${token.getOrElse("")}"),
          )

          val body = res.body.asobj
          if 200 != res.status || body.isEmpty then
            throw SekretoError(s"sekreto: doppler error: ${res.status}")

          var loaded = ListMap.empty[String, String]
          for (key, value) <- body.get do value.text.foreach(text => loaded = loaded.updated(key, text))

          values = Some(loaded)
          loaded

    override def lookup(name: String): Option[String] = load().get(envkey(name))

    override def describe(): String =
      "doppler" + (
        if project.exists(_.nonEmpty) then s":${project.get}/${config.getOrElse("")}" else ""
      )

  /** Infisical.
    *
    * `api.token` reads the secret keyed `API_TOKEN` (Infisical's own
    * convention is environment-style keys) at a secret path in one
    * environment of a project. Auth is a token, or a universal-auth (machine
    * identity) login with clientid/clientsecret.
    */
  class Infisical(
      addr: Option[String] = None,
      token: Option[String] = None,
      clientid: Option[String] = None,
      clientsecret: Option[String] = None,
      project: Option[String] = None,
      environment: Option[String] = None,
      path: Option[String] = None,
  ) extends Provider:

    // A configured token is kept forever; a universal-auth token carries
    // expiresIn and is renewed shortly before it runs out.
    private var livetoken: Option[String] = None
    private var renewat: Long = Long.MaxValue

    private def login(useaddr: String): String =
      if token.exists(_.nonEmpty) then token.get
      else
        if !clientid.exists(_.nonEmpty) || !clientsecret.exists(_.nonEmpty) then
          throw SekretoError("sekreto: infisical: no token and no client credentials")

        val body = Json.obj(
          "clientId" -> Json.str(clientid.get),
          "clientSecret" -> Json.str(clientsecret.get),
        )

        val res = fetchjson(
          "POST",
          s"$useaddr/api/v1/auth/universal-auth/login",
          Map("content-type" -> "application/json"),
          Some(Json.stringify(body)),
        )

        val got = res.body.dig("accessToken").text
        if 200 != res.status || !got.exists(_.nonEmpty) then
          throw SekretoError(s"sekreto: infisical login failed: ${res.status}")

        renewat = renewtime(res.body.dig("expiresIn"))

        got.get

    override def lookup(name: String): Option[String] =
      val useaddr = trimslash(first(addr, Some("https://app.infisical.com")))
      checkaddr(useaddr)

      val useproject = project.getOrElse("")
      val useenvironment = environment.getOrElse("")
      if useproject.isEmpty || useenvironment.isEmpty then
        throw SekretoError("sekreto: infisical: no project/environment")

      if livetoken.isEmpty || System.currentTimeMillis >= renewat then
        livetoken = Some(login(useaddr))

      val url = s"$useaddr/api/v3/secrets/raw/" + envkey(name) +
        "?workspaceId=" + uriescape(useproject) +
        "&environment=" + uriescape(useenvironment) +
        "&secretPath=" + uriescape(first(path, Some("/")))

      val res = fetchjson("GET", url, Map("authorization" -> s"Bearer ${livetoken.getOrElse("")}"))

      if 404 == res.status then None
      else if 200 != res.status then throw SekretoError(s"sekreto: infisical error: ${res.status}")
      else res.body.dig("secret", "secretValue").text

    override def describe(): String =
      s"infisical:${project.getOrElse("")}/${environment.getOrElse("")}"

  /** Build a provider from its declarative form - the same shape the shared
    * spec and an app's config file use.
    */
  def makeprovider(spec: ProviderSpec): Provider = spec.kind match
    case "env"    => Env(spec.prefix)
    case "dotenv" => Dotenv(spec.file.getOrElse(".env"), spec.prefix)
    case "memory" => Memory(spec.values, spec.prefix)
    case "file"   => File(spec.dir.getOrElse(""), spec.prefix)

    case "hashicorp" =>
      Hashicorp(
        spec.addr.getOrElse(""),
        spec.token,
        spec.mount,
        spec.kv,
        spec.vaultnamespace,
        spec.auth,
      )

    case "boru" =>
      Boru(spec.command, spec.namespace, spec.home, spec.addr, spec.token, spec.mount)

    case "awssecrets" =>
      Awssecrets(spec.region, spec.keyid, spec.secret, spec.session, spec.addr)

    case "awsparams" =>
      Awsparams(spec.region, spec.keyid, spec.secret, spec.session, spec.addr, spec.prefix)

    case "gcpsecrets" =>
      Gcpsecrets(spec.project, spec.token, spec.addr, spec.metadataaddr)

    case "azuresecrets" =>
      Azuresecrets(
        spec.vault,
        spec.token,
        spec.tenant,
        spec.clientid,
        spec.clientsecret,
        spec.loginaddr,
        spec.imdsaddr,
        spec.apiversion,
      )

    case "onepassword" => Onepassword(spec.addr, spec.token, spec.vault)

    case "doppler" => Doppler(spec.token, spec.project, spec.config, spec.addr)

    case "infisical" =>
      Infisical(
        spec.addr,
        spec.token,
        spec.clientid,
        spec.clientsecret,
        spec.project,
        spec.environment,
        spec.path,
      )

    case "secretspec" =>
      Secretspec(spec.command, spec.file, spec.profile, spec.backend, spec.reason, spec.prefix)

    case other => throw SekretoError(s"sekreto: unknown provider kind: $other")
