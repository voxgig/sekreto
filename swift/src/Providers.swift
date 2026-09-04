// The providers a Sekreto chains together.
//
// A provider answers one question: "do you have this secret?" It returns
// the value, or nil to mean "ask the next one". Nothing else about a
// provider is visible to the caller - which is the point: an app reads
// `api.token` and never learns whether it came from the environment, a
// .env file, HashiCorp Vault, AWS, GCP, Azure or a boru vault.
//
// Two failure shapes, and they are never interchangeable. A store that
// does not hold the secret is a MISS (nil) - the chain carries on. A store
// that could not answer - bad credentials, unreachable host, missing
// configuration - is an ERROR: falling through there would quietly reach
// for a weaker store.
//
// A port of typescript/src/Providers.ts, which is canonical.

import Dispatch
import Foundation

#if canImport(FoundationNetworking)
  import FoundationNetworking
#endif

// ------------------------------------------------------------ the specs

/// Logging in to a vault instead of being handed a token. `method` is
/// `kubernetes` or `approle`; `mount` defaults to the method name.
public struct AuthSpec: CustomStringConvertible {

  public var method: String
  public var mount: String?
  /// kubernetes: the Vault role to log in as.
  public var role: String?
  /// kubernetes: the service-account JWT itself (tests).
  public var jwt: String?
  /// kubernetes: where the JWT lives; the conventional pod path by default.
  public var jwtfile: String?
  /// approle: the role and secret ids.
  public var roleid: String?
  public var secretid: String?

  public init(
    method: String,
    mount: String? = nil,
    role: String? = nil,
    jwt: String? = nil,
    jwtfile: String? = nil,
    roleid: String? = nil,
    secretid: String? = nil
  ) {
    self.method = method
    self.mount = mount
    self.role = role
    self.jwt = jwt
    self.jwtfile = jwtfile
    self.roleid = roleid
    self.secretid = secretid
  }

  /// Printed without its credentials.
  ///
  /// A derived description prints every field, so
  /// `print("bad chain: \(specs)")` - which is what someone writes when a
  /// chain will not build - would put the service-account JWT and the
  /// AppRole secret id in the log. Fields that hold a credential report
  /// whether they are set, never what they are.
  public var description: String {
    return "AuthSpec(method=\(method), mount=\(shown(mount)), role=\(shown(role)), "
      + "jwtfile=\(shown(jwtfile)), roleid=\(shown(roleid)), "
      + "jwt=\(setornot(jwt)), secretid=\(setornot(secretid)))"
  }
}

/// What a credential field reports about itself.
public func setornot(_ value: String?) -> String {
  return (value?.isEmpty ?? true) ? "[unset]" : "[set]"
}

func shown(_ value: String?) -> String {
  return value ?? "nil"
}

/// The declarative form of a provider, as used in config and in the shared
/// spec. `kind` picks the provider; everything else is that kind's own.
public struct ProviderSpec: CustomStringConvertible {

  public var kind: String
  /// The store name `Sekreto.getfrom` addresses. Defaults to `kind`.
  public var name: String?
  public var prefix: String?
  /// dotenv: the file to read. secretspec: the declaration to read.
  public var file: String?
  /// memory: literal values, keyed like environment variables.
  public var values: Ordered<String>?
  /// file: the directory of one-secret-per-file entries.
  public var dir: String?
  /// hashicorp / boru (wire) / gcp / 1password / doppler / infisical: the base URL.
  public var addr: String?
  /// hashicorp / boru (wire) / gcp / azure / 1password / doppler / infisical: the token.
  public var token: String?
  /// hashicorp / boru (wire): the KV mount (default `secret`).
  public var mount: String?
  /// hashicorp: KV engine version, 1 or 2 (default 2).
  public var kv: Int?
  /// hashicorp: Vault Enterprise namespace (X-Vault-Namespace).
  public var vaultnamespace: String?
  /// hashicorp: log in for a token instead of being handed one.
  public var auth: AuthSpec?
  /// boru / secretspec: the executable to run (default: the kind's own name).
  public var command: String?
  /// secretspec: the profile to read (`--profile`).
  public var profile: String?
  /// secretspec: which of ITS backends to read from (`--provider`), e.g.
  /// `keyring` or `dotenv://.env`. Named `backend` here because `provider`
  /// already means a sekreto provider.
  public var backend: String?
  /// secretspec: the audit reason recorded for the read (`--reason`).
  public var reason: String?
  /// boru: the namespace qualifying the alias.
  public var namespace: String?
  /// boru: the vault home, passed as BORU_HOME.
  public var home: String?
  /// aws: region and credentials; the standard AWS_* variables fill the rest.
  public var region: String?
  public var keyid: String?
  public var secret: String?
  public var session: String?
  /// gcp / doppler / infisical: the project, however that store names it.
  public var project: String?
  /// azure: the Key Vault name or full URL. 1password: the vault name or id.
  public var vault: String?
  /// azure: client-credential login. infisical: universal-auth login.
  public var tenant: String?
  public var clientid: String?
  public var clientsecret: String?
  /// azure: where to log in / where IMDS answers. gcp: the metadata server.
  public var loginaddr: String?
  public var imdsaddr: String?
  public var metadataaddr: String?
  /// azure: the Key Vault API version (default 7.4).
  public var apiversion: String?
  /// doppler: the config slug (with `project`).
  public var config: String?
  /// infisical: the environment slug and secret path.
  public var environment: String?
  public var path: String?

  public init(
    kind: String,
    name: String? = nil,
    prefix: String? = nil,
    file: String? = nil,
    values: Ordered<String>? = nil,
    dir: String? = nil,
    addr: String? = nil,
    token: String? = nil,
    mount: String? = nil,
    kv: Int? = nil,
    vaultnamespace: String? = nil,
    auth: AuthSpec? = nil,
    command: String? = nil,
    profile: String? = nil,
    backend: String? = nil,
    reason: String? = nil,
    namespace: String? = nil,
    home: String? = nil,
    region: String? = nil,
    keyid: String? = nil,
    secret: String? = nil,
    session: String? = nil,
    project: String? = nil,
    vault: String? = nil,
    tenant: String? = nil,
    clientid: String? = nil,
    clientsecret: String? = nil,
    loginaddr: String? = nil,
    imdsaddr: String? = nil,
    metadataaddr: String? = nil,
    apiversion: String? = nil,
    config: String? = nil,
    environment: String? = nil,
    path: String? = nil
  ) {
    self.kind = kind
    self.name = name
    self.prefix = prefix
    self.file = file
    self.values = values
    self.dir = dir
    self.addr = addr
    self.token = token
    self.mount = mount
    self.kv = kv
    self.vaultnamespace = vaultnamespace
    self.auth = auth
    self.command = command
    self.profile = profile
    self.backend = backend
    self.reason = reason
    self.namespace = namespace
    self.home = home
    self.region = region
    self.keyid = keyid
    self.secret = secret
    self.session = session
    self.project = project
    self.vault = vault
    self.tenant = tenant
    self.clientid = clientid
    self.clientsecret = clientsecret
    self.loginaddr = loginaddr
    self.imdsaddr = imdsaddr
    self.metadataaddr = metadataaddr
    self.apiversion = apiversion
    self.config = config
    self.environment = environment
    self.path = path
  }

  /// Printed without its credentials. See AuthSpec.description: a derived
  /// one would put the Vault token, the AWS secret access key and the
  /// Azure client secret into whatever formatted it.
  public var description: String {
    return "ProviderSpec(kind=\(kind), name=\(shown(name)), addr=\(shown(addr)), "
      + "token=\(setornot(token)), secret=\(setornot(secret)), "
      + "clientsecret=\(setornot(clientsecret)), "
      + "auth=\(nil == auth ? "nil" : auth!.description))"
  }
}

// ------------------------------------------------------- shared machinery

/// How long any single vault round-trip may take before it is treated as
/// unreachable. Ports carry the same bound.
let TIMEOUT: Double = 10

/// How much of a response body will be read before the store is treated as
/// having answered incoherently. Ports carry the same bound.
///
/// Far above anything real - the largest legitimate payload this library
/// fetches is Doppler's whole-config download, measured in kilobytes. A
/// bound is needed because the timeout is not one: ten seconds on a
/// loopback or datacentre link is gigabytes, and the body is accumulated
/// in memory before it is parsed. This runs on an application's startup
/// path, so the failure is the application never starting.
let MAXBODY: Int = 8 * 1024 * 1024

/// An environment variable, or nil.
func getenv(_ name: String) -> String? {
  return ProcessInfo.processInfo.environment[name]
}

/// The first candidate that is set and non-empty, or empty.
public func first(_ candidates: String?...) -> String {
  for candidate in candidates {
    if let value = candidate, !value.isEmpty { return value }
  }
  return ""
}

func trimslash(_ text: String) -> String {
  return dropsuffix(text, "/")
}

/// A URL without its query string, for a message that must not leak one.
func bare(_ url: String) -> String {
  if let mark = url.firstIndex(of: "?") {
    return String(url[url.startIndex..<mark])
  }
  return url
}

/// What an error has to say for itself, never the empty string.
///
/// On Linux a refused connection arrives with a null `localizedDescription`
/// - "cannot reach ...: (null)" says nothing at all - so the description
/// of the error itself stands in.
func why(_ err: Error) -> String {
  let text = (err as NSError).localizedDescription

  if !text.isEmpty && "(null)" != text { return text }

  return String(describing: err)
}

// ------------------------------------------------------------ file reads

/// The outcome of reading a file that may legitimately not be there.
enum Readout {
  /// The bytes, as text.
  case text(String)
  /// No such file, or no such directory: "no secrets here", a MISS.
  case absent
  /// The file is there and could not be read: an ERROR.
  case failed(String)
}

/// Read a whole file.
///
/// Absence is a MISS and the chain carries on; anything else - permission
/// denied, an unreadable mount, a failing disk - is an ERROR, because
/// returning a miss there falls silently through to a weaker store.
///
/// The obvious spelling, `FileManager.fileExists`, is wrong in exactly the
/// case the rule exists for: it answers false for a directory the process
/// may not stat, and would turn a locked mount - the canonical "unreadable
/// mount" - into a miss. The read is attempted, and only a not-found
/// answer is read as absence.
func readfile(_ path: String) -> Readout {
  do {
    let data = try Data(contentsOf: URL(fileURLWithPath: path))
    return .text(String(decoding: data, as: UTF8.self))
  } catch {
    let err = error as NSError

    if NSCocoaErrorDomain == err.domain && NSFileReadNoSuchFileError == err.code {
      return .absent
    }

    // A path whose parent is a plain file, or is not there at all, really
    // is "no secrets here" - the ENOTDIR case, which not every platform
    // reports as a not-found error.
    let parent = (path as NSString).deletingLastPathComponent
    if !parent.isEmpty {
      var isdir: ObjCBool = false
      if !FileManager.default.fileExists(atPath: parent, isDirectory: &isdir) || !isdir.boolValue {
        return .absent
      }
    }

    return .failed(why(error))
  }
}

// ------------------------------------------------------------ subprocess

/// Where a command lives, searched along PATH. `Process` on Linux takes a
/// path, not a name, so the search a shell would do is done here.
func findcommand(_ command: String, _ environment: [String: String]) -> String? {
  if command.contains("/") {
    return FileManager.default.isExecutableFile(atPath: command) ? command : nil
  }

  for dir in (environment["PATH"] ?? "").components(separatedBy: ":") {
    let candidate = dir.isEmpty ? command : dir + "/" + command
    if FileManager.default.isExecutableFile(atPath: candidate) { return candidate }
  }

  return nil
}

/// What a finished child process left behind.
struct Ran {
  let out: String
  let why: String
  let status: Int32
}

/// Run a child to completion and collect both its streams.
///
/// The two streams are drained CONCURRENTLY. Reading stdout to EOF and
/// only then reading stderr deadlocks the moment the child writes more
/// than one pipe buffer (64 KiB on Linux) to stderr: the parent is blocked
/// waiting for stdout, the child is blocked waiting for room on stderr,
/// and neither can move. Nothing in this library sets a timeout, so that
/// hang is permanent - `get()` simply never returns. secretspec's
/// diagnostics are box-drawn and reach that size easily.
///
/// The child's stdin is the null device rather than a pipe nobody writes
/// to, so a CLI that reads it - one prompting for a passphrase when its
/// environment variable is absent - sees EOF and gives up instead of
/// waiting forever.
///
/// The argument list is passed as an array, never through a shell, and no
/// secret is ever put on a command line where the process table publishes
/// it.
func runcmd(_ argv: [String], _ environment: [String: String], _ command: String) throws -> Ran {
  // Resolved here rather than through `/usr/bin/env`, so that "this
  // binary is not installed" stays a `cannot run` error instead of
  // arriving as a non-zero exit that the miss detection would then have
  // to reason about.
  guard let binary = findcommand(argv[0], environment) else {
    throw SekretoError("sekreto: cannot run \(command): no such file or directory")
  }

  let process = Process()

  process.executableURL = URL(fileURLWithPath: binary)
  process.arguments = Array(argv.dropFirst())
  process.environment = environment

  let outpipe = Pipe()
  let errpipe = Pipe()

  process.standardInput = FileHandle.nullDevice
  process.standardOutput = outpipe
  process.standardError = errpipe

  do {
    try process.run()
  } catch {
    throw SekretoError("sekreto: cannot run \(command): \(why(error))")
  }

  var errdata = Data()
  let drained = DispatchSemaphore(value: 0)

  DispatchQueue.global().async {
    errdata = errpipe.fileHandleForReading.readDataToEndOfFile()
    drained.signal()
  }

  let outdata = outpipe.fileHandleForReading.readDataToEndOfFile()

  process.waitUntilExit()
  drained.wait()

  return Ran(
    out: String(decoding: outdata, as: UTF8.self),
    why: String(decoding: errdata, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines),
    status: process.terminationStatus
  )
}

// --------------------------------------------------------------- addresses

/// An address with any userinfo replaced by `[redacted]`, for messages.
///
/// Every refusal below names the address it refused, and one of them fires
/// precisely because the address carries a credential - so printing it
/// verbatim would write the password to stderr and into the logs. It
/// cannot be cleaned up afterwards either: that password was never
/// resolved as a secret, so redact() has never seen it and never will. The
/// host is what a reader needs to identify which chain entry is at fault;
/// the userinfo is not.
public func safeaddr(_ addr: String) -> String {
  guard let mark = addr.range(of: "://") else { return addr }

  let rest = String(addr[mark.upperBound...])
  let stop = rest.firstIndex { "/" == $0 || "?" == $0 || "#" == $0 }
  let authority = nil == stop ? rest : String(rest[rest.startIndex..<stop!])

  guard let at = authority.lastIndex(of: "@") else { return addr }

  let cut = authority.distance(from: authority.startIndex, to: at)
  let head = String(addr[addr.startIndex..<mark.upperBound])
  let tail = String(rest[rest.index(rest.startIndex, offsetBy: cut)...])

  return head + "[redacted]" + tail
}

/// Refuse to send a secret-bearing credential in the clear.
///
/// A vault API is HTTPS in any real deployment; plaintext is a dev-mode
/// convenience. Sending a token over http to anything but the local
/// machine puts both the token and the secret it fetches on the wire for
/// anyone on the path, so sekreto will not do it. Loopback stays allowed:
/// that is `vault server -dev`, `boru vault serve`, and this repo's own
/// test harness.
///
/// The address is read by hand, in the same handful of steps in every
/// port, rather than by each platform's URL parser. That is deliberate. A
/// dozen parsers disagree about malformed input - where userinfo ends,
/// whether `0177.0.0.1` is loopback, what an unclosed bracket means - and
/// a check that answers differently in different ports is not a check.
///
/// The rule this parse obeys, and the reason it can be trusted: it is
/// never more permissive than the HTTP client that will dial the address.
/// It ends the authority at `/`, `?` or `#` only, so a client that also
/// breaks on `\` (WHATWG does) can only ever see a SHORTER host than this
/// does. It refuses userinfo outright rather than locating its end. It
/// compares the host literally, so a numeric form no parser here agrees on
/// is refused rather than guessed at.
public func checkaddr(_ addr: String) throws {
  var scheme = ""

  // Literal and case-sensitive: `HTTP://localhost` is refused rather than
  // normalised, because normalising is where parsers start to disagree.
  if addr.hasPrefix("https://") {
    scheme = "https://"
  } else if addr.hasPrefix("http://") {
    scheme = "http://"
  } else {
    throw SekretoError("sekreto: not an http(s) address: \(safeaddr(addr))")
  }

  let rest = String(addr.dropFirst(scheme.count))
  let end = rest.firstIndex { "/" == $0 || "?" == $0 || "#" == $0 }
  let authority = nil == end ? rest : String(rest[rest.startIndex..<end!])

  // Userinfo is refused outright rather than parsed around, and on https
  // as well as http. No store this library speaks authenticates by
  // userinfo - they take a token or a signature - so an address carrying
  // one is a mistake at best. At worst it is the attack this whole
  // function exists to stop: `http://localhost:8200@evil.example.com/` is
  // a request to evil.example.com that reads, to anything that splits the
  // authority on ':', as loopback.
  if authority.contains("@") {
    throw SekretoError(
      "sekreto: refusing an address with embedded credentials: \(safeaddr(addr))")
  }

  // An opening bracket with no closing one is not an address at all.
  if authority.hasPrefix("[") && !authority.contains("]") {
    throw SekretoError("sekreto: not a valid http(s) address: \(safeaddr(addr))")
  }

  if "https://" == scheme { return }

  // A bracketed IPv6 literal keeps its brackets. Splitting the authority
  // on the first colon yields '[', so `http://[::1]:8200` could never
  // match - which made the '[::1]' entry below unreachable, and refused a
  // legitimate local vault.
  var host = authority

  if authority.hasPrefix("["), let close = authority.firstIndex(of: "]") {
    host = String(authority[authority.startIndex...close])
  } else if let colon = authority.firstIndex(of: ":") {
    host = String(authority[authority.startIndex..<colon])
  }

  host = asciilower(host)

  // Literal, and exactly these four. Nothing is normalised: `0177.0.0.1`,
  // `2130706433` and `[::ffff:127.0.0.1]` are all refused, because no two
  // URL parsers agree on what they mean.
  if "localhost" != host && "127.0.0.1" != host && "::1" != host && "[::1]" != host {
    throw SekretoError(
      "sekreto: refusing to send a token in plaintext to \(safeaddr(addr)) (use https)")
  }
}

// -------------------------------------------------------------------- http

/// One JSON round-trip's result: the status, and the parsed body.
struct Answer {
  let status: Int
  let body: Json?
}

/// The delegate that makes one round-trip behave.
///
/// Redirects are never followed: a vault API does not legitimately
/// redirect, and a followed redirect would carry X-Vault-Token to the
/// redirect's host (and could downgrade https to http), which checkaddr -
/// it only validates the configured address - cannot see. Answering the
/// completion handler with nil hands the redirect response itself back as
/// the result, which the caller then reads as the non-200 it is.
///
/// The body is counted as it arrives and the task cancelled one byte over
/// the bound, so an endless body is refused rather than accumulated in
/// memory until the deadline.
final class Roundtrip: NSObject, URLSessionDataDelegate {

  var status: Int = 0
  var data = Data()
  var oversize = false
  var failure: Error?

  let finished = DispatchSemaphore(value: 0)

  func urlSession(
    _ session: URLSession,
    dataTask: URLSessionDataTask,
    didReceive response: URLResponse,
    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void
  ) {
    if let http = response as? HTTPURLResponse {
      status = http.statusCode
    }
    completionHandler(.allow)
  }

  func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive chunk: Data) {
    if oversize { return }

    data.append(chunk)

    if MAXBODY < data.count {
      oversize = true
      dataTask.cancel()
    }
  }

  func urlSession(
    _ session: URLSession,
    task: URLSessionTask,
    willPerformHTTPRedirection response: HTTPURLResponse,
    newRequest request: URLRequest,
    completionHandler: @escaping (URLRequest?) -> Void
  ) {
    status = response.statusCode
    completionHandler(nil)
  }

  func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
    failure = error
    finished.signal()
  }
}

/// One JSON round-trip. Network failure is always an error - an
/// unreachable store is a store that could not answer.
func fetchjson(
  _ method: String,
  _ url: String,
  _ headers: Ordered<String> = Ordered<String>(),
  _ body: String? = nil
) throws -> Answer {
  guard let target = URL(string: url) else {
    throw SekretoError("sekreto: cannot reach \(bare(url)): not a usable address")
  }

  var request = URLRequest(url: target)
  request.httpMethod = method
  request.timeoutInterval = TIMEOUT

  for (key, value) in headers.pairs {
    request.setValue(value, forHTTPHeaderField: key)
  }

  if let text = body {
    request.httpBody = Data(text.utf8)
  }

  let config = URLSessionConfiguration.default
  config.timeoutIntervalForRequest = TIMEOUT
  config.timeoutIntervalForResource = TIMEOUT
  config.httpShouldSetCookies = false
  config.urlCache = nil
  config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
  // A proxy in the environment has sent a Vault token in the clear before,
  // and the GCP and Azure metadata endpoints are not loopback.
  config.connectionProxyDictionary = [:]

  let trip = Roundtrip()
  let session = URLSession(configuration: config, delegate: trip, delegateQueue: nil)

  session.dataTask(with: request).resume()
  trip.finished.wait()
  session.invalidateAndCancel()

  // One byte over the bound is enough to know it was exceeded. An endless
  // body is a store that could not answer, so this raises rather than
  // returning a miss - the latter would fall through to a weaker store on
  // an attacker's cue.
  if trip.oversize {
    throw SekretoError("sekreto: oversized response from \(bare(url))")
  }

  if let failure = trip.failure {
    throw SekretoError("sekreto: cannot reach \(bare(url)): \(why(failure))")
  }

  let text = String(decoding: trip.data, as: UTF8.self)
  let parsed = Json.parse(text)

  // A success status promised JSON; a body that does not parse means the
  // store could not answer coherently, and treating it as a miss would
  // fall through to a weaker store. Error statuses may carry any body -
  // they are decided on status alone.
  if 200 == trip.status && nil == parsed {
    throw SekretoError("sekreto: malformed response from \(bare(url))")
  }

  return Answer(status: trip.status, body: parsed)
}

/// When a logged-in token must be renewed, from its expiry in seconds (a
/// JSON number, or a string as Azure IMDS sends it): now + max(seconds -
/// 60, 1). A missing or zero expiry means never renew.
func renewtime(_ expires: Json?) -> Double {
  var seconds: Double = 0

  if let value = expires?.asnum {
    seconds = value
  } else if let text = expires?.asstr, let value = Double(text) {
    seconds = value
  }

  if seconds.isNaN || 0 >= seconds { return Double.greatestFiniteMagnitude }

  return nowms() + max(seconds - 60, 1) * 1000
}

func nowms() -> Double {
  return Date().timeIntervalSince1970 * 1000
}

// ------------------------------------------------------------- built in

/// Environment variables: `api.token` from `API_TOKEN`.
public final class EnvProvider: Provider {

  private let prefix: String?
  private let source: Ordered<String>?

  public init(prefix: String? = nil, source: Ordered<String>? = nil) {
    self.prefix = prefix
    self.source = source
  }

  public func lookup(_ name: String) throws -> String? {
    let key = try envkey(name, prefix)

    if let source = source { return source[key] }

    return getenv(key)
  }

  public func describe() -> String {
    let use = prefix ?? ""
    return use.isEmpty ? "env" : "env:\(use)"
  }
}

/// A `.env` file, read once, keyed exactly like the environment.
///
/// Loaded LAZILY: a chain may hold a dotenv provider and never be asked
/// anything, and an eager constructor would read whatever `.env` happens
/// to sit in the working directory.
public final class DotenvProvider: Provider {

  private let file: String
  private let prefix: String?
  private var values: Ordered<String>?

  public init(file: String, prefix: String? = nil) {
    self.file = file
    self.prefix = prefix
  }

  private func load() throws -> Ordered<String> {
    if let loaded = values { return loaded }

    var loaded = Ordered<String>()

    switch readfile(file) {
    case .text(let body):
      loaded = parsedotenv(body)
    // An absent file - or an absent directory - means "no secrets here",
    // exactly like the file provider.
    case .absent:
      loaded = Ordered<String>()
    case .failed(let err):
      throw SekretoError("sekreto: dotenv provider cannot read \(file): \(err)")
    }

    values = loaded
    return loaded
  }

  public func lookup(_ name: String) throws -> String? {
    return try load()[try envkey(name, prefix)]
  }

  public func describe() -> String {
    return "dotenv:\(file)"
  }
}

/// Literal values, keyed like environment variables. The spec uses this to
/// test chain behaviour without touching the outside world.
public final class MemoryProvider: Provider {

  private let values: Ordered<String>
  private let prefix: String?

  public init(values: Ordered<String>? = nil, prefix: String? = nil) {
    self.values = values ?? Ordered<String>()
    self.prefix = prefix
  }

  public func lookup(_ name: String) throws -> String? {
    return values[try envkey(name, prefix)]
  }

  public func describe() -> String {
    let use = prefix ?? ""
    return use.isEmpty ? "memory" : "memory:\(use)"
  }
}

/// A directory of one-secret-per-file entries, keyed like the environment:
/// `api.token` reads `<dir>/API_TOKEN`.
///
/// This is the shape of a mounted Kubernetes Secret, a Docker or Swarm
/// secret, and a systemd credentials directory, so those all work with no
/// further configuration. One trailing newline is stripped - tools that
/// write these files disagree about it, and a newline is never part of a
/// secret on purpose.
public final class FileProvider: Provider {

  private let dir: String
  private let prefix: String?

  public init(dir: String, prefix: String? = nil) {
    self.dir = dir
    self.prefix = prefix
  }

  public func lookup(_ name: String) throws -> String? {
    let key = try envkey(name, prefix)
    let path = dir.isEmpty ? key : (dir as NSString).appendingPathComponent(key)

    switch readfile(path) {
    case .absent:
      return nil
    case .failed(let err):
      throw SekretoError("sekreto: file provider cannot read \(path): \(err)")
    case .text(let body):
      if body.hasSuffix("\r\n") { return String(body.dropLast(2)) }
      if body.hasSuffix("\n") { return String(body.dropLast()) }
      return body
    }
  }

  public func describe() -> String {
    return "file:\(dir)"
  }
}

// ------------------------------------------------------------ hashicorp

/// HashiCorp Vault.
///
/// KV v2 (the default): `api.token` reads `{addr}/v1/{mount}/data/api` and
/// takes the `token` field of `data.data`. KV v1 (`kv: 1`) reads
/// `{addr}/v1/{mount}/api` and takes the field of `data`. A 404 means "not
/// here" - a miss - so a vault can sit in a chain with fallbacks.
///
/// A Vault Enterprise namespace rides the X-Vault-Namespace header, on
/// logins as well as reads.
///
/// Instead of being handed a token, the provider can log in: Kubernetes
/// auth (the pod's service-account JWT, from its conventional path) or
/// AppRole. A failed login is an error, never a miss - it means this store
/// could not answer at all.
public final class HashicorpProvider: Provider {

  private let addr: String
  private let mount: String
  private let kv: Int
  private let vaultnamespace: String?
  private let auth: AuthSpec?

  // The working token: a configured token is kept forever, a logged-in
  // token is renewed shortly before its lease runs out - a long-running
  // process must not keep presenting a token the vault already expired.
  private var livetoken: String?
  private var renewat: Double = Double.greatestFiniteMagnitude

  public init(
    addr: String,
    token: String? = nil,
    mount: String? = nil,
    kv: Int? = nil,
    vaultnamespace: String? = nil,
    auth: AuthSpec? = nil
  ) throws {
    self.addr = addr
    self.mount = first(mount, "secret")
    self.kv = kv ?? 2
    self.vaultnamespace = vaultnamespace
    self.auth = auth
    self.livetoken = (token?.isEmpty ?? true) ? nil : token

    // A version typo like kv: 3 must not quietly behave as v2 and turn its
    // 404s into misses; there is nothing safe to assume it meant.
    if 1 != self.kv && 2 != self.kv {
      throw SekretoError("sekreto: hashicorp: unsupported kv version: \(self.kv)")
    }
  }

  private func baseheaders() -> Ordered<String> {
    var out = Ordered<String>()

    if let space = vaultnamespace, !space.isEmpty {
      out["X-Vault-Namespace"] = space
    }

    return out
  }

  private func login() throws -> String {
    guard let use = auth else {
      throw SekretoError("sekreto: hashicorp: no token and no auth method")
    }

    let authmount = first(use.mount, use.method)
    let url = trimslash(addr) + "/v1/auth/" + authmount + "/login"

    var payload: Json

    switch use.method {
    case "kubernetes":
      var jwt = use.jwt ?? ""

      if jwt.isEmpty {
        let file = first(use.jwtfile, "/var/run/secrets/kubernetes.io/serviceaccount/token")

        guard case .text(let body) = readfile(file) else {
          throw SekretoError("sekreto: hashicorp: cannot read jwt file \(file)")
        }

        jwt = body.trimmingCharacters(in: .whitespacesAndNewlines)
      }

      payload = Json.obj([("role", .str(use.role ?? "")), ("jwt", .str(jwt))])

    case "approle":
      payload = Json.obj([
        ("role_id", .str(use.roleid ?? "")),
        ("secret_id", .str(use.secretid ?? "")),
      ])

    default:
      throw SekretoError("sekreto: hashicorp: unknown auth method: \(use.method)")
    }

    let res = try fetchjson("POST", url, baseheaders(), Json.stringify(payload))

    let got = res.body.dig("auth", "client_token").text

    if 200 != res.status || (got?.isEmpty ?? true) {
      throw SekretoError("sekreto: hashicorp login failed: \(res.status): \(url)")
    }

    renewat = renewtime(res.body.dig("auth", "lease_duration"))

    return got!
  }

  public func lookup(_ name: String) throws -> String? {
    try checkaddr(addr)

    if nil == livetoken || nowms() >= renewat {
      livetoken = try login()
    }

    let ref = try vaultref(name)
    let base = trimslash(addr) + "/v1/" + mount
    let url = 1 == kv ? "\(base)/\(ref.path)" : "\(base)/data/\(ref.path)"

    var headers = baseheaders()
    headers["X-Vault-Token"] = livetoken ?? ""

    let res = try fetchjson("GET", url, headers)

    // A 404 is this vault saying it does not hold the secret, so the chain
    // carries on. Anything else it refuses is a store that could not
    // answer.
    if 404 == res.status { return nil }

    if 200 != res.status {
      throw SekretoError("sekreto: hashicorp error: \(res.status): \(url)")
    }

    let data = 1 == kv ? res.body.dig("data") : res.body.dig("data", "data")

    return data.dig(ref.field).text
  }

  public func describe() -> String {
    return "hashicorp:\(addr)/\(mount)"
  }
}

// ----------------------------------------------------------------- boru

/// A boru vault (https://github.com/boru-lang/boru).
///
/// Two ways in, both boru's own.
///
/// With no `addr`, the CLI: `boru vault get --reveal <alias>` prints the
/// secret on stdout and nothing else. The passphrase is read by boru
/// itself from `BORU_VAULT_PASSPHRASE`; sekreto never accepts it as config
/// and never puts it on a command line, where it would show up in the
/// process table.
///
/// With an `addr`, boru's wire protocol: `boru vault serve` publishes a
/// read-only, HashiCorp-shaped provision API, authenticated by a
/// capability token from `boru vault grant`. A sekreto name is already a
/// valid boru alias, and boru aliases keep their dots, so `api.token` is
/// the single path segment `api.token` - not the `api`/`token` split a
/// HashiCorp KV gets. The value is the `value` field.
public final class BoruProvider: Provider {

  private let command: String
  private let namespace: String?
  private let home: String?
  private let addr: String
  private let token: String
  private let mount: String

  public init(
    command: String? = nil,
    namespace: String? = nil,
    home: String? = nil,
    addr: String? = nil,
    token: String? = nil,
    mount: String? = nil
  ) {
    self.command = first(command, "boru")
    self.namespace = namespace
    self.home = home
    self.addr = trimslash(addr ?? "")
    self.token = token ?? ""
    self.mount = first(mount, "secret")
  }

  public func lookup(_ name: String) throws -> String? {
    _ = try checkname(name)

    if !addr.isEmpty { return try wirelookup(name) }

    // The CLI alias is namespace-qualified with a COLON; the wire one with
    // a slash. Both are boru's own spellings.
    var alias = name
    if let space = namespace, !space.isEmpty { alias = "\(space):\(name)" }

    var environment = ProcessInfo.processInfo.environment
    if let usehome = home, !usehome.isEmpty { environment["BORU_HOME"] = usehome }

    let ran = try runcmd(
      [command, "vault", "get", "--reveal", alias], environment, command)

    if 0 == ran.status {
      // boru prints the value and one newline, and nothing else.
      return dropsuffix(ran.out, "\n")
    }

    // "no alias named" is boru saying it does not hold this secret, which
    // is a miss: the chain carries on to the next provider. A locked vault
    // or a wrong passphrase is not a miss - treating it as one would fall
    // through to a weaker store without saying so.
    if borumiss(ran.why) { return nil }

    throw SekretoError(
      "sekreto: boru vault error: " + (ran.why.isEmpty ? "exit \(ran.status)" : ran.why))
  }

  private func wirelookup(_ name: String) throws -> String? {
    try checkaddr(addr)

    // The dotted name stays one path segment: boru aliases keep dots.
    var alias = name
    if let space = namespace, !space.isEmpty { alias = "\(space)/\(name)" }

    let url = "\(addr)/v1/\(mount)/data/\(alias)"

    var headers = Ordered<String>()
    headers["X-Vault-Token"] = token

    let res = try fetchjson("GET", url, headers)

    if 404 == res.status { return nil }

    if 200 != res.status {
      throw SekretoError("sekreto: boru serve error: \(res.status): \(url)")
    }

    return res.body.dig("data", "data", "value").text
  }

  public func describe() -> String {
    if !addr.isEmpty { return "boru:\(addr)" }

    let space = namespace ?? ""
    return space.isEmpty ? "boru" : "boru:\(space)"
  }
}

/// Does this boru failure mean "no such secret" rather than "I could not
/// answer"? Matched on boru's own wording for a missing alias.
public func borumiss(_ why: String) -> Bool {
  return why.contains("no alias named")
}

// ----------------------------------------------------------- secretspec

/// SecretSpec (https://secretspec.dev).
///
/// SecretSpec is a declaration - a `secretspec.toml` naming the secrets a
/// project needs - plus a chain of its own backends to satisfy them from.
/// That makes it the same shape as sekreto one level down, and the reason
/// to support it is the same reason sekreto exists: a project that has
/// already declared its secrets there should not have to declare them
/// again here.
///
/// `backend` selects one of SecretSpec's backends (`--provider`) and is
/// called `backend` here only because `provider` already means something
/// else in this library.
///
/// A reason is required, not optional: SecretSpec records every read in an
/// audit log and refuses to read at all without one.
public final class SecretspecProvider: Provider {

  private let command: String
  private let file: String?
  private let profile: String?
  private let backend: String?
  private let reason: String?
  private let prefix: String?

  public init(
    command: String? = nil,
    file: String? = nil,
    profile: String? = nil,
    backend: String? = nil,
    reason: String? = nil,
    prefix: String? = nil
  ) {
    self.command = first(command, "secretspec")
    self.file = file
    self.profile = profile
    self.backend = backend
    self.reason = reason
    self.prefix = prefix
  }

  public func lookup(_ name: String) throws -> String? {
    let key = try envkey(name, prefix)

    // `--file` comes BEFORE the subcommand; everything else after it.
    var argv = [command]
    if let use = file, !use.isEmpty { argv += ["--file", use] }
    argv += ["get", key]
    if let use = backend, !use.isEmpty { argv += ["--provider", use] }
    if let use = profile, !use.isEmpty { argv += ["--profile", use] }
    argv += ["--reason", first(reason, "sekreto")]

    let ran = try runcmd(argv, ProcessInfo.processInfo.environment, command)

    if 0 == ran.status {
      // The value and one newline, and nothing else.
      return dropsuffix(ran.out, "\n")
    }

    if secretspecmiss(ran.why, key) { return nil }

    throw SekretoError(
      "sekreto: secretspec error: " + (ran.why.isEmpty ? "exit \(ran.status)" : ran.why))
  }

  public func describe() -> String {
    let use = backend ?? ""
    return use.isEmpty ? "secretspec" : "secretspec:\(use)"
  }
}

/// Does this SecretSpec failure mean "no such secret" rather than "I could
/// not answer"?
///
/// MATCHED ON THE WHOLE PHRASE, NOT ON "not found". SecretSpec also says
/// `Provider backend 'keyring' not found`, which is a store that could not
/// answer at all - and reading that as a miss is the worst failure this
/// library has, because the chain then falls through to a weaker store
/// without saying so. The key is required to appear, so the two cannot be
/// confused.
public func secretspecmiss(_ why: String, _ key: String) -> Bool {
  return why.contains("Secret '\(key)' not found")
}

// ------------------------------------------------------------------ aws

/// The `YYYYMMDDTHHMMSSZ` timestamp SigV4 wants, for now.
func awsnow() -> String {
  let stamp = DateFormatter()
  stamp.dateFormat = "yyyyMMdd'T'HHmmss'Z'"
  stamp.timeZone = TimeZone(identifier: "UTC")
  stamp.locale = Locale(identifier: "en_US_POSIX")
  return stamp.string(from: Date())
}

/// Region and credentials, resolved for one call.
struct Awsauth {
  let region: String
  let keyid: String
  let secret: String
  let session: String?
}

/// Region and credentials, from config first and the standard AWS_*
/// environment variables second - those are AWS's own convention, and a
/// pod or CI job that has them set should just work. Missing either is an
/// error: an AWS store with no credentials could not answer.
func awsauth(
  _ region: String?, _ keyid: String?, _ secret: String?, _ session: String?
) throws -> Awsauth {
  let useregion = first(region, getenv("AWS_REGION"), getenv("AWS_DEFAULT_REGION"))
  let usekeyid = first(keyid, getenv("AWS_ACCESS_KEY_ID"))
  let usesecret = first(secret, getenv("AWS_SECRET_ACCESS_KEY"))
  let usesession = first(session, getenv("AWS_SESSION_TOKEN"))

  if useregion.isEmpty {
    throw SekretoError("sekreto: aws: no region (set region or AWS_REGION)")
  }

  if usekeyid.isEmpty || usesecret.isEmpty {
    throw SekretoError(
      "sekreto: aws: no credentials"
        + " (set keyid/secret or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY)")
  }

  return Awsauth(
    region: useregion,
    keyid: usekeyid,
    secret: usesecret,
    session: usesession.isEmpty ? nil : usesession
  )
}

/// One signed call to an AWS JSON-1.1 API.
func awscall(
  _ region: String?,
  _ keyid: String?,
  _ secret: String?,
  _ session: String?,
  _ addr: String?,
  _ service: String,
  _ target: String,
  _ payload: String
) throws -> Answer {
  let auth = try awsauth(region, keyid, secret, session)

  // The China partition lives under its own suffix; every other commercial
  // region is plain amazonaws.com.
  let suffix = auth.region.hasPrefix("cn-") ? ".amazonaws.com.cn" : ".amazonaws.com"
  let useaddr = first(addr, "https://\(service).\(auth.region)\(suffix)")
  try checkaddr(useaddr)

  let url = trimslash(useaddr) + "/"

  var extras = Ordered<String>()
  extras["content-type"] = "application/x-amz-json-1.1"
  extras["x-amz-target"] = target

  let signed = sigv4(
    Signing(
      method: "POST",
      url: url,
      service: service,
      region: auth.region,
      keyid: auth.keyid,
      secret: auth.secret,
      datetime: awsnow(),
      headers: extras,
      body: payload,
      session: auth.session
    ))

  var headers = extras
  for (key, value) in signed.pairs {
    headers[key] = value
  }

  return try fetchjson("POST", url, headers, payload)
}

/// Does this AWS error body name one of the not-found types? Those are a
/// miss; every other failure is a store that could not answer.
func awsmiss(_ body: Json?, _ types: [String]) -> Bool {
  guard let errtype = body.dig("__type").asstr else { return false }

  for want in types where errtype.contains(want) {
    return true
  }

  return false
}

/// AWS Secrets Manager.
///
/// `api.token` reads the secret named `api` (the vaultref path, so
/// `db.pass.main` reads `db/pass`) and takes the `token` field of its JSON
/// SecretString - the AWS idiom of one JSON map per secret. A SecretString
/// that is not JSON is the value itself, under the conventional field
/// `value`. Requests are SigV4-signed in-tree; see Sigv4.swift.
public final class AwssecretsProvider: Provider {

  private let region: String?
  private let keyid: String?
  private let secret: String?
  private let session: String?
  private let addr: String?

  public init(
    region: String? = nil,
    keyid: String? = nil,
    secret: String? = nil,
    session: String? = nil,
    addr: String? = nil
  ) {
    self.region = region
    self.keyid = keyid
    self.secret = secret
    self.session = session
    self.addr = addr
  }

  public func lookup(_ name: String) throws -> String? {
    let ref = try vaultref(name)

    let res = try awscall(
      region, keyid, secret, session, addr,
      "secretsmanager",
      "secretsmanager.GetSecretValue",
      Json.stringify(Json.obj([("SecretId", .str(ref.path))]))
    )

    if 400 == res.status && awsmiss(res.body, ["ResourceNotFoundException"]) { return nil }

    if 200 != res.status {
      throw SekretoError("sekreto: aws secretsmanager error: \(res.status)")
    }

    guard let text = res.body.dig("SecretString").asstr else {
      // A binary secret has no fields to address; only the conventional
      // `value` field can mean "the bytes themselves".
      guard let binary = res.body.dig("SecretBinary").asstr, "value" == ref.field else {
        return nil
      }

      guard let decoded = unbase64(binary) else {
        throw SekretoError("sekreto: aws secretsmanager: undecodable secret")
      }

      return decoded
    }

    if let parsed = Json.parse(text), let fields = parsed.asmap {
      return fields[ref.field].text
    }

    // A plain-string secret is the whole value; it has no named fields.
    return "value" == ref.field ? text : nil
  }

  // Config only, never the environment: describe() feeds the spec's
  // sources group, which must answer the same everywhere.
  public func describe() -> String {
    return "awssecrets:\(region ?? "")"
  }
}

/// AWS SSM Parameter Store.
///
/// `db.pass.main` reads the parameter `/db/pass/main` (under an optional
/// prefix path), decrypted. Parameter Store carries flat strings, so there
/// is no field indirection.
public final class AwsparamsProvider: Provider {

  private let region: String?
  private let keyid: String?
  private let secret: String?
  private let session: String?
  private let addr: String?
  private let prefix: String?

  public init(
    region: String? = nil,
    keyid: String? = nil,
    secret: String? = nil,
    session: String? = nil,
    addr: String? = nil,
    prefix: String? = nil
  ) {
    self.region = region
    self.keyid = keyid
    self.secret = secret
    self.session = session
    self.addr = addr
    self.prefix = prefix
  }

  public func lookup(_ name: String) throws -> String? {
    let payload = Json.obj([
      ("Name", .str(try awsparam(name, prefix))),
      ("WithDecryption", .bool(true)),
    ])

    let res = try awscall(
      region, keyid, secret, session, addr,
      "ssm",
      "AmazonSSM.GetParameter",
      Json.stringify(payload)
    )

    if 400 == res.status && awsmiss(res.body, ["ParameterNotFound"]) { return nil }

    if 200 != res.status {
      throw SekretoError("sekreto: aws ssm error: \(res.status)")
    }

    return res.body.dig("Parameter", "Value").text
  }

  public func describe() -> String {
    return "awsparams:\(region ?? "")\(prefix ?? "")"
  }
}

// ------------------------------------------------------------------ gcp

/// GCP Secret Manager.
///
/// `api.token` reads secret `api_token` (dots flattened to `_`; Secret
/// Manager ids have no hierarchy and reject dots), latest version. The
/// token comes from config, then `GOOGLE_OAUTH_ACCESS_TOKEN`, then the
/// GCE/GKE metadata server - so on Google's own platform no credential
/// configuration is needed at all.
///
/// The metadata call itself is plain http to a link-local host by platform
/// design; no credential rides on it, so `checkaddr` guards the Secret
/// Manager address instead.
public final class GcpsecretsProvider: Provider {

  private let project: String?
  private let token: String?
  private let addr: String?
  private let metadataaddr: String?

  private var livetoken: String?
  private var renewat: Double = Double.greatestFiniteMagnitude

  public init(
    project: String? = nil,
    token: String? = nil,
    addr: String? = nil,
    metadataaddr: String? = nil
  ) {
    self.project = project
    self.token = token
    self.addr = addr
    self.metadataaddr = metadataaddr
  }

  private func usemetadataaddr() -> String {
    if let use = metadataaddr, !use.isEmpty { return use }

    if let host = getenv("GCE_METADATA_HOST"), !host.isEmpty { return "http://\(host)" }

    return "http://metadata.google.internal"
  }

  private func login() throws -> String {
    let configured = first(token, getenv("GOOGLE_OAUTH_ACCESS_TOKEN"))
    if !configured.isEmpty { return configured }

    let url =
      trimslash(usemetadataaddr())
      + "/computeMetadata/v1/instance/service-accounts/default/token"

    var headers = Ordered<String>()
    headers["Metadata-Flavor"] = "Google"

    let res = try fetchjson("GET", url, headers)

    let got = res.body.dig("access_token").text

    if 200 != res.status || (got?.isEmpty ?? true) {
      throw SekretoError("sekreto: gcp: no token and metadata server did not answer")
    }

    renewat = renewtime(res.body.dig("expires_in"))

    return got!
  }

  public func lookup(_ name: String) throws -> String? {
    let useproject = project ?? ""
    if useproject.isEmpty { throw SekretoError("sekreto: gcp: no project") }

    let useaddr = first(addr, "https://secretmanager.googleapis.com")
    try checkaddr(useaddr)

    if nil == livetoken || nowms() >= renewat {
      livetoken = try login()
    }

    let url =
      trimslash(useaddr) + "/v1/projects/" + useproject + "/secrets/"
      + (try flatname(name, "_")) + "/versions/latest:access"

    var headers = Ordered<String>()
    headers["authorization"] = "Bearer \(livetoken ?? "")"

    let res = try fetchjson("GET", url, headers)

    if 404 == res.status { return nil }

    if 200 != res.status {
      throw SekretoError("sekreto: gcp error: \(res.status): \(url)")
    }

    guard let data = res.body.dig("payload", "data").asstr else { return nil }

    guard let decoded = unbase64(data) else {
      throw SekretoError("sekreto: gcp: undecodable secret")
    }

    return decoded
  }

  public func describe() -> String {
    return "gcpsecrets:\(project ?? "")"
  }
}

// ---------------------------------------------------------------- azure

/// The Key Vault audience an Azure token is minted for.
let AZURERESOURCE = "https://vault.azure.net"

/// Azure Key Vault.
///
/// `api.token` reads secret `api-token` (dots flattened to `-`; Key Vault
/// names allow nothing else), current version. The token comes from
/// config, then a client-credentials login when tenant/clientid/
/// clientsecret are given, then the IMDS managed-identity endpoint - so on
/// Azure's own platform no credential configuration is needed.
///
/// As with GCP, the IMDS call is plain http to a link-local host by
/// platform design and carries no credential; the login and vault
/// addresses are `checkaddr`-guarded.
public final class AzuresecretsProvider: Provider {

  private let vault: String?
  private let token: String?
  private let tenant: String?
  private let clientid: String?
  private let clientsecret: String?
  private let loginaddr: String?
  private let imdsaddr: String?
  private let apiversion: String?

  private var livetoken: String?
  private var renewat: Double = Double.greatestFiniteMagnitude

  public init(
    vault: String? = nil,
    token: String? = nil,
    tenant: String? = nil,
    clientid: String? = nil,
    clientsecret: String? = nil,
    loginaddr: String? = nil,
    imdsaddr: String? = nil,
    apiversion: String? = nil
  ) {
    self.vault = vault
    self.token = token
    self.tenant = tenant
    self.clientid = clientid
    self.clientsecret = clientsecret
    self.loginaddr = loginaddr
    self.imdsaddr = imdsaddr
    self.apiversion = apiversion
  }

  private func login() throws -> String {
    if let use = token, !use.isEmpty { return use }

    let usetenant = tenant ?? ""
    let useclientid = clientid ?? ""
    let useclientsecret = clientsecret ?? ""

    if !usetenant.isEmpty && !useclientid.isEmpty && !useclientsecret.isEmpty {
      let useloginaddr = first(loginaddr, "https://login.microsoftonline.com")
      try checkaddr(useloginaddr)

      let url = trimslash(useloginaddr) + "/" + usetenant + "/oauth2/v2.0/token"
      let form =
        "grant_type=client_credentials&client_id=" + uriescape(useclientid)
        + "&client_secret=" + uriescape(useclientsecret)
        + "&scope=" + uriescape("\(AZURERESOURCE)/.default")

      var headers = Ordered<String>()
      headers["content-type"] = "application/x-www-form-urlencoded"

      let res = try fetchjson("POST", url, headers, form)

      let got = res.body.dig("access_token").text

      if 200 != res.status || (got?.isEmpty ?? true) {
        throw SekretoError("sekreto: azure login failed: \(res.status)")
      }

      renewat = renewtime(res.body.dig("expires_in"))

      return got!
    }

    let imds =
      trimslash(first(imdsaddr, "http://169.254.169.254"))
      + "/metadata/identity/oauth2/token?api-version=2018-02-01&resource="
      + uriescape(AZURERESOURCE)

    var headers = Ordered<String>()
    headers["Metadata"] = "true"

    let res = try fetchjson("GET", imds, headers)

    let got = res.body.dig("access_token").text

    if 200 != res.status || (got?.isEmpty ?? true) {
      throw SekretoError(
        "sekreto: azure: no token, no client credentials, and IMDS did not answer")
    }

    // IMDS sends expires_in as a STRING, unlike everybody else.
    renewat = renewtime(res.body.dig("expires_in"))

    return got!
  }

  public func lookup(_ name: String) throws -> String? {
    let usevault = vault ?? ""
    if usevault.isEmpty { throw SekretoError("sekreto: azure: no vault") }

    // Only an explicit scheme is a URL; a vault NAMED httpvault must still
    // become https://httpvault.vault.azure.net.
    let vaulturl =
      (usevault.hasPrefix("http://") || usevault.hasPrefix("https://"))
      ? usevault : "https://\(usevault).vault.azure.net"
    try checkaddr(vaulturl)

    if nil == livetoken || nowms() >= renewat {
      livetoken = try login()
    }

    let url =
      trimslash(vaulturl) + "/secrets/" + (try flatname(name, "-"))
      + "?api-version=" + first(apiversion, "7.4")

    var headers = Ordered<String>()
    headers["authorization"] = "Bearer \(livetoken ?? "")"

    let res = try fetchjson("GET", url, headers)

    if 404 == res.status { return nil }

    if 200 != res.status {
      throw SekretoError("sekreto: azure error: \(res.status): \(bare(url))")
    }

    return res.body.dig("value").text
  }

  public func describe() -> String {
    return "azuresecrets:\(vault ?? "")"
  }
}

// ----------------------------------------------------------- 1password

/// 1Password, through a Connect server.
///
/// The item titled `api.token` (titles keep their dots), in the named
/// vault. The value is the field with purpose PASSWORD, or the field
/// labelled `value`. A vault that cannot be found is an error - config
/// names it, so its absence is a broken store, not a missing secret.
public final class OnepasswordProvider: Provider {

  private let addr: String?
  private let token: String?
  private let vault: String?

  private var vaultid: String?

  public init(addr: String? = nil, token: String? = nil, vault: String? = nil) {
    self.addr = addr
    self.token = token
    self.vault = vault
  }

  private func auth() -> Ordered<String> {
    var out = Ordered<String>()
    out["authorization"] = "Bearer \(token ?? "")"
    return out
  }

  private func resolvevault(_ useaddr: String) throws -> String {
    let want = vault ?? ""
    if want.isEmpty { throw SekretoError("sekreto: onepassword: no vault") }

    let res = try fetchjson("GET", "\(useaddr)/v1/vaults", auth())

    guard 200 == res.status, let list = res.body.aslist else {
      throw SekretoError("sekreto: onepassword error: \(res.status): listing vaults")
    }

    for entry in list {
      let id = entry.dig("id").text
      let name = entry.dig("name").text

      if want == id || want == name {
        return id ?? ""
      }
    }

    throw SekretoError("sekreto: onepassword: no vault named \(want)")
  }

  public func lookup(_ name: String) throws -> String? {
    _ = try checkname(name)

    let useaddr = trimslash(addr ?? "")
    if useaddr.isEmpty { throw SekretoError("sekreto: onepassword: no addr") }
    try checkaddr(useaddr)

    if nil == vaultid {
      vaultid = try resolvevault(useaddr)
    }

    let id = vaultid ?? ""

    let filter = uriescape("title eq \"\(name)\"")
    let found = try fetchjson("GET", "\(useaddr)/v1/vaults/\(id)/items?filter=\(filter)", auth())

    guard 200 == found.status, let items = found.body.aslist else {
      throw SekretoError("sekreto: onepassword error: \(found.status): finding \(name)")
    }

    if items.isEmpty { return nil }

    let itemid = items[0].dig("id").text ?? ""
    let item = try fetchjson("GET", "\(useaddr)/v1/vaults/\(id)/items/\(itemid)", auth())

    if 200 != item.status {
      throw SekretoError("sekreto: onepassword error: \(item.status): reading \(name)")
    }

    let fields = item.body.dig("fields").aslist ?? []

    // Two full passes, in order: a password field wins over a field merely
    // labelled `value`.
    for field in fields where "PASSWORD" == field.dig("purpose").asstr {
      return field.dig("value").text
    }

    for field in fields where "value" == field.dig("label").asstr {
      return field.dig("value").text
    }

    return nil
  }

  public func describe() -> String {
    return "onepassword:\(vault ?? "")"
  }
}

// -------------------------------------------------------------- doppler

/// Doppler.
///
/// The whole config is downloaded once - Doppler's own bulk endpoint - and
/// answered from memory, like a remote .env: `api.token` is the
/// `API_TOKEN` entry. A service token is config-scoped, so project and
/// config are only needed with broader tokens.
public final class DopplerProvider: Provider {

  private let token: String?
  private let project: String?
  private let config: String?
  private let addr: String?

  private var values: Ordered<String>?

  public init(
    token: String? = nil, project: String? = nil, config: String? = nil, addr: String? = nil
  ) {
    self.token = token
    self.project = project
    self.config = config
    self.addr = addr
  }

  private func load() throws -> Ordered<String> {
    if let loaded = values { return loaded }

    let useaddr = trimslash(first(addr, "https://api.doppler.com"))
    try checkaddr(useaddr)

    var url = "\(useaddr)/v3/configs/config/secrets/download?format=json"
    if let use = project, !use.isEmpty { url += "&project=" + uriescape(use) }
    if let use = config, !use.isEmpty { url += "&config=" + uriescape(use) }

    var headers = Ordered<String>()
    headers["authorization"] = "Bearer \(token ?? "")"

    let res = try fetchjson("GET", url, headers)

    guard 200 == res.status, let body = res.body.asmap else {
      throw SekretoError("sekreto: doppler error: \(res.status)")
    }

    var loaded = Ordered<String>()

    for (key, value) in body.pairs {
      if let text = value.text { loaded[key] = text }
    }

    // Only a successful load is remembered: a failed one retries.
    values = loaded
    return loaded
  }

  public func lookup(_ name: String) throws -> String? {
    return try load()[try envkey(name)]
  }

  public func describe() -> String {
    let useproject = project ?? ""
    return useproject.isEmpty ? "doppler" : "doppler:\(useproject)/\(config ?? "")"
  }
}

// ------------------------------------------------------------- infisical

/// Infisical.
///
/// `api.token` reads the secret keyed `API_TOKEN` (Infisical's own
/// convention is environment-style keys) at a secret path in one
/// environment of a project. Auth is a token, or a universal-auth (machine
/// identity) login with clientid/clientsecret.
public final class InfisicalProvider: Provider {

  private let addr: String?
  private let token: String?
  private let clientid: String?
  private let clientsecret: String?
  private let project: String?
  private let environment: String?
  private let path: String?

  private var livetoken: String?
  private var renewat: Double = Double.greatestFiniteMagnitude

  public init(
    addr: String? = nil,
    token: String? = nil,
    clientid: String? = nil,
    clientsecret: String? = nil,
    project: String? = nil,
    environment: String? = nil,
    path: String? = nil
  ) {
    self.addr = addr
    self.token = token
    self.clientid = clientid
    self.clientsecret = clientsecret
    self.project = project
    self.environment = environment
    self.path = path
  }

  private func login(_ useaddr: String) throws -> String {
    if let use = token, !use.isEmpty { return use }

    let useclientid = clientid ?? ""
    let useclientsecret = clientsecret ?? ""

    if useclientid.isEmpty || useclientsecret.isEmpty {
      throw SekretoError("sekreto: infisical: no token and no client credentials")
    }

    let payload = Json.obj([
      ("clientId", .str(useclientid)),
      ("clientSecret", .str(useclientsecret)),
    ])

    var headers = Ordered<String>()
    headers["content-type"] = "application/json"

    let res = try fetchjson(
      "POST", "\(useaddr)/api/v1/auth/universal-auth/login", headers, Json.stringify(payload))

    let got = res.body.dig("accessToken").text

    if 200 != res.status || (got?.isEmpty ?? true) {
      throw SekretoError("sekreto: infisical login failed: \(res.status)")
    }

    // camelCase, unlike everyone else's expires_in.
    renewat = renewtime(res.body.dig("expiresIn"))

    return got!
  }

  public func lookup(_ name: String) throws -> String? {
    let useaddr = trimslash(first(addr, "https://app.infisical.com"))
    try checkaddr(useaddr)

    let useproject = project ?? ""
    let useenvironment = environment ?? ""

    if useproject.isEmpty || useenvironment.isEmpty {
      throw SekretoError("sekreto: infisical: no project/environment")
    }

    if nil == livetoken || nowms() >= renewat {
      livetoken = try login(useaddr)
    }

    let url =
      "\(useaddr)/api/v3/secrets/raw/" + (try envkey(name))
      + "?workspaceId=" + uriescape(useproject)
      + "&environment=" + uriescape(useenvironment)
      + "&secretPath=" + uriescape(first(path, "/"))

    var headers = Ordered<String>()
    headers["authorization"] = "Bearer \(livetoken ?? "")"

    let res = try fetchjson("GET", url, headers)

    if 404 == res.status { return nil }

    if 200 != res.status {
      throw SekretoError("sekreto: infisical error: \(res.status)")
    }

    return res.body.dig("secret", "secretValue").text
  }

  public func describe() -> String {
    return "infisical:\(project ?? "")/\(environment ?? "")"
  }
}

// ------------------------------------------------------------ the switch

/// Build a provider from its declarative form - the same shape the shared
/// spec and an app's config file use.
public func makeprovider(_ spec: ProviderSpec) throws -> Provider {
  switch spec.kind {
  case "env":
    return EnvProvider(prefix: spec.prefix)

  case "dotenv":
    return DotenvProvider(file: first(spec.file, ".env"), prefix: spec.prefix)

  case "memory":
    return MemoryProvider(values: spec.values, prefix: spec.prefix)

  case "file":
    return FileProvider(dir: spec.dir ?? "", prefix: spec.prefix)

  case "hashicorp":
    return try HashicorpProvider(
      addr: spec.addr ?? "",
      token: spec.token,
      mount: spec.mount,
      kv: spec.kv,
      vaultnamespace: spec.vaultnamespace,
      auth: spec.auth
    )

  case "boru":
    return BoruProvider(
      command: spec.command,
      namespace: spec.namespace,
      home: spec.home,
      addr: spec.addr,
      token: spec.token,
      mount: spec.mount
    )

  case "awssecrets":
    return AwssecretsProvider(
      region: spec.region, keyid: spec.keyid, secret: spec.secret,
      session: spec.session, addr: spec.addr)

  case "awsparams":
    return AwsparamsProvider(
      region: spec.region, keyid: spec.keyid, secret: spec.secret,
      session: spec.session, addr: spec.addr, prefix: spec.prefix)

  case "gcpsecrets":
    return GcpsecretsProvider(
      project: spec.project, token: spec.token, addr: spec.addr,
      metadataaddr: spec.metadataaddr)

  case "azuresecrets":
    return AzuresecretsProvider(
      vault: spec.vault,
      token: spec.token,
      tenant: spec.tenant,
      clientid: spec.clientid,
      clientsecret: spec.clientsecret,
      loginaddr: spec.loginaddr,
      imdsaddr: spec.imdsaddr,
      apiversion: spec.apiversion
    )

  case "onepassword":
    return OnepasswordProvider(addr: spec.addr, token: spec.token, vault: spec.vault)

  case "doppler":
    return DopplerProvider(
      token: spec.token, project: spec.project, config: spec.config, addr: spec.addr)

  case "infisical":
    return InfisicalProvider(
      addr: spec.addr,
      token: spec.token,
      clientid: spec.clientid,
      clientsecret: spec.clientsecret,
      project: spec.project,
      environment: spec.environment,
      path: spec.path
    )

  case "secretspec":
    return SecretspecProvider(
      command: spec.command,
      file: spec.file,
      profile: spec.profile,
      backend: spec.backend,
      reason: spec.reason,
      prefix: spec.prefix
    )

  default:
    throw SekretoError("sekreto: unknown provider kind: \(spec.kind)")
  }
}
