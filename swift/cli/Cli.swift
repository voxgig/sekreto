// A tiny app that needs a secret.
//
// It asks sekreto for `api.token` and calls the token-protected API with
// it. Every port ships this same CLI, and test/integration.sh runs all of
// them against the same server from every secret source - which is what
// proves the library, rather than the spec alone.
//
// Usage: sekreto-cli <api-url> [--source <source>] [--store <name>]
//
// Sources: env dotenv file hashicorp boru boruwire awssecrets awsparams
//          gcpsecrets azuresecrets onepassword doppler infisical
//          secretspec chain
//
// Each source's configuration arrives in the environment variables its own
// ecosystem already uses (VAULT_*, AWS_*, OP_CONNECT_*, ...), listed in
// chainfor below.

import Dispatch
import Foundation
import Sekreto

#if canImport(FoundationNetworking)
  import FoundationNetworking
#endif

let LANG = "swift"

func envvar(_ name: String) -> String? {
  let value = ProcessInfo.processInfo.environment[name]
  // An empty value is treated as absent: every port does, so a variable
  // exported blank is the same as a variable never set.
  return (value?.isEmpty ?? true) ? nil : value
}

func envor(_ name: String, _ fallback: String) -> String {
  return envvar(name) ?? fallback
}

func chainfor(_ source: String) -> [ProviderSpec] {
  let envspec = ProviderSpec(kind: "env", prefix: envvar("SEKRETO_PREFIX"))

  let dotenvspec = ProviderSpec(kind: "dotenv", file: envor("SEKRETO_DOTENV", ".env"))

  let filespec = ProviderSpec(kind: "file", dir: envor("SEKRETO_FILEDIR", "/run/secrets"))

  var auth: AuthSpec? = nil
  if let method = envvar("VAULT_AUTH") {
    auth = AuthSpec(
      method: method,
      role: envvar("VAULT_ROLE"),
      jwtfile: envvar("VAULT_JWT_FILE"),
      roleid: envvar("VAULT_ROLE_ID"),
      secretid: envvar("VAULT_SECRET_ID")
    )
  }

  let hashicorpspec = ProviderSpec(
    kind: "hashicorp",
    addr: envor("VAULT_ADDR", ""),
    token: envor("VAULT_TOKEN", ""),
    mount: envvar("VAULT_MOUNT"),
    kv: envvar("VAULT_KV").flatMap { Int($0) },
    vaultnamespace: envvar("VAULT_NAMESPACE"),
    auth: auth
  )

  let boruspec = ProviderSpec(
    kind: "boru",
    command: envor("BORU_COMMAND", "boru"),
    namespace: envvar("BORU_NAMESPACE"),
    home: envvar("BORU_HOME")
  )

  // The same vault over its wire protocol (`boru vault serve`) instead of
  // the CLI: an address plus a capability token from `vault grant`.
  let boruwirespec = ProviderSpec(
    kind: "boru",
    addr: envor("BORU_ADDR", ""),
    token: envor("BORU_TOKEN", ""),
    namespace: envvar("BORU_NAMESPACE")
  )

  let awssecretsspec = ProviderSpec(
    kind: "awssecrets",
    addr: envvar("AWS_ENDPOINT"),
    region: envvar("AWS_REGION")
  )

  let awsparamsspec = ProviderSpec(
    kind: "awsparams",
    prefix: envvar("AWS_PARAM_PREFIX"),
    addr: envvar("AWS_ENDPOINT"),
    region: envvar("AWS_REGION")
  )

  let gcpspec = ProviderSpec(
    kind: "gcpsecrets",
    addr: envvar("GCP_ADDR"),
    project: envvar("GCP_PROJECT"),
    metadataaddr: envvar("GCP_METADATA_ADDR")
  )

  let azurespec = ProviderSpec(
    kind: "azuresecrets",
    token: envvar("AZURE_TOKEN"),
    vault: envvar("AZURE_VAULT"),
    tenant: envvar("AZURE_TENANT"),
    clientid: envvar("AZURE_CLIENT_ID"),
    clientsecret: envvar("AZURE_CLIENT_SECRET"),
    loginaddr: envvar("AZURE_LOGIN_ADDR"),
    imdsaddr: envvar("AZURE_IMDS_ADDR")
  )

  let onepasswordspec = ProviderSpec(
    kind: "onepassword",
    addr: envvar("OP_CONNECT_HOST"),
    token: envvar("OP_CONNECT_TOKEN"),
    vault: envvar("OP_VAULT")
  )

  let dopplerspec = ProviderSpec(
    kind: "doppler",
    addr: envvar("DOPPLER_ADDR"),
    token: envvar("DOPPLER_TOKEN"),
    project: envvar("DOPPLER_PROJECT"),
    config: envvar("DOPPLER_CONFIG")
  )

  // SecretSpec's own environment variables where it has them
  // (SECRETSPEC_FILE, _PROFILE, _PROVIDER, _REASON are read by the
  // secretspec CLI itself), so a shell already set up for secretspec needs
  // nothing further.
  let secretspecspec = ProviderSpec(
    kind: "secretspec",
    file: envvar("SECRETSPEC_FILE"),
    command: envor("SECRETSPEC_COMMAND", "secretspec"),
    profile: envvar("SECRETSPEC_PROFILE"),
    backend: envvar("SECRETSPEC_PROVIDER"),
    reason: envvar("SECRETSPEC_REASON")
  )

  let infisicalspec = ProviderSpec(
    kind: "infisical",
    addr: envvar("INFISICAL_ADDR"),
    token: envvar("INFISICAL_TOKEN"),
    project: envvar("INFISICAL_PROJECT"),
    clientid: envvar("INFISICAL_CLIENT_ID"),
    clientsecret: envvar("INFISICAL_CLIENT_SECRET"),
    environment: envvar("INFISICAL_ENV"),
    path: envvar("INFISICAL_PATH")
  )

  switch source {
  case "env": return [envspec]
  case "dotenv": return [dotenvspec]
  case "file": return [filespec]
  case "hashicorp": return [hashicorpspec]
  case "boru": return [boruspec]
  case "boruwire": return [boruwirespec]
  case "awssecrets": return [awssecretsspec]
  case "awsparams": return [awsparamsspec]
  case "gcpsecrets": return [gcpspec]
  case "azuresecrets": return [azurespec]
  case "onepassword": return [onepasswordspec]
  case "doppler": return [dopplerspec]
  case "infisical": return [infisicalspec]
  case "secretspec": return [secretspecspec]
  // The default: the chain an app would actually ship with - local
  // overrides first, shared vaults last.
  default: return [envspec, dotenvspec, hashicorpspec, boruspec]
  }
}

/// The value of a `--flag value` pair, or "" when the flag is absent.
func flag(_ args: [String], _ name: String) -> String {
  guard let at = args.firstIndex(of: name), at + 1 < args.count else { return "" }
  return args[at + 1]
}

/// What the API said: its status and its body.
func callapi(_ url: String, _ token: String) throws -> (Int, String) {
  guard let target = URL(string: url) else {
    throw SekretoError("not a usable address: \(url)")
  }

  var request = URLRequest(url: target)
  request.httpMethod = "GET"
  request.timeoutInterval = 10
  request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
  request.setValue(LANG, forHTTPHeaderField: "X-Sekreto-Lang")

  let config = URLSessionConfiguration.default
  config.timeoutIntervalForRequest = 10
  config.connectionProxyDictionary = [:]

  let session = URLSession(configuration: config)
  let waiting = DispatchSemaphore(value: 0)

  var status = 0
  var body = ""
  var failure: Error?

  session.dataTask(with: request) { data, response, err in
    failure = err
    if let http = response as? HTTPURLResponse { status = http.statusCode }
    if let data = data { body = String(decoding: data, as: UTF8.self) }
    waiting.signal()
  }.resume()

  waiting.wait()
  session.finishTasksAndInvalidate()

  if let failure = failure {
    throw SekretoError("\(failure)")
  }

  return (status, body)
}

func run(_ args: [String]) -> Int32 {
  let url = args.isEmpty ? "http://127.0.0.1:8099/whoami" : args[0]

  let named = flag(args, "--source")
  let source = named.isEmpty ? "chain" : named

  // --store names a store outright: the secret must come from that one,
  // not from whichever provider happens to answer first.
  let store = flag(args, "--store")

  let secrets: Sekreto

  do {
    secrets = try makesekreto(chainfor(source))
  } catch {
    // Nothing has been resolved yet, so there is nothing to redact.
    FileHandle.standardError.write(Data("sekreto-cli: \(error)\n".utf8))
    return 2
  }

  let token: String

  do {
    token = store.isEmpty ? try secrets.get("api.token") : try secrets.getfrom(store, "api.token")
  } catch {
    // Routed through redact like every other failure path: a chain that
    // answered from one store and then failed in another must not put the
    // value it did resolve into a diagnostic.
    FileHandle.standardError.write(
      Data("sekreto-cli: \(secrets.redact("\(error)"))\n".utf8))
    return 2
  }

  var status = 0
  var body = ""

  do {
    (status, body) = try callapi(url, token)
  } catch {
    // Never print the token itself, even when the call fails.
    FileHandle.standardError.write(
      Data("sekreto-cli: \(secrets.redact("\(error)"))\n".utf8))
    return 1
  }

  if 200 != status {
    FileHandle.standardError.write(Data("sekreto-cli: \(secrets.redact(body))\n".utf8))
    return 1
  }

  let caller = Json.parse(body).dig("caller")

  // Assembled field by field, in the spec's order. Printing a map here is
  // what has bitten port after port: the language's own key order is not
  // the one every other port prints.
  var line = "{\"ok\":true"
  line += ",\"lang\":" + Json.quote(LANG)
  line += ",\"source\":" + Json.quote(source)
  line += ",\"store\":" + Json.quote(store)
  line += ",\"caller\":" + (nil == caller ? "null" : Json.stringify(caller!))
  line += "}"

  print(line)

  return 0
}

exit(run(Array(CommandLine.arguments.dropFirst())))
