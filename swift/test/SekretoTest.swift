// RUN: make test
// RUN-SOME: ./build/sekreto-test envkey
//
// The sekreto conformance suite. Every port runs these same groups, from
// the same spec/sekreto.json, through its own voxgig/omni runner.
//
// No third-party test framework: a failing omni check throws OmniError, so
// any host framework (XCTest, swift-testing) reports it as a failure. This
// harness keeps `make test` dependency-free.
//
// Two value models meet here. omni has an `enum Json` with an `absent`
// case; the library takes plain Swift values and typed specs. The bridge
// below converts between them explicitly, so nothing about absent, null
// and value is guessed. `Json` is spelled `J` throughout, because both
// modules export a type of that name and the ambiguity is better resolved
// once than at every use.

import Foundation
import Omni
import Sekreto

typealias J = Omni.Json

var ONLY: String? = nil
var passcount = 0
var failcount = 0

/// Find the shared spec directory by walking up from the working dir.
func specfile(_ name: String) throws -> String {
  var dir = FileManager.default.currentDirectoryPath

  for _ in 0..<8 {
    let cand = dir + "/spec/" + name
    if FileManager.default.fileExists(atPath: cand) { return cand }

    let parent = (dir as NSString).deletingLastPathComponent
    if parent == dir || parent.isEmpty { break }
    dir = parent
  }

  throw OmniError("sekreto: spec not found: " + name)
}

// ------------------------------------------------------------ the bridge

/// omni's model -> a plain Swift value. Absent and null both read as nil,
/// which is what the library's `Any?` entry points expect.
func plain(_ value: J) -> Any? {
  switch value {
  case .absent: return nil
  case .null: return nil
  case .bool(let entry): return entry
  case .num(let entry): return entry
  case .str(let entry): return entry
  case .list(let entries): return entries.map(plain)
  case .map(let entries): return entries.map { ($0.0, plain($0.1)) }
  case .provider: return nil
  }
}

/// A list of strings, as omni compares them.
func textlist(_ values: [String]) -> J {
  return .list(values.map { J.str($0) })
}

/// An ordered string map, as omni compares it.
func textmap(_ values: Ordered<String>) -> J {
  return J.mapOf(values.pairs.map { ($0.0, J.str($0.1)) })
}

/// One provider spec, out of the spec's declarative chain description.
func specof(_ entry: J) -> ProviderSpec {
  var values: Ordered<String>? = nil

  if let source = entry.get("values").asmap {
    var out = Ordered<String>()
    for (key, value) in source {
      out[key] = Omni.stringify(value)
    }
    values = out
  }

  var auth: AuthSpec? = nil

  if entry.get("auth").ismap {
    let useauth = entry.get("auth")
    auth = AuthSpec(
      method: useauth.get("method").asstr ?? "",
      mount: useauth.get("mount").asstr,
      role: useauth.get("role").asstr,
      jwt: useauth.get("jwt").asstr,
      jwtfile: useauth.get("jwtfile").asstr,
      roleid: useauth.get("roleid").asstr,
      secretid: useauth.get("secretid").asstr
    )
  }

  return ProviderSpec(
    kind: entry.get("kind").asstr ?? "",
    name: entry.get("name").asstr,
    prefix: entry.get("prefix").asstr,
    file: entry.get("file").asstr,
    values: values,
    dir: entry.get("dir").asstr,
    addr: entry.get("addr").asstr,
    token: entry.get("token").asstr,
    mount: entry.get("mount").asstr,
    kv: entry.get("kv").asnum.map { Int($0) },
    vaultnamespace: entry.get("vaultnamespace").asstr,
    auth: auth,
    command: entry.get("command").asstr,
    profile: entry.get("profile").asstr,
    backend: entry.get("backend").asstr,
    reason: entry.get("reason").asstr,
    namespace: entry.get("namespace").asstr,
    home: entry.get("home").asstr,
    region: entry.get("region").asstr,
    keyid: entry.get("keyid").asstr,
    secret: entry.get("secret").asstr,
    session: entry.get("session").asstr,
    project: entry.get("project").asstr,
    vault: entry.get("vault").asstr,
    tenant: entry.get("tenant").asstr,
    clientid: entry.get("clientid").asstr,
    clientsecret: entry.get("clientsecret").asstr,
    loginaddr: entry.get("loginaddr").asstr,
    imdsaddr: entry.get("imdsaddr").asstr,
    metadataaddr: entry.get("metadataaddr").asstr,
    apiversion: entry.get("apiversion").asstr,
    config: entry.get("config").asstr,
    environment: entry.get("environment").asstr,
    path: entry.get("path").asstr
  )
}

/// Build a Sekreto from the spec's declarative chain description.
///
/// Built INSIDE the subject, never beside it: four entries expect
/// `unsupported kv version`, which the constructor raises, and only a
/// construction failure inside the subject reaches omni as a subject
/// error.
func chainof(_ entry: J) throws -> Sekreto {
  let chain = (entry.get("chain").aslist ?? []).map(specof)
  return try makesekreto(chain, cache: false)
}

/// The name a group's entry asks about.
func namearg(_ entry: J) -> String {
  return entry.get("name").asstr ?? ""
}

// --------------------------------------------------------- the subjects

// `validname` answers whatever the language calls true; the spec says JSON
// true, so the adaptation happens here rather than in the library.
let VALIDNAME: Subject = { args in .bool(validname(plain(args[0]))) }

let ENVKEY: Subject = { args in
  .str(try envkey(plain(args[0].get("name")), args[0].get("prefix").asstr))
}

let VAULTREF: Subject = { args in
  let ref = try vaultref(plain(args[0]))
  return J.mapOf([("path", .str(ref.path)), ("field", .str(ref.field))])
}

let FLATNAME: Subject = { args in
  .str(try flatname(plain(args[0].get("name")), args[0].get("sep").asstr ?? ""))
}

let AWSPARAM: Subject = { args in
  .str(try awsparam(plain(args[0].get("name")), args[0].get("prefix").asstr))
}

let PARSEDOTENV: Subject = { args in textmap(parsedotenv(plain(args[0]))) }

let RESOLVE: Subject = { args in .str(try chainof(args[0]).get(namearg(args[0]))) }

let TRYSECRET: Subject = { args in
  guard let found = try chainof(args[0]).tryget(namearg(args[0])) else { return .null }
  return .str(found)
}

let SOURCES: Subject = { args in textlist(try chainof(args[0]).sources()) }

let STORES: Subject = { args in textlist(try chainof(args[0]).stores()) }

let GETFROM: Subject = { args in
  .str(try chainof(args[0]).getfrom(args[0].get("store").asstr ?? "", namearg(args[0])))
}

let TRYFROM: Subject = { args in
  let found = try chainof(args[0]).tryfrom(args[0].get("store").asstr ?? "", namearg(args[0]))
  guard let value = found else { return .null }
  return .str(value)
}

// Answers the ordered output map itself, which omni compares as a JSON
// object against the spec's known-answer signatures.
let SIGV4: Subject = { args in
  let entry = args[0]

  var headers = Ordered<String>()
  if let source = entry.get("headers").asmap {
    for (key, value) in source {
      headers[key] = Omni.stringify(value)
    }
  }

  let signed = sigv4(
    Signing(
      method: entry.get("method").asstr ?? "",
      url: entry.get("url").asstr ?? "",
      service: entry.get("service").asstr ?? "",
      region: entry.get("region").asstr ?? "",
      keyid: entry.get("keyid").asstr ?? "",
      secret: entry.get("secret").asstr ?? "",
      datetime: entry.get("datetime").asstr ?? "",
      headers: headers,
      body: entry.get("body").asstr ?? "",
      session: entry.get("session").asstr
    ))

  return textmap(signed)
}

let REDACT: Subject = { args in
  let values = args[0].get("values").aslist.map { $0.map(plain) }
  return .str(redact(plain(args[0].get("text")), values))
}

// ---------------------------------------------------------- the runner

func testcase(_ name: String, _ body: () throws -> Void) {
  if let only = ONLY, name != only { return }

  do {
    try body()
    passcount += 1
    print("ok   - \(name)")
  } catch {
    failcount += 1
    print("FAIL - \(name)")
    print(errmessage(error))
  }
}

func main() -> Int32 {
  let args = Array(CommandLine.arguments.dropFirst())
  if !args.isEmpty { ONLY = args[0] }

  let R: RunPack

  do {
    R = try makeRunner(try specfile("sekreto.json"), Omni.Provider()).runner("sekreto")
  } catch {
    print("FAIL - runner")
    print(errmessage(error))
    return 1
  }

  testcase("validname") { try R.runsetflags(R.set("validname"), Flags.nonull(), VALIDNAME) }
  testcase("envkey") { try R.runset(R.set("envkey"), ENVKEY) }
  testcase("vaultref") { try R.runset(R.set("vaultref"), VAULTREF) }
  testcase("flatname") { try R.runset(R.set("flatname"), FLATNAME) }
  testcase("awsparam") { try R.runset(R.set("awsparam"), AWSPARAM) }
  testcase("parsedotenv") { try R.runset(R.set("parsedotenv"), PARSEDOTENV) }
  testcase("resolve") { try R.runset(R.set("resolve"), RESOLVE) }
  testcase("trysecret") { try R.runset(R.set("trysecret"), TRYSECRET) }
  testcase("sources") { try R.runset(R.set("sources"), SOURCES) }
  testcase("stores") { try R.runset(R.set("stores"), STORES) }
  testcase("getfrom") { try R.runset(R.set("getfrom"), GETFROM) }
  testcase("tryfrom") { try R.runset(R.set("tryfrom"), TRYFROM) }
  testcase("sigv4") { try R.runset(R.set("sigv4"), SIGV4) }
  testcase("redact") { try R.runset(R.set("redact"), REDACT) }

  print("\n\(passcount) passed, \(failcount) failed")

  return 0 == failcount ? 0 : 1
}

exit(main())
