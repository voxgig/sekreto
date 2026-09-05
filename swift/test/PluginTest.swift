// RUN: make test
// RUN-SOME: ./build/sekreto-plugintest fullset
//
// THE PLUGIN SEAM, from both sides.
//
// Moving the provider kinds that open sockets and spawn processes out of
// the core made a consumer's PLUGIN LIST load-bearing: a kind nobody
// passed in is not in the catalog, and a chain naming it is refused. That
// is the intended behaviour, and it means a consumer can be broken without
// a single conformance test noticing - the conformance suite hands every
// plugin to every chain it builds, so it can never see a missing one.
//
// This file is compiled as its own binary rather than folded into
// SekretoTest.swift, because it needs no omni: a checkout with no omni
// beside it can still run the seam.
//
// No third-party test framework, for the same reason the conformance suite
// has none: `make test` stays dependency-free.

import Foundation
import Sekreto
import SekretoPlugins
import VoxgigPlugin

let PLUGINKINDS = [
  "awsparams", "awssecrets", "azuresecrets", "boru", "doppler", "gcpsecrets",
  "hashicorp", "infisical", "onepassword", "secretspec",
]

let BUILTINKINDS = ["dotenv", "env", "file", "memory"]

let EVERYKIND = (BUILTINKINDS + PLUGINKINDS).sorted()

// The port directory, found from this binary rather than from the working
// directory, so `./build/sekreto-plugintest` works from anywhere.
let HERE: String = {
  var dir = URL(fileURLWithPath: CommandLine.arguments[0])
    .deletingLastPathComponent().path

  if !dir.hasPrefix("/") {
    dir = FileManager.default.currentDirectoryPath + "/" + dir
  }

  for _ in 0..<8 {
    if FileManager.default.fileExists(atPath: dir + "/plugins/All.swift") { return dir }
    let parent = (dir as NSString).deletingLastPathComponent
    if parent == dir || parent.isEmpty { break }
    dir = parent
  }

  return FileManager.default.currentDirectoryPath
}()

// --------------------------------------------------------- the harness

var ONLY: String? = nil
var passcount = 0
var failcount = 0

struct Failed: Error, CustomStringConvertible {
  let description: String
}

func fail(_ text: String) -> Failed { return Failed(description: text) }

func same<T: Equatable>(_ got: T, _ want: T, _ what: String) throws {
  if got != want { throw fail("\(what): got \(got), want \(want)") }
}

func truth(_ got: Bool, _ what: String) throws {
  if !got { throw fail(what) }
}

/// What an error says, however it says it. A SekretoError is its message;
/// a PluginError is the host's formatted line.
func said(_ err: Error) -> String {
  if let err = err as? SekretoError { return err.message }
  if let err = err as? PluginError { return err.message }
  return String(describing: err)
}

/// The SekretoError this threw, or a failure naming what it threw instead.
func refusal(_ what: String, _ body: () throws -> Void) throws -> String {
  do {
    try body()
  } catch let err as SekretoError {
    return err.message
  } catch {
    throw fail("\(what): not a SekretoError: \(type(of: error)): \(said(error))")
  }

  throw fail("\(what): nothing was refused")
}

func testcase(_ name: String, _ body: () throws -> Void) {
  if let only = ONLY, name != only { return }

  do {
    try body()
    passcount += 1
    print("ok   - \(name)")
  } catch {
    failcount += 1
    print("FAIL - \(name)")
    print("       \(said(error))")
  }
}

/// A file of this port, read whole.
func source(_ path: String) throws -> String {
  guard let data = FileManager.default.contents(atPath: HERE + "/" + path) else {
    throw fail("cannot read \(path)")
  }
  return String(decoding: data, as: UTF8.self)
}

/// Run a command, and say whether it succeeded and what it printed.
@discardableResult
func run(_ argv: [String]) throws -> (Bool, String) {
  let process = Process()
  process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
  process.arguments = argv
  process.currentDirectoryURL = URL(fileURLWithPath: HERE)

  let pipe = Pipe()
  process.standardOutput = pipe
  process.standardError = pipe

  try process.run()
  let out = pipe.fileHandleForReading.readDataToEndOfFile()
  process.waitUntilExit()

  return (0 == process.terminationStatus, String(decoding: out, as: UTF8.self))
}

// ------------------------------------------- what the full set holds

func thefullsetholdseverykind() throws {
  try same(allplugins.map { $0.name }.sorted(), PLUGINKINDS, "allplugins")
  try same(KINDS.plugin.sorted(), PLUGINKINDS, "KINDS.plugin")
  try same(KINDS.builtin.sorted(), BUILTINKINDS, "KINDS.builtin")
  try same(BUILTINS.map { $0.name }, KINDS.builtin, "BUILTINS")

  // The individually exported names ARE the members of the full set: a
  // consumer that imports one gets the same definition the CLI does.
  let one = [
    hashicorp, boru, awssecrets, awsparams, gcpsecrets, azuresecrets,
    onepassword, doppler, infisical, secretspec,
  ]
  try same(one.map { $0.name }, allplugins.map { $0.name }, "the named ten")
}

// Naming a kind is not enough: a kind can be in the catalog and still fail
// to build. Construction is what the CLI does before any network.
func everykindbuildsfromaspec() throws {
  let chain = EVERYKIND.map {
    ProviderSpec(
      kind: $0, file: "/tmp/.env", values: Ordered<String>(), dir: "/tmp",
      addr: "http://127.0.0.1:8200", token: "t")
  }

  let secrets = try makesekreto(chain, plugins: allplugins)

  try same(secrets.stores(), EVERYKIND, "stores")
  try same(secrets.host.list().keys, EVERYKIND, "host refs")

  for ref in secrets.host.list().keys {
    try same(secrets.host.list().at(ref).asString ?? "", "live", ref)
  }

  try secrets.close()
}

func theclipassesthefullset() throws {
  let text = try source("cli/Cli.swift")
  try truth(text.contains("import SekretoPlugins"), "the CLI does not import the plugins")
  try truth(text.contains("plugins: allplugins"), "the CLI does not pass the full set")
}

// ------------------------------------------------ what a consumer sees

// A chain of built-ins works with NO plugin loaded at all. That is the
// whole point of the four: an app that reads its secrets from options, the
// environment, a `.env` and a mounted directory links no vault client.
func builtinsneednoplugin() throws {
  var values = Ordered<String>()
  values["API_TOKEN"] = "tok01"

  let secrets = try makesekreto([
    ProviderSpec(kind: "memory", values: values),
    ProviderSpec(kind: "env"),
    ProviderSpec(kind: "dotenv", file: "/nonexistent-sekreto-test/.env"),
    ProviderSpec(kind: "file", dir: "/nonexistent-sekreto-test"),
  ])

  try same(try secrets.get("api.token"), "tok01", "get")
  try same(secrets.stores(), ["memory", "env", "dotenv", "file"], "stores")
  try same(secrets.catalog.names(), BUILTINKINDS, "catalog")

  for ref in secrets.host.list().keys {
    try same(secrets.host.list().at(ref).asString ?? "", "live", ref)
  }

  try secrets.close()
}

func onepluginisenoughforachainthatnamesonlyit() throws {
  var values = Ordered<String>()
  values["API_TOKEN"] = "tok01"

  let secrets = try makesekreto(
    [
      ProviderSpec(kind: "memory", values: values),
      ProviderSpec(
        kind: "hashicorp", name: "prod", addr: "https://vault.example.com", token: "t"),
    ], plugins: [hashicorp])

  try same(secrets.stores(), ["memory", "prod"], "stores")
  try same(
    secrets.sources(), ["memory", "hashicorp:https://vault.example.com/secret"], "sources")
  try same(try secrets.get("api.token"), "tok01", "get")

  // The plugin host is what the chain is made of, and it reads like the
  // chain: the kind, or kind$store for a named store.
  try same(secrets.host.list().keys, ["hashicorp$prod", "memory"], "host refs")
  try same(
    secrets.catalog.names(), ["dotenv", "env", "file", "hashicorp", "memory"], "catalog")

  try secrets.close()
}

func akindthatwasnotpassedinisrefusednamingthefix() throws {
  try same(
    try refusal("doppler") {
      _ = try makesekreto(
        [ProviderSpec(kind: "doppler", token: "t")], plugins: [hashicorp])
    },
    "sekreto: unknown provider kind: doppler"
      + " (available: dotenv, env, file, hashicorp, memory)"
      + " - doppler is a sekreto plugin, not built in: pass it in the plugins option",
    "the fix")

  // A kind nobody ships is a typo, and gets no such hint.
  try same(
    try refusal("vualt") { _ = try makesekreto([ProviderSpec(kind: "vualt")]) },
    "sekreto: unknown provider kind: vualt (available: dotenv, env, file, memory)",
    "a typo")
}

// Two providers MAY share a store name - a directed read walks both, and
// the spec pins it - but an instance ref may not, so the second gets a
// numbered tag from the host and keeps its store name.
func arepeatedstorenamekeepsthestoreandnumberstheinstance() throws {
  var second = Ordered<String>()
  second["API_TOKEN"] = "second"
  var pair2 = Ordered<String>()
  pair2["API_TOKEN"] = "pair2"

  let secrets = try makesekreto([
    ProviderSpec(kind: "memory", values: Ordered<String>()),
    ProviderSpec(kind: "memory", values: second),
    ProviderSpec(kind: "memory", name: "pair", values: Ordered<String>()),
    ProviderSpec(kind: "memory", name: "pair", values: pair2),
  ])

  try same(secrets.stores(), ["memory", "pair"], "stores")
  try same(
    secrets.host.list().keys, ["memory", "memory$1", "memory$2", "memory$pair"], "host refs")
  try same(try secrets.getfrom("memory", "api.token"), "second", "memory")
  try same(try secrets.getfrom("pair", "api.token"), "pair2", "pair")

  try secrets.close()
}

func astorenamemustbeavalidtag() throws {
  try same(
    try refusal("my store") {
      _ = try makesekreto([ProviderSpec(kind: "memory", name: "my store")])
    },
    "sekreto: invalid store name: my store", "an invalid tag")
}

// A provider that refuses its own configuration throws a SekretoError from
// inside the plugin's `define`. The spec pins that message byte for byte,
// so it must come back out of the host as itself - not wrapped as
// plugin_define_failed, and not as a PluginError.
func asekretoerrorthrownindefinecomesbackoutasitself() throws {
  try same(
    try refusal("kv: 3") {
      _ = try makesekreto(
        [ProviderSpec(kind: "hashicorp", addr: "http://127.0.0.1:1", token: "t", kv: 3)],
        plugins: [hashicorp])
    },
    "sekreto: hashicorp: unsupported kv version: 3", "the refusal")
}

// ...and any other error is not sekreto's to rewrite: it surfaces as the
// host reports it, naming the instance and the cause.
//
// `providerplugin` cannot produce one - it catches SekretoError and
// nothing else - so the case is reachable only for a definition written by
// hand, which is exactly the definition sekreto did not write.
func anyothererrorthrownindefineisthehostsreportofit() throws {
  struct Boom: Error, CustomStringConvertible {
    var description: String { return "boom" }
  }

  let broken = Definition(name: "broken", define: { _ in throw Boom() })

  do {
    _ = try makesekreto([ProviderSpec(kind: "broken")], plugins: [broken])
  } catch let err as PluginError {
    try same(err.code, "plugin_define_failed", "code")
    try truth(err.message.contains("boom"), "the cause is not in \(err.message)")
    return
  }

  throw fail("nothing was reported")
}

// A custom kind is one providerplugin call.
final class Shouty: Provider {
  let values: Ordered<String>
  init(_ values: Ordered<String>) { self.values = values }
  func lookup(_ name: String) throws -> String? { return values[asciiupper(name)] }
  func describe() -> String { return "shouty" }
}

func acustomkindisoneproviderplugincall() throws {
  let shouty = providerplugin("shouty") { spec in
    guard let values = spec.values else {
      throw SekretoError("sekreto: shouty: no values")
    }
    return Shouty(values)
  }

  var values = Ordered<String>()
  values["API.TOKEN"] = "loud"

  let secrets = try makesekreto(
    [ProviderSpec(kind: "shouty", values: values)], plugins: [shouty])

  try same(try secrets.get("api.token"), "loud", "get")
  try same(secrets.host.list().keys, ["shouty"], "host refs")
  try secrets.close()

  // ...and its own refusal crosses the boundary as itself, exactly as a
  // shipped plugin's does.
  try same(
    try refusal("no values") {
      _ = try makesekreto([ProviderSpec(kind: "shouty")], plugins: [shouty])
    },
    "sekreto: shouty: no values", "the custom refusal")
}

// A plugin that names a built-in kind replaces it: that is how a host
// substitutes an implementation, and never an accident, because the four
// names are documented.
func apluginmayreplaceabuiltinkind() throws {
  final class Replaced: Provider {
    func lookup(_ name: String) throws -> String? { return "replaced" }
    func describe() -> String { return "memory" }
  }

  var values = Ordered<String>()
  values["API_TOKEN"] = "original"

  let secrets = try makesekreto(
    [ProviderSpec(kind: "memory", values: values)],
    plugins: [providerplugin("memory") { _ in Replaced() }])

  try same(try secrets.get("api.token"), "replaced", "get")
  try same(secrets.catalog.names(), BUILTINKINDS, "catalog")
  try secrets.close()
}

// A provider already built joins the chain as it is, under its own store
// name, backed by no instance.
func aliveproviderjoinsthechain() throws {
  var values = Ordered<String>()
  values["API.TOKEN"] = "loud"

  let secrets = Sekreto(
    providers: [Shouty(values), Shouty(Ordered<String>())], names: [nil, "quiet"])

  try same(secrets.stores(), ["shouty", "quiet"], "stores")
  try same(secrets.host.list().keys, [], "host refs")
  try same(secrets.catalog.names(), BUILTINKINDS, "catalog")
  try same(try secrets.get("api.token"), "loud", "get")
}

// A definition that is not a provider plugin at all - it loads, it
// activates, it exports nothing - is refused by name. Python's twin of this
// test passes a MODULE where a definition belongs; swift's type system
// refuses that outright, and what remains checkable is a definition that is
// not one of ours.
func adefinitionthatisnotaproviderpluginisrefused() throws {
  try same(
    try refusal("empty") {
      _ = try makesekreto(
        [ProviderSpec(kind: "hollow")], plugins: [Definition(name: "hollow")])
    },
    "sekreto: plugin hollow exported no provider", "the refusal")
}

func closetearsthechaindownandkeepsredaction() throws {
  var values = Ordered<String>()
  values["API_TOKEN"] = "tok01"

  let secrets = try makesekreto([ProviderSpec(kind: "memory", values: values)])
  try same(try secrets.get("api.token"), "tok01", "get")

  try secrets.close()

  try same(secrets.host.list().keys, [], "host refs")
  try same(secrets.stores(), [], "stores")
  try truth(nil == (try secrets.tryget("api.token")), "still resolving after close")
  try same(secrets.redact("token=tok01"), "token=[redacted]", "redaction")
}

// The full set is a VALUE, not a side effect. Naming it builds no
// provider, declares no instance and opens nothing: a Sekreto handed all
// ten kinds and no specs has an empty host and an empty chain.
func thefullsetisinert() throws {
  let secrets = try makesekreto([], plugins: allplugins)

  try same(secrets.host.list().keys, [], "host refs")
  try same(secrets.stores(), [], "stores")
  try same(secrets.catalog.names(), EVERYKIND, "catalog")
  try secrets.close()
}

// EVERY SPEC FIELD SURVIVES THE ROUND TRIP through the host's options.
//
// A ProviderSpec goes out as a plugin instance's options and comes back as
// a ProviderSpec, and only sixteen of its thirty-four fields appear in the
// shared spec at all. A field dropped on the way through would therefore
// be invisible to the conformance suite, and would surface as a vault that
// quietly ignored its `mount` or an AWS provider that lost its session
// token - at run time, against a real store.
let WHOLESPEC = [
  "addr", "apiversion", "auth", "backend", "clientid", "clientsecret",
  "command", "config", "dir", "environment", "file", "home", "imdsaddr",
  "keyid", "kind", "kv", "loginaddr", "metadataaddr", "mount", "name",
  "namespace", "path", "prefix", "profile", "project", "reason", "region",
  "secret", "session", "tenant", "token", "values", "vault",
  "vaultnamespace",
].sorted()

let WHOLEAUTH = ["jwt", "jwtfile", "method", "mount", "role", "roleid", "secretid"]

func everyspecfieldsurvivestheroundtrip() throws {
  var values = Ordered<String>()
  values["API_TOKEN"] = "v"

  let spec = ProviderSpec(
    kind: "hashicorp", name: "n", prefix: "P_", file: "f", values: values, dir: "d",
    addr: "a", token: "t", mount: "m", kv: 1, vaultnamespace: "vn",
    auth: AuthSpec(
      method: "approle", mount: "am", role: "r", jwt: "j", jwtfile: "jf",
      roleid: "ri", secretid: "si"),
    command: "c", profile: "pr", backend: "b", reason: "rs", namespace: "ns",
    home: "h", region: "rg", keyid: "ki", secret: "sc", session: "ss",
    project: "pj", vault: "vl", tenant: "tn", clientid: "ci", clientsecret: "cs",
    loginaddr: "la", imdsaddr: "ia", metadataaddr: "ma", apiversion: "av",
    config: "cf", environment: "ev", path: "p")

  let there = optionsof(spec)

  try same(there.json, optionsof(specof(there)).json, "the round trip")

  // ...and `optionsof` writes them all, so that a field BOTH halves forgot
  // cannot pass the comparison above by agreeing on its absence.
  try same(there.keys, WHOLESPEC, "the options map")
  try same(there.at("auth").keys, WHOLEAUTH.sorted(), "the auth map")

  // An absent field stays absent: an omitted key and an authored empty
  // string are not the same thing to a provider that defaults on
  // emptiness - `mount` defaults to `secret`, and "" must not become it.
  let bare = optionsof(ProviderSpec(kind: "memory"))
  try same(bare.keys, ["kind"], "a bare spec")
  try same(specof(bare).mount, nil, "an absent mount")
}

// ------------------------------------------- the core reaches no plugin

// THE MODULE BOUNDARY IS THE COMPILER'S, and the Makefile is where it is
// drawn: `Sekreto` is compiled from src/*.swift alone, so a core source
// naming `SekretoPlugins` names a module that does not exist when the core
// is built - and would be a cycle if it did.
func thecoreisbuiltfromsrcalone() throws {
  // Continuations folded first: a shell recipe's logical line is what
  // decides what gets compiled, and it spans three physical ones here.
  let makefile = try source("Makefile")
    .replacingOccurrences(of: "\\\n", with: " ")

  guard let at = makefile.range(of: "-module-name Sekreto ") else {
    throw fail("the Makefile does not build a Sekreto module")
  }

  let line = String(makefile[at.upperBound...].prefix(while: { "\n" != $0 }))

  try truth(line.contains("src/*.swift"), "the core's build line: \(line)")
  try truth(!line.contains("plugins/"), "the core's build line names plugins/: \(line)")

  // ...and the plugins are built from plugins/ - which is what makes the
  // line above a boundary rather than an omission.
  guard let pat = makefile.range(of: "-module-name SekretoPlugins ") else {
    throw fail("the Makefile does not build a SekretoPlugins module")
  }

  let pline = String(makefile[pat.upperBound...].prefix(while: { "\n" != $0 }))
  try truth(pline.contains("plugins/*.swift"), "the plugins' build line: \(pline)")
}

// ...and what the SOURCE says, because what the compiler cannot see is
// most of it: URLSession, Process and a hash function are all one `import
// Foundation` away in every core file.
//
// CODE, not prose: the comments in src/ point at the plugins on purpose -
// that is how a reader finds them - and a scan that could not tell an
// expression from a sentence would have to choose between being wrong and
// being useless.
func thecorenamesnopluginandreachesnoplatform() throws {
  let banned = [
    "URLSession", "FoundationNetworking", "Process(", "Pipe(", "sha256",
    "hmacsha256", "sigv4", "SekretoPlugins",
  ]

  var files = 0

  for name in try FileManager.default.contentsOfDirectory(atPath: HERE + "/src").sorted() {
    guard name.hasSuffix(".swift") else { continue }
    files += 1

    let code = try source("src/" + name)
      .components(separatedBy: "\n")
      .filter { !$0.trimmingCharacters(in: .whitespaces).hasPrefix("//") }
      .joined(separator: "\n")

    for word in banned where code.contains(word) {
      throw fail("src/\(name) names \(word) - it belongs in a plugin")
    }
  }

  try truth(3 < files, "read only \(files) core sources")
}

// ...and what the ARTIFACT says, which is the claim itself rather than a
// proxy for it. A static archive records every symbol it needs from
// outside; the core's list holds no URLSession, no Process and nothing
// from the plugins module.
func thecorearchivelinksnoplugin() throws {
  let (ok, out) = try run(["nm", "-u", "build/libSekreto.a"])
  try truth(ok, "nm: \(out)")

  for symbol in out.components(separatedBy: "\n") {
    for word in ["URLSession", "SekretoPlugins", "sha256", "hmacsha256", "10FoundationP7ProcessC"]
    where symbol.contains(word) {
      throw fail("the core archive needs \(word): \(symbol)")
    }
  }

  // ...and the same read of the plugins archive finds the socket, which is
  // what makes the first half a measurement rather than a tautology.
  let (okp, outp) = try run(["nm", "-u", "build/libSekretoPlugins.a"])
  try truth(okp, "nm: \(outp)")
  try truth(outp.contains("URLSession"), "the plugins archive has no socket in it")
}

// ONE PLUGIN NEEDS ONLY ITSELF. A swift module is compiled whole, so a
// plugin file that reached into a neighbour would still build as part of
// SekretoPlugins with no import to give it away. The check is to build it
// the way a lean consumer would - beside the shared helpers and nothing
// else - and the negative control is what gives that teeth: the aws plugin
// needs its signing, and compiling it without Sigv4.swift must FAIL.
func onepluginneedsonlyitself() throws {
  let swiftc = ProcessInfo.processInfo.environment["SEKRETO_SWIFTC"] ?? "swiftc"

  func compile(_ files: [String]) throws -> (Bool, String) {
    return try run(
      [swiftc, "-I", "build", "-emit-module", "-emit-library", "-static",
       "-module-name", "SekretoPlugins",
       "-emit-module-path", "build/one.swiftmodule", "-o", "build/libone.a"] + files)
  }

  let (lean, leanout) = try compile(
    ["plugins/Hashicorp.swift", "plugins/Httpjson.swift"])
  try truth(lean, "hashicorp does not build on its own: \(leanout)")

  let (partial, _) = try compile(["plugins/Aws.swift", "plugins/Httpjson.swift"])
  try truth(!partial, "aws built without its signing - the check has no teeth")
}

// ---------------------------------------------------------- the runner

func main() -> Int32 {
  let args = Array(CommandLine.arguments.dropFirst())
  if !args.isEmpty { ONLY = args[0] }

  testcase("fullset", thefullsetholdseverykind)
  testcase("everykind", everykindbuildsfromaspec)
  testcase("cli", theclipassesthefullset)
  testcase("builtinsalone", builtinsneednoplugin)
  testcase("oneplugin", onepluginisenoughforachainthatnamesonlyit)
  testcase("unknownkind", akindthatwasnotpassedinisrefusednamingthefix)
  testcase("repeatedstore", arepeatedstorenamekeepsthestoreandnumberstheinstance)
  testcase("storename", astorenamemustbeavalidtag)
  testcase("sekretoerror", asekretoerrorthrownindefinecomesbackoutasitself)
  testcase("othererror", anyothererrorthrownindefineisthehostsreportofit)
  testcase("customkind", acustomkindisoneproviderplugincall)
  testcase("replacebuiltin", apluginmayreplaceabuiltinkind)
  testcase("liveprovider", aliveproviderjoinsthechain)
  testcase("notaplugin", adefinitionthatisnotaproviderpluginisrefused)
  testcase("close", closetearsthechaindownandkeepsredaction)
  testcase("fullsetinert", thefullsetisinert)
  testcase("specroundtrip", everyspecfieldsurvivestheroundtrip)
  testcase("corebuild", thecoreisbuiltfromsrcalone)
  testcase("coresource", thecorenamesnopluginandreachesnoplatform)
  testcase("corearchive", thecorearchivelinksnoplugin)
  testcase("leanplugin", onepluginneedsonlyitself)

  print("\n\(passcount) passed, \(failcount) failed")

  return 0 == failcount ? 0 : 1
}

exit(main())
