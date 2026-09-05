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
// One thing the conformance suite CAN see is a kind missing from the full
// set: `sources` and `stores` name all ten, so dropping one fails there
// too. The seam test for it is still worth having - it fails faster and
// names the kind - but it is not covering a blind spot. What genuinely is
// one is the CONSUMER's list: a CLI passing one plugin instead of ten
// leaves all fourteen conformance groups green and fails nine integration
// checks.
//
// This file is compiled as its own binary rather than folded into
// SekretoTest.cpp, because it needs no omni: a checkout with no omni beside
// it can still run the seam.
//
// No third-party test framework, for the same reason the conformance suite
// has none: `make test` stays dependency-free.

#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "All.hpp"
#include "Hashicorp.hpp"
#include "Provider.hpp"
#include "Providers.hpp"
#include "Sekreto.hpp"

namespace {

using sekreto::Definition;
using sekreto::Ordered;
using sekreto::Provider;
using sekreto::ProviderSpec;
using sekreto::Sekreto;
using sekreto::SekretoError;
using sekreto::SekretoOptions;

const std::vector<std::string> PLUGINKINDS = {
    "awsparams", "awssecrets", "azuresecrets", "boru",       "doppler",
    "gcpsecrets", "hashicorp", "infisical",    "onepassword", "secretspec",
};

const std::vector<std::string> BUILTINKINDS = {"dotenv", "env", "file", "memory"};

// ---------------------------------------------------------- the harness

std::string ONLY;
int PASSCOUNT = 0;
int FAILCOUNT = 0;

struct Failed : public std::runtime_error {
  explicit Failed(const std::string& why) : std::runtime_error(why) {}
};

void fail(const std::string& why) { throw Failed(why); }

std::string show(const std::vector<std::string>& list) {
  std::string out = "[";
  for (size_t index = 0; index < list.size(); index++) {
    if (0 < index) out += ", ";
    out += list[index];
  }
  return out + "]";
}

void same(const std::string& got, const std::string& want, const std::string& what) {
  if (got != want) fail(what + ": got \"" + got + "\", want \"" + want + "\"");
}

void same(const std::vector<std::string>& got, const std::vector<std::string>& want,
          const std::string& what) {
  if (got != want) fail(what + ": got " + show(got) + ", want " + show(want));
}

void same(size_t got, size_t want, const std::string& what) {
  if (got != want) {
    fail(what + ": got " + std::to_string(got) + ", want " + std::to_string(want));
  }
}

void truth(bool got, const std::string& what) {
  if (!got) fail(what);
}

/// The SekretoError this threw, or a failure naming what it threw instead.
std::string refusal(const std::string& what, const std::function<void()>& body) {
  try {
    body();
  } catch (const SekretoError& err) {
    return err.what();
  } catch (const std::exception& err) {
    fail(what + ": not a SekretoError: " + err.what());
  }

  fail(what + ": nothing was refused");
  return "";
}

void testcase(const std::string& name, const std::function<void()>& body) {
  if (!ONLY.empty() && name != ONLY) return;

  try {
    body();
    PASSCOUNT++;
    std::cout << "ok   - " << name << "\n";
  } catch (const std::exception& err) {
    FAILCOUNT++;
    std::cout << "FAIL - " << name << "\n       " << err.what() << "\n";
  }
}

// ------------------------------------------------------------ the port

/// The port directory, found from this binary rather than from the working
/// directory, so `./build/sekreto-plugintest` works from anywhere.
std::string HERE;

bool exists(const std::string& path) {
  struct stat info;
  return 0 == ::stat(path.c_str(), &info);
}

void findhere(const std::string& argv0) {
  std::string dir = argv0;
  size_t at = dir.rfind('/');
  dir = (std::string::npos == at) ? "." : dir.substr(0, at);

  if ('/' != dir[0]) {
    char cwd[4096];
    if (nullptr != ::getcwd(cwd, sizeof(cwd))) dir = std::string(cwd) + "/" + dir;
  }

  for (int step = 0; step < 8; step++) {
    if (exists(dir + "/plugins/All.cpp")) {
      HERE = dir;
      return;
    }
    at = dir.rfind('/');
    if (std::string::npos == at || 0 == at) break;
    dir = dir.substr(0, at);
  }

  HERE = ".";
}

/// A file of this port, read whole.
std::string source(const std::string& path) {
  std::ifstream handle(HERE + "/" + path);
  if (!handle) fail("cannot read " + path);

  std::stringstream out;
  out << handle.rdbuf();
  return out.str();
}

bool holds(const std::string& text, const std::string& want) {
  return std::string::npos != text.find(want);
}

/// Run a command and collect its output. Only ever `nm` here.
std::string run(const std::string& command) {
  FILE* pipe = popen(command.c_str(), "r");
  if (nullptr == pipe) fail("cannot run " + command);

  std::string out;
  char buf[4096];
  while (nullptr != std::fgets(buf, sizeof(buf), pipe)) out += buf;

  pclose(pipe);
  return out;
}

// ------------------------------------------------------- plugin values

std::vector<std::string> keysof(const plugin::V& map) {
  return plugin::keys(map);
}

std::vector<std::string> listof(const plugin::V& list) {
  std::vector<std::string> out;
  for (size_t index = 0; index < plugin::len(list); index++) {
    out.push_back(plugin::asstr(plugin::at(list, index)));
  }
  return out;
}

std::vector<std::string> namesof(const std::vector<Definition>& set) {
  std::vector<std::string> out;
  for (const Definition& def : set) out.push_back(def->name);
  return out;
}

std::vector<std::string> sorted(std::vector<std::string> list) {
  std::sort(list.begin(), list.end());
  return list;
}

ProviderSpec of(const std::string& kind) {
  ProviderSpec spec;
  spec.kind = kind;
  return spec;
}

// ------------------------------------------------- what the full set holds

void thefullsetholdseverykind() {
  same(sorted(namesof(sekreto::allplugins())), PLUGINKINDS, "allplugins");

  // ...and the core's list of what ships as a plugin says the same. It is
  // what tells a typo from a plugin nobody passed in, so a kind added on one
  // side and not the other would give the wrong advice.
  same(sorted(sekreto::KINDS().plugin), PLUGINKINDS, "KINDS().plugin");
  same(sekreto::KINDS().builtin, {"env", "memory", "dotenv", "file"}, "KINDS().builtin");
  same(namesof(sekreto::builtins()), sekreto::KINDS().builtin, "builtins()");
}

// Naming a kind is not enough: a kind can be in the catalog and still fail
// to build. Construction is what the CLI does before any network.
void everykindbuildsfromaspec() {
  std::vector<std::string> every = sorted(PLUGINKINDS);
  for (const std::string& kind : BUILTINKINDS) every.push_back(kind);
  every = sorted(every);

  std::vector<ProviderSpec> chain;

  for (const std::string& kind : every) {
    ProviderSpec spec = of(kind);
    spec.addr = "http://127.0.0.1:8200";
    spec.token = "t";
    spec.dir = "/tmp";
    spec.file = "/tmp/.env";
    chain.push_back(spec);
  }

  Sekreto secrets = sekreto::makesekreto(chain, sekreto::allplugins());

  same(secrets.stores(), every, "stores");
  same(keysof(secrets.host().list()), every, "host.list");

  for (const std::string& ref : keysof(secrets.host().list())) {
    same(plugin::asstr(plugin::get(secrets.host().list(), ref)), "live", ref);
  }
}

// THE CONSUMER'S LIST IS THE BLIND SPOT. A CLI that passes one plugin
// instead of ten leaves every conformance group green and fails nine
// integration checks, so the call site is pinned here - closing bracket
// included, because `holds("allplugins(")` is just as true of
// `allplugins().at(0)`.
void theclipassesthefullset() {
  const std::string text = source("cli/Cli.cpp");

  truth(holds(text, "#include \"All.hpp\""), "the CLI does not include the full set");
  truth(holds(text, "sekreto::makesekreto(chain, sekreto::allplugins());"),
        "the CLI does not pass the full set");

  // ...and so is the conformance suite's, for the same reason: it builds the
  // spec's chains, and the spec names kinds from both sides of the split.
  const std::string suite = source("test/SekretoTest.cpp");
  truth(holds(suite, "sekreto::makesekreto(chain, sekreto::allplugins(), false);"),
        "the conformance suite does not pass the full set");
}

// ---------------------------------------------------- what a consumer sees

// A chain of built-ins works with NO plugin loaded at all. That is the whole
// point of the four: an app that reads its secrets from options, the
// environment, a `.env` and a mounted directory links no vault client.
void builtinsneednoplugin() {
  ProviderSpec values = of("memory");
  values.values.set("API_TOKEN", "tok01");

  ProviderSpec dotenv = of("dotenv");
  dotenv.file = "/nonexistent-sekreto-test/.env";

  ProviderSpec fromdir = of("file");
  fromdir.dir = "/nonexistent-sekreto-test";

  Sekreto secrets = sekreto::makesekreto({values, of("env"), dotenv, fromdir});

  same(secrets.get("api.token"), "tok01", "get");
  same(secrets.stores(), {"memory", "env", "dotenv", "file"}, "stores");
  same(listof(secrets.catalog().names()), BUILTINKINDS, "catalog");
  same(keysof(secrets.host().list()), BUILTINKINDS, "host.list");

  for (const std::string& ref : keysof(secrets.host().list())) {
    same(plugin::asstr(plugin::get(secrets.host().list(), ref)), "live", ref);
  }
}

void onepluginisenoughforachainthatnamesonlyit() {
  ProviderSpec values = of("memory");
  values.values.set("API_TOKEN", "tok01");

  ProviderSpec vault = of("hashicorp");
  vault.name = "prod";
  vault.addr = "https://vault.example.com";
  vault.token = "t";

  Sekreto secrets = sekreto::makesekreto({values, vault}, {sekreto::hashicorp()});

  same(secrets.stores(), {"memory", "prod"}, "stores");
  same(secrets.sources(), {"memory", "hashicorp:https://vault.example.com/secret"}, "sources");
  same(secrets.get("api.token"), "tok01", "get");

  // The plugin host is what the chain is made of, and it reads like the
  // chain: the kind, or kind$store for a named store.
  same(keysof(secrets.host().list()), {"hashicorp$prod", "memory"}, "host.list");
  same(listof(secrets.catalog().names()),
       {"dotenv", "env", "file", "hashicorp", "memory"}, "catalog");
}

void akindthatwasnotpassedinisrefusednamingthefix() {
  ProviderSpec other = of("doppler");
  other.token = "t";

  same(refusal("doppler was not passed in",
               [&] { sekreto::makesekreto({other}, {sekreto::hashicorp()}); }),
       "sekreto: unknown provider kind: doppler "
       "(available: dotenv, env, file, hashicorp, memory)"
       " - doppler is a sekreto plugin, not built in: pass it in the plugins option",
       "unknown plugin kind");

  // A kind nobody ships is a typo, and gets no such hint.
  same(refusal("a typo cannot be built either",
               [&] { sekreto::makesekreto({of("vualt")}); }),
       "sekreto: unknown provider kind: vualt (available: dotenv, env, file, memory)",
       "unknown kind");
}

// Two providers MAY share a store name - a directed read walks both, and the
// spec pins it - but an instance ref may not, so the second gets a numbered
// tag from the host and keeps its store name.
void arepeatedstorenamekeepsthestoreandnumberstheinstance() {
  ProviderSpec second = of("memory");
  second.values.set("API_TOKEN", "second");

  ProviderSpec pair = of("memory");
  pair.name = "pair";

  ProviderSpec pairtwo = of("memory");
  pairtwo.name = "pair";
  pairtwo.values.set("API_TOKEN", "pair2");

  Sekreto secrets = sekreto::makesekreto({of("memory"), second, pair, pairtwo});

  same(secrets.stores(), {"memory", "pair"}, "stores");
  same(keysof(secrets.host().list()), {"memory", "memory$1", "memory$2", "memory$pair"},
       "host.list");
  same(secrets.getfrom("memory", "api.token"), "second", "getfrom memory");
  same(secrets.getfrom("pair", "api.token"), "pair2", "getfrom pair");
}

void astorenamemustbeavalidtag() {
  ProviderSpec spaced = of("memory");
  spaced.name = "my store";

  same(refusal("a store name is a plugin tag",
               [&] { sekreto::makesekreto({spaced}); }),
       "sekreto: invalid store name: my store", "invalid store name");
}

// A provider that refuses its own configuration throws a SekretoError from
// inside the plugin's `define`. The spec pins that message byte for byte, so
// it must come back out of the host as itself - not wrapped as
// plugin_define_failed, and not as a PluginError.
void asekretoerrorthrownindefinecomesbackoutasitself() {
  ProviderSpec vault = of("hashicorp");
  vault.addr = "http://127.0.0.1:1";
  vault.token = "t";
  vault.kv = 3;

  same(refusal("kv: 3 is not a KV version",
               [&] { sekreto::makesekreto({vault}, {sekreto::hashicorp()}); }),
       "sekreto: hashicorp: unsupported kv version: 3", "define refusal");
}

// ...and any other error is not sekreto's to rewrite: it surfaces as the
// host reports it, naming the instance and the cause.
void anyothererrorthrownindefineisthehostsreportofit() {
  Definition broken = sekreto::providerplugin(
      "broken", [](const ProviderSpec&) -> std::shared_ptr<Provider> {
        throw std::runtime_error("boom");
      });

  try {
    sekreto::makesekreto({of("broken")}, {broken});
    fail("a broken define was not reported");
  } catch (const plugin::PluginError& err) {
    same(err.code, "plugin_define_failed", "code");
    truth(holds(err.message, "boom"), "the cause is missing: " + err.message);
    truth(holds(err.message, "broken"), "the instance is missing: " + err.message);
  }
}

void acustomkindisoneproviderplugincall() {
  class Shouty : public Provider {
   public:
    explicit Shouty(const Ordered& values) : values_(values) {}

    std::optional<std::string> lookup(const std::string& name) override {
      return values_.get(sekreto::asciiupper(name));
    }

    std::string describe() const override { return "shouty"; }

   private:
    Ordered values_;
  };

  Definition shouty = sekreto::providerplugin(
      "shouty", [](const ProviderSpec& spec) -> std::shared_ptr<Provider> {
        return std::make_shared<Shouty>(spec.values);
      });

  ProviderSpec spec = of("shouty");
  spec.values.set("API.TOKEN", "loud");

  Sekreto secrets = sekreto::makesekreto({spec}, {shouty});

  same(secrets.get("api.token"), "loud", "get");
  same(keysof(secrets.host().list()), {"shouty"}, "host.list");
}

// A plugin that names a built-in kind replaces it: that is how a host
// substitutes an implementation, and never an accident, because the four
// names are documented.
void apluginmayreplaceabuiltinkind() {
  class Replaced : public Provider {
   public:
    std::optional<std::string> lookup(const std::string&) override { return "replaced"; }
    std::string describe() const override { return "memory"; }
  };

  Definition replacement = sekreto::providerplugin(
      "memory",
      [](const ProviderSpec&) -> std::shared_ptr<Provider> {
        return std::make_shared<Replaced>();
      });

  ProviderSpec spec = of("memory");
  spec.values.set("API_TOKEN", "original");

  Sekreto secrets = sekreto::makesekreto({spec}, {replacement});

  same(secrets.get("api.token"), "replaced", "get");
  same(listof(secrets.catalog().names()), BUILTINKINDS, "catalog");
}

// A live provider handed in directly joins the chain with no instance behind
// it: nothing declared it, so the host is empty and the store name comes
// from `describe()`.
void aliveproviderjoinsthechain() {
  class Fixed : public Provider {
   public:
    std::optional<std::string> lookup(const std::string&) override { return "fixed"; }
    std::string describe() const override { return "fixed:one"; }
  };

  Sekreto secrets(std::vector<std::shared_ptr<Provider>>{std::make_shared<Fixed>()}, {});

  same(secrets.get("api.token"), "fixed", "get");
  same(secrets.stores(), {"fixed"}, "stores");
  same(keysof(secrets.host().list()), {}, "host.list");
}

void adefinitionthatisnotoneisrefused() {
  same(refusal("nothing is not a definition",
               [&] {
                 SekretoOptions options;
                 options.plugins = {Definition()};
                 Sekreto secrets(options);
               }),
       "sekreto: not a plugin definition: nothing"
       " - pass the definition providerplugin returned",
       "not a definition");
}

void closetearsthechaindownandkeepsredaction() {
  ProviderSpec spec = of("memory");
  spec.values.set("API_TOKEN", "tok01");

  Sekreto secrets = sekreto::makesekreto({spec});
  same(secrets.get("api.token"), "tok01", "get");

  secrets.close();

  same(keysof(secrets.host().list()), {}, "host.list");
  same(secrets.stores(), {}, "stores");
  truth(!secrets.tryget("api.token").has_value(), "the chain still resolves");
  same(secrets.redact("token=tok01"), "token=[redacted]", "redact");
}

// The full set is BUILT, not held: `allplugins()` returns fresh definitions,
// so two Sekretos never share one and a consumer that wants one kind calls
// that kind's own function and links nothing else.
void thefullsetisbuiltondemand() {
  std::vector<Definition> first = sekreto::allplugins();
  std::vector<Definition> second = sekreto::allplugins();

  same(first.size(), size_t(10), "allplugins");
  same(second.size(), size_t(10), "allplugins again");

  for (size_t index = 0; index < first.size(); index++) {
    truth(first[index] != second[index], "two calls share a definition");
  }

  // ...and each kind is its own header, which is what makes "include one" a
  // thing a consumer can actually do.
  const std::vector<std::string> headers = {
      "Hashicorp", "Boru",      "Aws",   "Gcpsecrets", "Azuresecrets", "Onepassword",
      "Doppler",   "Infisical", "Secretspec", "Httpjson", "Sigv4", "Crypto", "Proc", "Tls"};

  for (const std::string& file : headers) {
    truth(exists(HERE + "/plugins/" + file + ".hpp"), "no plugins/" + file + ".hpp");
  }
}

// A provider is parked in a slot for the moment between its `define` and the
// host handing back its export, because voxgig/plugin values carry numbers
// and not pointers. Every slot is claimed, including on the failing paths,
// so the table is empty between constructions.
void nothingisleftinaslot() {
  same(sekreto::providerslots(), size_t(0), "before");

  ProviderSpec spec = of("memory");
  spec.values.set("API_TOKEN", "tok01");
  Sekreto secrets = sekreto::makesekreto({spec});
  same(sekreto::providerslots(), size_t(0), "after a chain was built");

  ProviderSpec bad = of("hashicorp");
  bad.addr = "http://127.0.0.1:1";
  bad.token = "t";
  bad.kv = 3;

  ProviderSpec good = of("memory");

  try {
    sekreto::makesekreto({good, bad}, {sekreto::hashicorp()});
  } catch (const SekretoError&) {
    // The point: the first provider was built and the second refused.
  }

  same(sekreto::providerslots(), size_t(0), "after a chain failed halfway");

  // ...AND THE CASE THAT ONE CANNOT SEE. `kv: 3` refuses inside `define`,
  // before the provider exists and therefore before anything is parked, so
  // it never reaches the discard at all: taking `providerdiscard` out of
  // `declare` leaves the assertion above green while a provider is stranded
  // for good. A slot is only left filled when `define` SUCCEEDS - the
  // provider is parked and its ticket exported - and the instance then fails
  // to go live, which is what this builds.
  {
    class Fixed : public Provider {
     public:
      std::optional<std::string> lookup(const std::string&) override { return "fixed"; }
      std::string describe() const override { return "wontstart"; }
    };

    Definition built = sekreto::providerplugin(
        "wontstart", [](const ProviderSpec&) -> std::shared_ptr<Provider> {
          return std::make_shared<Fixed>();
        });

    auto refuses = std::make_shared<plugin::Definition>();
    refuses->name = built->name;
    refuses->define = built->define;
    refuses->activate = [](plugin::Inst&) {
      plugin::fail("wontstart_refused", "this instance will not go live");
    };

    try {
      sekreto::makesekreto({of("memory"), of("wontstart")}, {refuses});
      fail("an activate that refuses was not reported");
    } catch (const plugin::PluginError&) {
      // As it should be: an error that is not sekreto's to rewrite.
    }

    same(sekreto::providerslots(), size_t(0), "after an activate refused");
  }
}

// ------------------------------------------------- what the core reaches

// THE COMPILER'S HALF. The core is compiled from src/ with plugins/ NOT on
// its include path, so a core source that wrote `#include "Httpjson.hpp"`
// would fail to compile. That is the boundary this port has instead of a
// module system, and it is worth pinning because it is one -I away from
// gone.
void thecoreisbuiltfromsrcalone() {
  std::string makefile = source("Makefile");

  // Continuations folded first: a recipe's logical line is what decides what
  // gets compiled.
  std::string folded;
  for (size_t index = 0; index < makefile.size(); index++) {
    if ('\\' == makefile[index] && index + 1 < makefile.size() && '\n' == makefile[index + 1]) {
      folded += ' ';
      index++;
      continue;
    }
    folded += makefile[index];
  }

  auto recipe = [&folded](const std::string& target) {
    size_t at = folded.find(target);
    if (std::string::npos == at) fail("the Makefile has no rule for " + target);
    size_t from = folded.find("$(CXX)", at);
    if (std::string::npos == from) fail("no compile line for " + target);
    return folded.substr(from, folded.find('\n', from) - from);
  };

  const std::string core = recipe("build/obj/core/%.o: src/%.cpp");
  truth(holds(core, "-Isrc"), "the core's compile line: " + core);
  truth(!holds(core, "-Iplugins"), "the core is compiled with -Iplugins: " + core);

  // ...and the plugins ARE compiled with both, which is what makes the line
  // above a boundary rather than an omission.
  const std::string kinds = recipe("build/obj/plugins/%.o: plugins/%.cpp");
  truth(holds(kinds, "-Iplugins"), "the plugins' compile line: " + kinds);
  truth(holds(kinds, "-Isrc"), "the plugins' compile line: " + kinds);
}

// ...and what the SOURCE says, for the little the compiler and the symbol
// table between them cannot see.
//
// CODE, not prose: the comments in src/ point at the plugins on purpose -
// that is how a reader finds them - and a scan that could not tell an
// expression from a sentence would have to choose between being wrong and
// being useless. Matched as FIXED STRINGS, because `Socket.` read as a regex
// matches `SocketException` and half of these would fire on a comment.
void thecorenamesnoplugin() {
  const std::vector<std::string> banned = {
      "#include \"Httpjson.hpp\"", "#include \"Tls.hpp\"", "#include \"Crypto.hpp\"",
      "#include \"Sigv4.hpp\"",    "#include \"Proc.hpp\"", "#include \"All.hpp\"",
      "#include <openssl/",        "#include <sys/socket.h>", "#include <netdb.h>",
      "allplugins",                "sha256",                 "hmacsha256",
      "SSL_",
  };

  const std::vector<std::string> files = {"Json.cpp",  "Json.hpp",      "Provider.cpp",
                                          "Provider.hpp", "Providers.cpp", "Providers.hpp",
                                          "Sekreto.cpp", "Sekreto.hpp"};

  for (const std::string& name : files) {
    std::istringstream lines(source("src/" + name));
    std::string line;

    while (std::getline(lines, line)) {
      size_t from = line.find_first_not_of(" \t");
      if (std::string::npos == from) continue;
      if ("//" == line.substr(from, 2)) continue;

      for (const std::string& word : banned) {
        if (holds(line, word)) fail("src/" + name + " names " + word + " - it belongs in a plugin");
      }
    }
  }

  // A read of no files is a pass that measured nothing.
  for (const std::string& name : files) {
    truth(exists(HERE + "/src/" + name), "no src/" + name);
  }
}

// THE NAMES A LIBC CALL LEAVES BEHIND, which is the half that cannot be
// talked around.
//
// `socket`, `connect`, `getaddrinfo`, `fork`, `execve`, `posix_spawn`,
// `popen` and `dlopen` are all reachable from a C++ file with a declaration
// and no sekreto header to key a source scan on - a core could open a socket
// and spawn a child without naming one word the scan above looks for. The
// archive's own list of what it needs from outside is what says otherwise.
//
// EXACT NAMES, never substrings: `connect` is inside `disconnect`, and a
// substring search over a mangled C++ symbol finds `system` in all sorts of
// places. The C symbols are unmangled, so the raw `nm` output is what is
// matched, and this reads `nm` without `-C` deliberately.
const std::set<std::string> PLATFORMSYMBOLS = {
    "socket", "connect", "bind",    "listen",       "accept",       "accept4",
    "getaddrinfo", "gethostbyname", "gethostbyname2", "posix_spawn", "posix_spawnp",
    "fork",   "vfork",   "execv",   "execve",       "execvp",       "execl",
    "execlp", "popen",   "system",  "dlopen",       "dlsym",
};

/// The name in each `nm -u` line: "                 U socket" is one field
/// once the padding is gone.
std::set<std::string> neededby(const std::string& out) {
  std::set<std::string> names;
  std::istringstream lines(out);
  std::string line;

  while (std::getline(lines, line)) {
    std::istringstream fields(line);
    std::string field;
    std::string last;
    while (fields >> field) last = field;
    if (!last.empty()) names.insert(last);
  }

  return names;
}

void thecorearchiveneedsnoplatform() {
  const std::set<std::string> needed = neededby(run("nm -u '" + HERE + "/build/libsekreto.a'"));

  // THE CONTROL FOR THE READ ITSELF: the core needs the allocator, so a set
  // with none of these in it is a set that was not parsed - a stripped
  // archive, a wrong flag, an `nm` that is not there - and the empty
  // intersection below would then mean nothing at all. A check that reports
  // success when it read nothing is worse than no check.
  bool sane = false;
  const std::vector<std::string> allocator = {"malloc", "free",   "memcpy",
                                             "memset", "_Znwm", "_ZdlPv"};

  for (const std::string& name : allocator) {
    if (needed.end() != needed.find(name)) sane = true;
  }
  truth(sane, "no libc name came out of nm - the symbol read has no teeth");

  std::vector<std::string> reached;
  for (const std::string& name : needed) {
    if (PLATFORMSYMBOLS.end() != PLATFORMSYMBOLS.find(name)) reached.push_back(name);
    if (0 == name.compare(0, 4, "SSL_")) reached.push_back(name);
  }

  truth(reached.empty(), "the core archive needs " + show(reached) +
                             " - a socket, a child process or TLS");

  // ...and the same read of the plugins archive DOES find them, which is what
  // makes the half above a measurement rather than a tautology.
  const std::set<std::string> theirs =
      neededby(run("nm -u '" + HERE + "/build/libsekretoplugins.a'"));

  const std::vector<std::string> platform = {"socket", "connect", "execve"};

  for (const std::string& want : platform) {
    truth(theirs.end() != theirs.find(want), "the plugins archive does not need " + want);
  }

  bool tls = false;
  for (const std::string& name : theirs) {
    if (0 == name.compare(0, 4, "SSL_")) tls = true;
  }
  truth(tls, "the plugins archive needs no TLS");
}

// ONLY THE SIGNER NEEDS A DIGEST. Percent-encoding and base64 sit with the
// transport rather than with SigV4, so a plugin that builds a query string
// or decodes a payload - Azure, 1Password, Doppler, Infisical, GCP - does
// not drag SHA-256 in behind it. Read from the object files, demangled,
// because these are C++ symbols.
void onlyawsneedsadigest() {
  const std::vector<std::string> unsigned_ = {
      "Hashicorp", "Boru",      "Gcpsecrets", "Azuresecrets", "Onepassword",
      "Doppler",   "Infisical", "Secretspec", "Httpjson",     "Tls"};

  for (const std::string& kind : unsigned_) {
    const std::string out =
        run("nm -C -u '" + HERE + "/build/obj/plugins/" + kind + ".o'");
    truth(!holds(out, "sekreto::sha256") && !holds(out, "sekreto::hmacsha256"),
          kind + " needs a digest - only aws signs");
  }

  // The control: aws does need one, so the read above is looking at
  // something.
  const std::string aws = run("nm -C -u '" + HERE + "/build/obj/plugins/Sigv4.o'");
  truth(holds(aws, "sekreto::sha256"), "sigv4 needs no digest - the read has no teeth");
}

}  // namespace

int main(int argc, char** argv) {
  findhere(argv[0]);
  if (1 < argc) ONLY = argv[1];

  testcase("fullset", thefullsetholdseverykind);
  testcase("everykind", everykindbuildsfromaspec);
  testcase("cli", theclipassesthefullset);
  testcase("builtinsalone", builtinsneednoplugin);
  testcase("oneplugin", onepluginisenoughforachainthatnamesonlyit);
  testcase("unknownkind", akindthatwasnotpassedinisrefusednamingthefix);
  testcase("repeatedstore", arepeatedstorenamekeepsthestoreandnumberstheinstance);
  testcase("storename", astorenamemustbeavalidtag);
  testcase("sekretoerror", asekretoerrorthrownindefinecomesbackoutasitself);
  testcase("othererror", anyothererrorthrownindefineisthehostsreportofit);
  testcase("customkind", acustomkindisoneproviderplugincall);
  testcase("replacebuiltin", apluginmayreplaceabuiltinkind);
  testcase("liveprovider", aliveproviderjoinsthechain);
  testcase("notadefinition", adefinitionthatisnotoneisrefused);
  testcase("close", closetearsthechaindownandkeepsredaction);
  testcase("fullsetbuilt", thefullsetisbuiltondemand);
  testcase("slots", nothingisleftinaslot);
  testcase("corebuild", thecoreisbuiltfromsrcalone);
  testcase("coresource", thecorenamesnoplugin);
  testcase("corearchive", thecorearchiveneedsnoplatform);
  testcase("digest", onlyawsneedsadigest);

  std::cout << "\n" << PASSCOUNT << " passed, " << FAILCOUNT << " failed\n";

  return 0 == FAILCOUNT ? 0 : 1;
}
