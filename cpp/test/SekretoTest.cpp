// RUN: make test
// RUN-SOME: ./build/sekreto-test envkey
//
// The sekreto conformance suite. Every port runs these same groups, from
// the same spec/sekreto.json, through its own voxgig/omni runner.
//
// No third-party test framework: a failing omni check throws OmniError, so
// any host framework (Catch2, GoogleTest) reports it as a failure. This
// harness keeps `make test` dependency-free.
//
// Two value models meet here. omni has a `Json` with an Absent case; the
// library has its own, and takes typed specs. The bridge below converts
// between them explicitly, so nothing about absent, null and value is
// guessed. omni's is spelled `J` throughout, because both namespaces
// export a type of that name and the ambiguity is better resolved once
// than at every use.
//
// This is also the ONLY file in the port that may name voxgig/omni.

#include <filesystem>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "omni.hpp"

#include "Json.hpp"
#include "Providers.hpp"
#include "Sekreto.hpp"
#include "Sigv4.hpp"

namespace {

using J = omni::Json;

std::string ONLY;
int PASSCOUNT = 0;
int FAILCOUNT = 0;

/// Find the shared spec directory by walking up from the working
/// directory.
std::string specfile(const std::string& name) {
  std::filesystem::path dir = std::filesystem::current_path();

  for (int step = 0; step < 8; step++) {
    std::filesystem::path cand = dir / "spec" / name;
    if (std::filesystem::exists(cand)) return cand.string();
    if (!dir.has_parent_path() || dir == dir.parent_path()) break;
    dir = dir.parent_path();
  }

  throw omni::OmniError("sekreto: spec not found: " + name);
}

// ------------------------------------------------------------ the bridge

/// omni's model -> the library's own. Absent and null both read as null,
/// which is what the library's Json-flavoured entry points expect.
sekreto::Json plain(const J& value) {
  switch (value.type) {
    case J::Type::Absent:
    case J::Type::Null:
      return sekreto::Json::null();
    case J::Type::Bool:
      return sekreto::Json::boolean(value.boolval);
    case J::Type::Num:
      return sekreto::Json::num(value.numval);
    case J::Type::Str:
      return sekreto::Json::str(value.strval);
    case J::Type::List: {
      std::vector<sekreto::Json> out;
      for (const J& entry : value.listval) out.push_back(plain(entry));
      return sekreto::Json::arr(out);
    }
    case J::Type::Map: {
      std::vector<std::pair<std::string, sekreto::Json>> out;
      for (const auto& entry : value.mapval) out.emplace_back(entry.first, plain(entry.second));
      return sekreto::Json::obj(out);
    }
  }

  return sekreto::Json::null();
}

/// A field as text, or "" - the library's "not configured" is the empty
/// string everywhere.
std::string strof(const J& value) {
  return value.isstr() ? value.strval : "";
}

/// A list of strings, as omni compares them.
J textlist(const std::vector<std::string>& values) {
  J out = J::list();
  for (const std::string& value : values) out.push(J::str(value));
  return out;
}

/// An ordered string map, as omni compares it.
J textmap(const sekreto::Ordered& values) {
  J out = J::map();
  for (const auto& entry : values.pairs) out.set(entry.first, J::str(entry.second));
  return out;
}

/// One provider spec, out of the spec's declarative chain description.
sekreto::ProviderSpec specof(const J& entry) {
  sekreto::ProviderSpec spec;

  spec.kind = strof(entry.get("kind"));
  spec.name = strof(entry.get("name"));
  spec.prefix = strof(entry.get("prefix"));
  spec.file = strof(entry.get("file"));
  spec.dir = strof(entry.get("dir"));
  spec.addr = strof(entry.get("addr"));
  spec.token = strof(entry.get("token"));
  spec.mount = strof(entry.get("mount"));
  spec.vaultnamespace = strof(entry.get("vaultnamespace"));
  spec.command = strof(entry.get("command"));
  spec.profile = strof(entry.get("profile"));
  spec.backend = strof(entry.get("backend"));
  spec.reason = strof(entry.get("reason"));
  spec.namespace_ = strof(entry.get("namespace"));
  spec.home = strof(entry.get("home"));
  spec.region = strof(entry.get("region"));
  spec.keyid = strof(entry.get("keyid"));
  spec.secret = strof(entry.get("secret"));
  spec.session = strof(entry.get("session"));
  spec.project = strof(entry.get("project"));
  spec.vault = strof(entry.get("vault"));
  spec.tenant = strof(entry.get("tenant"));
  spec.clientid = strof(entry.get("clientid"));
  spec.clientsecret = strof(entry.get("clientsecret"));
  spec.loginaddr = strof(entry.get("loginaddr"));
  spec.imdsaddr = strof(entry.get("imdsaddr"));
  spec.metadataaddr = strof(entry.get("metadataaddr"));
  spec.apiversion = strof(entry.get("apiversion"));
  spec.config = strof(entry.get("config"));
  spec.environment = strof(entry.get("environment"));
  spec.path = strof(entry.get("path"));

  J values = entry.get("values");
  if (values.ismap()) {
    for (const auto& pair : values.mapval) {
      spec.values.set(pair.first, omni::stringify(pair.second));
    }
  }

  J kv = entry.get("kv");
  if (kv.isnum()) spec.kv = static_cast<int>(kv.numval);

  J auth = entry.get("auth");
  if (auth.ismap()) {
    sekreto::AuthSpec use;
    use.method = strof(auth.get("method"));
    use.mount = strof(auth.get("mount"));
    use.role = strof(auth.get("role"));
    use.jwt = strof(auth.get("jwt"));
    use.jwtfile = strof(auth.get("jwtfile"));
    use.roleid = strof(auth.get("roleid"));
    use.secretid = strof(auth.get("secretid"));
    spec.auth = use;
  }

  return spec;
}

/// Build a Sekreto from the spec's declarative chain description.
///
/// Built INSIDE the subject, never beside it: four entries expect
/// `unsupported kv version`, which the constructor raises, and only a
/// construction failure inside the subject reaches omni as a subject
/// error. Caching is off on every constructed chain.
sekreto::Sekreto chainof(const J& entry) {
  std::vector<sekreto::ProviderSpec> chain;

  J list = entry.get("chain");
  if (list.islist()) {
    for (const J& one : list.listval) chain.push_back(specof(one));
  }

  return sekreto::makesekreto(chain, false);
}

/// The name a group's entry asks about.
std::string namearg(const J& entry) {
  return strof(entry.get("name"));
}

// --------------------------------------------------------- the subjects

// `validname` answers a C++ bool; the spec wants a JSON true, so the
// adaptation happens here rather than in the library.
const omni::Subject VALIDNAME = [](const std::vector<J>& args) {
  return J::boolean(sekreto::validname(plain(args[0])));
};

const omni::Subject ENVKEY = [](const std::vector<J>& args) {
  return J::str(sekreto::envkey(sekreto::checkname(plain(args[0].get("name"))),
                                strof(args[0].get("prefix"))));
};

const omni::Subject VAULTREF = [](const std::vector<J>& args) {
  sekreto::VaultRef ref = sekreto::vaultref(sekreto::checkname(plain(args[0])));
  J out = J::map();
  out.set("path", J::str(ref.path));
  out.set("field", J::str(ref.field));
  return out;
};

const omni::Subject FLATNAME = [](const std::vector<J>& args) {
  return J::str(sekreto::flatname(sekreto::checkname(plain(args[0].get("name"))),
                                  strof(args[0].get("sep"))));
};

const omni::Subject AWSPARAM = [](const std::vector<J>& args) {
  return J::str(sekreto::awsparam(sekreto::checkname(plain(args[0].get("name"))),
                                  strof(args[0].get("prefix"))));
};

const omni::Subject PARSEDOTENV = [](const std::vector<J>& args) {
  return textmap(sekreto::parsedotenv(plain(args[0])));
};

const omni::Subject RESOLVE = [](const std::vector<J>& args) {
  return J::str(chainof(args[0]).get(namearg(args[0])));
};

const omni::Subject TRYSECRET = [](const std::vector<J>& args) {
  std::optional<std::string> found = chainof(args[0]).tryget(namearg(args[0]));
  if (!found.has_value()) return J::null();
  return J::str(found.value());
};

const omni::Subject SOURCES = [](const std::vector<J>& args) {
  return textlist(chainof(args[0]).sources());
};

const omni::Subject STORES = [](const std::vector<J>& args) {
  return textlist(chainof(args[0]).stores());
};

const omni::Subject GETFROM = [](const std::vector<J>& args) {
  return J::str(chainof(args[0]).getfrom(strof(args[0].get("store")), namearg(args[0])));
};

const omni::Subject TRYFROM = [](const std::vector<J>& args) {
  std::optional<std::string> found =
      chainof(args[0]).tryfrom(strof(args[0].get("store")), namearg(args[0]));
  if (!found.has_value()) return J::null();
  return J::str(found.value());
};

// Answers the ordered output map itself, which omni compares as a JSON
// object against the spec's known-answer signatures.
const omni::Subject SIGV4 = [](const std::vector<J>& args) {
  const J& entry = args[0];

  sekreto::Signing input;
  input.method = strof(entry.get("method"));
  input.url = strof(entry.get("url"));
  input.service = strof(entry.get("service"));
  input.region = strof(entry.get("region"));
  input.keyid = strof(entry.get("keyid"));
  input.secret = strof(entry.get("secret"));
  input.datetime = strof(entry.get("datetime"));
  input.body = strof(entry.get("body"));
  input.session = strof(entry.get("session"));

  J headers = entry.get("headers");
  if (headers.ismap()) {
    for (const auto& pair : headers.mapval) {
      input.headers.set(pair.first, omni::stringify(pair.second));
    }
  }

  return textmap(sekreto::sigv4(input));
};

const omni::Subject REDACT = [](const std::vector<J>& args) {
  std::vector<std::string> values;

  J list = args[0].get("values");
  if (list.islist()) {
    for (const J& one : list.listval) {
      if (one.isstr()) values.push_back(one.strval);
    }
  }

  J text = args[0].get("text");

  // A non-string text answers "", which the library's own overload does -
  // reached here by passing only what is a string through.
  return J::str(sekreto::redact(text.isstr() ? text.strval : "", values));
};

// ----------------------------------------------------------- the runner

void testcase(const std::string& name, const std::function<void()>& body) {
  if (!ONLY.empty() && name != ONLY) return;

  try {
    body();
    PASSCOUNT++;
    std::cout << "ok   - " << name << "\n";
  } catch (const std::exception& err) {
    FAILCOUNT++;
    std::cout << "FAIL - " << name << "\n" << err.what() << "\n";
  }
}

}  // namespace

int main(int argc, char** argv) {
  if (1 < argc) ONLY = argv[1];

  omni::RunPack R = omni::makeRunner(specfile("sekreto.json")).runner("sekreto");

  // `validname` is the only group with nonull: its set carries real JSON
  // nulls as inputs, which default flags would rewrite to a sentinel.
  testcase("validname",
           [&R] { R.runsetflags(R.set("validname"), omni::Flags::nonull(), VALIDNAME); });
  testcase("envkey", [&R] { R.runset(R.set("envkey"), ENVKEY); });
  testcase("vaultref", [&R] { R.runset(R.set("vaultref"), VAULTREF); });
  testcase("flatname", [&R] { R.runset(R.set("flatname"), FLATNAME); });
  testcase("awsparam", [&R] { R.runset(R.set("awsparam"), AWSPARAM); });
  testcase("parsedotenv", [&R] { R.runset(R.set("parsedotenv"), PARSEDOTENV); });
  testcase("resolve", [&R] { R.runset(R.set("resolve"), RESOLVE); });
  testcase("trysecret", [&R] { R.runset(R.set("trysecret"), TRYSECRET); });
  testcase("sources", [&R] { R.runset(R.set("sources"), SOURCES); });
  testcase("stores", [&R] { R.runset(R.set("stores"), STORES); });
  testcase("getfrom", [&R] { R.runset(R.set("getfrom"), GETFROM); });
  testcase("tryfrom", [&R] { R.runset(R.set("tryfrom"), TRYFROM); });
  testcase("sigv4", [&R] { R.runset(R.set("sigv4"), SIGV4); });
  testcase("redact", [&R] { R.runset(R.set("redact"), REDACT); });

  std::cout << "\n" << PASSCOUNT << " passed, " << FAILCOUNT << " failed\n";

  return 0 == FAILCOUNT ? 0 : 1;
}
