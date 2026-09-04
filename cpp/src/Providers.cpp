#include "Providers.hpp"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <cstdlib>
#include <ctime>
#include <limits>
#include <map>

#include "Crypto.hpp"
#include "Http.hpp"
#include "Sigv4.hpp"

extern char** environ;

namespace sekreto {

// ------------------------------------------------------------- the specs

namespace {

/// What a credential field reports about itself.
std::string setornot(const std::string& value) {
  return value.empty() ? "[unset]" : "[set]";
}

}  // namespace

std::string AuthSpec::str() const {
  return "AuthSpec(method=" + method + ", mount=" + mount + ", role=" + role +
         ", jwtfile=" + jwtfile + ", roleid=" + roleid + ", jwt=" + setornot(jwt) +
         ", secretid=" + setornot(secretid) + ")";
}

std::string ProviderSpec::str() const {
  return "ProviderSpec(kind=" + kind + ", name=" + name + ", addr=" + addr +
         ", token=" + setornot(token) + ", secret=" + setornot(secret) +
         ", clientsecret=" + setornot(clientsecret) +
         ", auth=" + (auth.has_value() ? auth.value().str() : "none") + ")";
}

// -------------------------------------------------------- shared machinery

std::string first(const std::string& one, const std::string& two) {
  return one.empty() ? two : one;
}

std::string first(const std::string& one, const std::string& two, const std::string& three) {
  if (!one.empty()) return one;
  if (!two.empty()) return two;
  return three;
}

namespace {

std::string envvar(const std::string& name) {
  const char* value = std::getenv(name.c_str());
  return (nullptr == value) ? "" : value;
}

std::string trimslash(const std::string& text) {
  if (!text.empty() && '/' == text[text.size() - 1]) return text.substr(0, text.size() - 1);
  return text;
}

std::string trimtext(const std::string& text) {
  size_t start = 0;
  size_t stop = text.size();

  while (start < stop && (' ' == text[start] || '\t' == text[start] || '\n' == text[start] ||
                          '\r' == text[start])) {
    start++;
  }
  while (stop > start && (' ' == text[stop - 1] || '\t' == text[stop - 1] ||
                          '\n' == text[stop - 1] || '\r' == text[stop - 1])) {
    stop--;
  }

  return text.substr(start, stop - start);
}

std::string dropnewline(const std::string& text) {
  if (!text.empty() && '\n' == text[text.size() - 1]) return text.substr(0, text.size() - 1);
  return text;
}

double nowms() {
  return static_cast<double>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count());
}

const double NEVER = std::numeric_limits<double>::max();

/// When a logged-in token must be renewed, from its expiry in seconds (a
/// JSON number, or a string as Azure IMDS sends it): now + max(seconds -
/// 60, 1). A missing or zero expiry means never renew, which is also what
/// a configured token gets.
double renewtime(const Json& expires) {
  double seconds = 0;
  std::string text;

  if (expires.asnum(seconds)) {
    // Taken as it stands.
  } else if (expires.asstr(text)) {
    char* stop = nullptr;
    seconds = std::strtod(text.c_str(), &stop);
    if (nullptr == stop || '\0' != *stop) seconds = 0;
  }

  if (0 >= seconds) return NEVER;

  double lead = seconds - 60;
  if (1 > lead) lead = 1;

  return nowms() + lead * 1000;
}

// ------------------------------------------------------------- file reads

enum class Readstate { Text, Absent, Failed };

/// The outcome of reading a file that may legitimately not be there.
struct Readout {
  Readstate state = Readstate::Absent;
  std::string text;
  std::string why;
};

/// Read a whole file.
///
/// Absence is a MISS and the chain carries on; anything else - permission
/// denied, an unreadable mount, a failing disk - is an ERROR, because
/// returning a miss there falls silently through to a weaker store.
///
/// Keyed on the platform's not-found codes rather than on an `exists()`
/// predicate: that predicate answers false for a directory the process may
/// not stat, and would turn a locked mount - the canonical "unreadable
/// mount" - into a miss.
Readout readfile(const std::string& path) {
  Readout out;

  int fd = ::open(path.c_str(), O_RDONLY);

  if (0 > fd) {
    if (ENOENT == errno || ENOTDIR == errno) {
      out.state = Readstate::Absent;
      return out;
    }
    out.state = Readstate::Failed;
    out.why = strerror(errno);
    return out;
  }

  std::string body;
  char buf[8192];

  while (true) {
    ssize_t got = ::read(fd, buf, sizeof(buf));

    if (0 == got) break;

    if (0 > got) {
      if (EINTR == errno) continue;
      out.state = Readstate::Failed;
      out.why = strerror(errno);
      ::close(fd);
      return out;
    }

    body.append(buf, static_cast<size_t>(got));
  }

  ::close(fd);

  out.state = Readstate::Text;
  out.text = body;
  return out;
}

// ------------------------------------------------------------- subprocess

/// What a finished child process left behind.
struct Ran {
  std::string out;
  std::string why;
  int status = 0;
};

/// Where a command lives, searched along PATH, so that "this binary is not
/// installed" stays a `cannot run` error rather than arriving as a
/// non-zero exit the miss detection would then have to reason about.
bool findcommand(const std::string& command, const std::string& path, std::string& out) {
  auto runnable = [](const std::string& candidate) {
    return 0 == ::access(candidate.c_str(), X_OK);
  };

  if (std::string::npos != command.find('/')) {
    if (!runnable(command)) return false;
    out = command;
    return true;
  }

  size_t start = 0;

  while (start <= path.size()) {
    size_t at = path.find(':', start);
    std::string dir =
        (std::string::npos == at) ? path.substr(start) : path.substr(start, at - start);

    std::string candidate = dir.empty() ? command : dir + "/" + command;
    if (runnable(candidate)) {
      out = candidate;
      return true;
    }

    if (std::string::npos == at) break;
    start = at + 1;
  }

  return false;
}

/// Run a child to completion and collect both its streams.
///
/// The two streams are drained CONCURRENTLY, by polling both pipes.
/// Reading stdout to EOF and only then reading stderr deadlocks the moment
/// the child writes more than one pipe buffer (64 KiB on Linux) to stderr:
/// the parent is blocked on stdout, the child is blocked waiting for room
/// on stderr, and neither can move. Nothing here sets a timeout, so that
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
Ran runcmd(const std::vector<std::string>& argv,
           const std::vector<std::string>& environment, const std::string& command) {
  std::string path;
  for (const std::string& entry : environment) {
    if (0 == entry.compare(0, 5, "PATH=")) path = entry.substr(5);
  }

  std::string binary;
  if (!findcommand(argv[0], path, binary)) {
    throw SekretoError("sekreto: cannot run " + command + ": no such file or directory");
  }

  int outpipe[2];
  int errpipe[2];

  if (0 != pipe(outpipe)) {
    throw SekretoError(std::string("sekreto: cannot run ") + command + ": " + strerror(errno));
  }
  if (0 != pipe(errpipe)) {
    ::close(outpipe[0]);
    ::close(outpipe[1]);
    throw SekretoError(std::string("sekreto: cannot run ") + command + ": " + strerror(errno));
  }

  std::vector<char*> args;
  for (const std::string& arg : argv) {
    args.push_back(const_cast<char*>(arg.c_str()));
  }
  args.push_back(nullptr);

  std::vector<char*> envp;
  for (const std::string& entry : environment) {
    envp.push_back(const_cast<char*>(entry.c_str()));
  }
  envp.push_back(nullptr);

  pid_t child = fork();

  if (0 > child) {
    ::close(outpipe[0]);
    ::close(outpipe[1]);
    ::close(errpipe[0]);
    ::close(errpipe[1]);
    throw SekretoError(std::string("sekreto: cannot run ") + command + ": " + strerror(errno));
  }

  if (0 == child) {
    int null = ::open("/dev/null", O_RDONLY);
    if (0 <= null) {
      dup2(null, STDIN_FILENO);
      ::close(null);
    }

    dup2(outpipe[1], STDOUT_FILENO);
    dup2(errpipe[1], STDERR_FILENO);

    ::close(outpipe[0]);
    ::close(outpipe[1]);
    ::close(errpipe[0]);
    ::close(errpipe[1]);

    execve(binary.c_str(), args.data(), envp.data());
    _exit(127);
  }

  ::close(outpipe[1]);
  ::close(errpipe[1]);

  Ran ran;
  std::string errtext;

  pollfd waiting[2];
  waiting[0].fd = outpipe[0];
  waiting[1].fd = errpipe[0];

  while (0 <= waiting[0].fd || 0 <= waiting[1].fd) {
    waiting[0].events = POLLIN;
    waiting[1].events = POLLIN;
    waiting[0].revents = 0;
    waiting[1].revents = 0;

    if (0 > poll(waiting, 2, -1)) {
      if (EINTR == errno) continue;
      break;
    }

    for (int side = 0; side < 2; side++) {
      if (0 > waiting[side].fd || 0 == waiting[side].revents) continue;

      char buf[4096];
      ssize_t got = ::read(waiting[side].fd, buf, sizeof(buf));

      if (0 < got) {
        if (0 == side) {
          ran.out.append(buf, static_cast<size_t>(got));
        } else {
          errtext.append(buf, static_cast<size_t>(got));
        }
        continue;
      }

      if (0 > got && EINTR == errno) continue;

      ::close(waiting[side].fd);
      waiting[side].fd = -1;
    }
  }

  if (0 <= waiting[0].fd) ::close(waiting[0].fd);
  if (0 <= waiting[1].fd) ::close(waiting[1].fd);

  int state = 0;
  while (0 > waitpid(child, &state, 0)) {
    if (EINTR != errno) break;
  }

  ran.status = WIFEXITED(state) ? WEXITSTATUS(state) : 1;
  ran.why = trimtext(errtext);

  return ran;
}

/// The process environment as `KEY=value` entries.
std::vector<std::string> processenv() {
  std::vector<std::string> out;

  for (char** step = environ; nullptr != *step; step++) {
    out.push_back(*step);
  }

  return out;
}

void setenvvar(std::vector<std::string>& environment, const std::string& key,
               const std::string& value) {
  std::string prefix = key + "=";

  for (std::string& entry : environment) {
    if (0 == entry.compare(0, prefix.size(), prefix)) {
      entry = prefix + value;
      return;
    }
  }

  environment.push_back(prefix + value);
}

}  // namespace

// --------------------------------------------------------------- addresses

std::string safeaddr(const std::string& addr) {
  size_t mark = addr.find("://");
  if (std::string::npos == mark) return addr;

  size_t from = mark + 3;
  size_t stop = addr.find_first_of("/?#", from);
  std::string authority =
      (std::string::npos == stop) ? addr.substr(from) : addr.substr(from, stop - from);

  size_t at = authority.rfind('@');
  if (std::string::npos == at) return addr;

  return addr.substr(0, from) + "[redacted]" + addr.substr(from + at);
}

void checkaddr(const std::string& addr) {
  std::string scheme;

  // Literal and case-sensitive: `HTTP://localhost` is refused rather than
  // normalised, because normalising is where parsers start to disagree.
  if (0 == addr.compare(0, 8, "https://")) {
    scheme = "https://";
  } else if (0 == addr.compare(0, 7, "http://")) {
    scheme = "http://";
  } else {
    throw SekretoError("sekreto: not an http(s) address: " + safeaddr(addr));
  }

  std::string rest = addr.substr(scheme.size());

  // The authority ends at `/`, `?` or `#` only - never at `\`. A client
  // that also breaks on backslash can then only ever see a SHORTER host
  // than this did, which is the invariant that makes this check
  // trustworthy: it is never more permissive than what will be dialled.
  size_t stop = rest.find_first_of("/?#");
  std::string authority = (std::string::npos == stop) ? rest : rest.substr(0, stop);

  // Userinfo is refused outright rather than parsed around, and on https
  // as well as http. At worst it is the attack this whole function exists
  // to stop: `http://localhost:8200@evil.example.com/` is a request to
  // evil.example.com that reads, to anything that splits the authority on
  // ':', as loopback.
  if (std::string::npos != authority.find('@')) {
    throw SekretoError("sekreto: refusing an address with embedded credentials: " +
                       safeaddr(addr));
  }

  // An opening bracket with no closing one is not an address at all.
  if (!authority.empty() && '[' == authority[0] &&
      std::string::npos == authority.find(']')) {
    throw SekretoError("sekreto: not a valid http(s) address: " + safeaddr(addr));
  }

  if ("https://" == scheme) return;

  // A bracketed IPv6 literal keeps its brackets. Splitting the authority
  // on the first colon yields '[', so `http://[::1]:8200` could never
  // match the allowlist below, and a legitimate local vault was refused.
  std::string host = authority;

  if (!authority.empty() && '[' == authority[0]) {
    size_t close = authority.find(']');
    if (std::string::npos != close) host = authority.substr(0, close + 1);
  } else {
    size_t colon = authority.find(':');
    if (std::string::npos != colon) host = authority.substr(0, colon);
  }

  host = asciilower(host);

  // Literal, and exactly these four. Nothing is normalised: `0177.0.0.1`,
  // `2130706433` and `[::ffff:127.0.0.1]` are all refused, because no two
  // URL parsers agree on what they mean.
  if ("localhost" != host && "127.0.0.1" != host && "::1" != host && "[::1]" != host) {
    throw SekretoError("sekreto: refusing to send a token in plaintext to " + safeaddr(addr) +
                       " (use https)");
  }
}

// -------------------------------------------------------------------- http

namespace {

/// One JSON round-trip's result: the status, and the parsed body. An
/// unparsed body is Null, which every accessor reads as "no value".
struct Answer {
  int status = 0;
  Json body;
};

/// One JSON round-trip. Network failure is always an error - an
/// unreachable store is a store that could not answer.
///
/// Redirects are never followed: a vault API does not legitimately
/// redirect, and a followed redirect would carry X-Vault-Token to a host
/// checkaddr never saw, and could downgrade https to http. Proxies are
/// never consulted: the GCP and Azure metadata endpoints are not loopback,
/// and an `http_proxy` in the environment has sent a Vault token in the
/// clear before. Http.cpp does neither, so there is nothing to switch off.
Answer fetchjson(const std::string& method, const std::string& url,
                 const Ordered& headers = Ordered(),
                 const std::optional<std::string>& body = std::nullopt) {
  Response res = httprequest(method, url, headers, body);

  Answer out;
  out.status = res.status;

  bool parsed = Json::parse(res.body, out.body);

  // A success status promised JSON; a body that does not parse means the
  // store could not answer coherently, and treating it as a miss would
  // fall through to a weaker store. Error statuses may carry any body -
  // they are decided on status alone.
  if (200 == res.status && !parsed) {
    throw SekretoError("sekreto: malformed response from " + bareurl(url));
  }

  return out;
}

/// A field's text, or nothing.
std::optional<std::string> textof(const Json& val) {
  std::string out;
  if (!val.text(out)) return std::nullopt;
  return out;
}

// -------------------------------------------------------------- built in

/// Environment variables: `api.token` from `API_TOKEN`.
class EnvProvider : public Provider {
 public:
  EnvProvider(const std::string& prefix, bool injected, const Ordered& source)
      : prefix_(prefix), injected_(injected), source_(source) {}

  std::optional<std::string> lookup(const std::string& name) override {
    std::string key = envkey(name, prefix_);

    if (injected_) return source_.get(key);

    const char* value = std::getenv(key.c_str());
    if (nullptr == value) return std::nullopt;

    return std::string(value);
  }

  std::string describe() const override {
    return prefix_.empty() ? "env" : "env:" + prefix_;
  }

 private:
  std::string prefix_;
  bool injected_;
  Ordered source_;
};

/// A `.env` file, read once, keyed exactly like the environment.
///
/// Loaded LAZILY: a chain may hold a dotenv provider and never be asked
/// anything, and an eager constructor would read whatever `.env` happens
/// to sit in the working directory.
class DotenvProvider : public Provider {
 public:
  DotenvProvider(const std::string& file, const std::string& prefix)
      : file_(file), prefix_(prefix) {}

  std::optional<std::string> lookup(const std::string& name) override {
    load();
    return values_.get(envkey(name, prefix_));
  }

  std::string describe() const override { return "dotenv:" + file_; }

 private:
  void load() {
    if (loaded_) return;

    Readout got = readfile(file_);

    switch (got.state) {
      case Readstate::Text:
        values_ = parsedotenv(got.text);
        break;
      // An absent file - or an absent directory - means "no secrets here",
      // exactly like the file provider.
      case Readstate::Absent:
        values_ = Ordered();
        break;
      case Readstate::Failed:
        throw SekretoError("sekreto: dotenv provider cannot read " + file_ + ": " + got.why);
    }

    loaded_ = true;
  }

  std::string file_;
  std::string prefix_;
  Ordered values_;
  bool loaded_ = false;
};

/// Literal values, keyed like environment variables. The spec uses this to
/// test chain behaviour without touching the outside world.
class MemoryProvider : public Provider {
 public:
  MemoryProvider(const Ordered& values, const std::string& prefix)
      : values_(values), prefix_(prefix) {}

  std::optional<std::string> lookup(const std::string& name) override {
    // An absent key is a miss; the empty string is a HIT.
    return values_.get(envkey(name, prefix_));
  }

  std::string describe() const override {
    return prefix_.empty() ? "memory" : "memory:" + prefix_;
  }

 private:
  Ordered values_;
  std::string prefix_;
};

/// A directory of one-secret-per-file entries, keyed like the environment:
/// `api.token` reads `<dir>/API_TOKEN`.
///
/// This is the shape of a mounted Kubernetes Secret, a Docker or Swarm
/// secret, and a systemd credentials directory, so those all work with no
/// further configuration. Read on EVERY lookup, never cached: a mounted
/// secret is rotated under a running process. One trailing newline is
/// stripped - tools that write these files disagree about it, and a
/// newline is never part of a secret on purpose.
class FileProvider : public Provider {
 public:
  FileProvider(const std::string& dir, const std::string& prefix)
      : dir_(dir), prefix_(prefix) {}

  std::optional<std::string> lookup(const std::string& name) override {
    std::string key = envkey(name, prefix_);
    std::string path = dir_.empty() ? key : trimslash(dir_) + "/" + key;

    Readout got = readfile(path);

    if (Readstate::Absent == got.state) return std::nullopt;

    if (Readstate::Failed == got.state) {
      throw SekretoError("sekreto: file provider cannot read " + path + ": " + got.why);
    }

    std::string body = got.text;

    if (2 <= body.size() && "\r\n" == body.substr(body.size() - 2)) {
      return body.substr(0, body.size() - 2);
    }
    if (!body.empty() && '\n' == body[body.size() - 1]) {
      return body.substr(0, body.size() - 1);
    }

    return body;
  }

  std::string describe() const override { return "file:" + dir_; }

 private:
  std::string dir_;
  std::string prefix_;
};

// ------------------------------------------------------------- hashicorp

/// HashiCorp Vault.
///
/// KV v2 (the default): `api.token` reads `{addr}/v1/{mount}/data/api` and
/// takes the `token` field of `data.data`. KV v1 reads
/// `{addr}/v1/{mount}/api` and takes the field of `data`. A 404 means "not
/// here" - a miss - so a vault can sit in a chain with fallbacks.
///
/// A Vault Enterprise namespace rides X-Vault-Namespace, on logins as well
/// as reads. Instead of being handed a token the provider can log in:
/// Kubernetes auth or AppRole. A failed login is an error, never a miss.
class HashicorpProvider : public Provider {
 public:
  HashicorpProvider(const std::string& addr, const std::string& token,
                    const std::string& mount, const std::optional<int>& kv,
                    const std::string& vaultnamespace, const std::optional<AuthSpec>& auth)
      : addr_(addr),
        mount_(first(mount, "secret")),
        kv_(kv.value_or(2)),
        vaultnamespace_(vaultnamespace),
        auth_(auth) {
    if (!token.empty()) livetoken_ = token;

    // A version typo like kv: 3 must not quietly behave as v2 and turn its
    // 404s into misses; there is nothing safe to assume it meant.
    if (1 != kv_ && 2 != kv_) {
      throw SekretoError("sekreto: hashicorp: unsupported kv version: " +
                         std::to_string(kv_));
    }
  }

  std::optional<std::string> lookup(const std::string& name) override {
    checkaddr(addr_);

    if (!livetoken_.has_value() || nowms() >= renewat_) {
      livetoken_ = login();
    }

    VaultRef ref = vaultref(name);
    std::string base = trimslash(addr_) + "/v1/" + mount_;
    std::string url = (1 == kv_) ? base + "/" + ref.path : base + "/data/" + ref.path;

    Ordered headers = baseheaders();
    headers.set("X-Vault-Token", livetoken_.value_or(""));

    Answer res = fetchjson("GET", url, headers);

    // A 404 is this vault saying it does not hold the secret, so the chain
    // carries on. Anything else it refuses is a store that could not
    // answer.
    if (404 == res.status) return std::nullopt;

    if (200 != res.status) {
      throw SekretoError("sekreto: hashicorp error: " + std::to_string(res.status) + ": " + url);
    }

    Json data = (1 == kv_) ? res.body.get("data") : res.body.get("data").get("data");

    return textof(data.get(ref.field));
  }

  std::string describe() const override { return "hashicorp:" + addr_ + "/" + mount_; }

 private:
  Ordered baseheaders() const {
    Ordered out;
    if (!vaultnamespace_.empty()) out.set("X-Vault-Namespace", vaultnamespace_);
    return out;
  }

  std::string login() {
    if (!auth_.has_value()) {
      throw SekretoError("sekreto: hashicorp: no token and no auth method");
    }

    const AuthSpec& use = auth_.value();
    std::string url = trimslash(addr_) + "/v1/auth/" + first(use.mount, use.method) + "/login";

    Json payload;

    if ("kubernetes" == use.method) {
      std::string jwt = use.jwt;

      if (jwt.empty()) {
        std::string file =
            first(use.jwtfile, "/var/run/secrets/kubernetes.io/serviceaccount/token");

        Readout got = readfile(file);
        if (Readstate::Text != got.state) {
          throw SekretoError("sekreto: hashicorp: cannot read jwt file " + file);
        }

        jwt = trimtext(got.text);
      }

      payload = Json::obj({{"role", Json::str(use.role)}, {"jwt", Json::str(jwt)}});
    } else if ("approle" == use.method) {
      payload = Json::obj({{"role_id", Json::str(use.roleid)},
                           {"secret_id", Json::str(use.secretid)}});
    } else {
      throw SekretoError("sekreto: hashicorp: unknown auth method: " + use.method);
    }

    Answer res = fetchjson("POST", url, baseheaders(), Json::stringify(payload));

    std::optional<std::string> got = textof(res.body.get("auth").get("client_token"));

    if (200 != res.status || !got.has_value() || got.value().empty()) {
      throw SekretoError("sekreto: hashicorp login failed: " + std::to_string(res.status) +
                         ": " + url);
    }

    renewat_ = renewtime(res.body.get("auth").get("lease_duration"));

    return got.value();
  }

  std::string addr_;
  std::string mount_;
  int kv_;
  std::string vaultnamespace_;
  std::optional<AuthSpec> auth_;

  // The working token: a configured token is kept forever, a logged-in one
  // is renewed shortly before its lease runs out.
  std::optional<std::string> livetoken_;
  double renewat_ = NEVER;
};

// ------------------------------------------------------------------ boru

/// A boru vault.
///
/// Two ways in, both boru's own. With no `addr`, the CLI:
/// `boru vault get --reveal <alias>` prints the secret on stdout and
/// nothing else; the passphrase is read by boru itself from
/// BORU_VAULT_PASSPHRASE, is never accepted as config, and never reaches a
/// command line where the process table would publish it.
///
/// With an `addr`, boru's wire protocol: a read-only, HashiCorp-shaped
/// provision API. A boru alias KEEPS its dots, so `api.token` is the
/// single path segment `api.token` - not the `api`/`token` split a
/// HashiCorp KV gets - and the value is the `value` field.
class BoruProvider : public Provider {
 public:
  BoruProvider(const std::string& command, const std::string& namespace_,
               const std::string& home, const std::string& addr, const std::string& token,
               const std::string& mount)
      : command_(first(command, "boru")),
        namespace_(namespace_),
        home_(home),
        addr_(trimslash(addr)),
        token_(token),
        mount_(first(mount, "secret")) {}

  std::optional<std::string> lookup(const std::string& name) override {
    checkname(name);

    if (!addr_.empty()) return wirelookup(name);

    // The CLI alias is namespace-qualified with a COLON; the wire one with
    // a slash. Both are boru's own spellings.
    std::string alias = namespace_.empty() ? name : namespace_ + ":" + name;

    std::vector<std::string> environment = processenv();
    if (!home_.empty()) setenvvar(environment, "BORU_HOME", home_);

    Ran ran = runcmd({command_, "vault", "get", "--reveal", alias}, environment, command_);

    if (0 == ran.status) {
      // boru prints the value and one newline, and nothing else.
      return dropnewline(ran.out);
    }

    // "no alias named" is boru saying it does not hold this secret, which
    // is a miss: the chain carries on. A locked vault or a wrong passphrase
    // is not a miss - treating it as one would fall through to a weaker
    // store without saying so.
    if (borumiss(ran.why)) return std::nullopt;

    throw SekretoError("sekreto: boru vault error: " +
                       (ran.why.empty() ? "exit " + std::to_string(ran.status) : ran.why));
  }

  std::string describe() const override {
    if (!addr_.empty()) return "boru:" + addr_;
    return namespace_.empty() ? "boru" : "boru:" + namespace_;
  }

 private:
  std::optional<std::string> wirelookup(const std::string& name) {
    checkaddr(addr_);

    std::string alias = namespace_.empty() ? name : namespace_ + "/" + name;
    std::string url = addr_ + "/v1/" + mount_ + "/data/" + alias;

    Ordered headers;
    headers.set("X-Vault-Token", token_);

    Answer res = fetchjson("GET", url, headers);

    if (404 == res.status) return std::nullopt;

    if (200 != res.status) {
      throw SekretoError("sekreto: boru serve error: " + std::to_string(res.status) + ": " + url);
    }

    return textof(res.body.get("data").get("data").get("value"));
  }

  std::string command_;
  std::string namespace_;
  std::string home_;
  std::string addr_;
  std::string token_;
  std::string mount_;
};

// ------------------------------------------------------------- secretspec

/// SecretSpec (https://secretspec.dev).
///
/// A declaration - a `secretspec.toml` naming the secrets a project needs
/// - plus a chain of its own backends to satisfy them from. `backend`
/// selects one of those (`--provider`) and is called `backend` here only
/// because `provider` already means something else in this library.
///
/// A reason is required, not optional: SecretSpec records every read in an
/// audit log and refuses to read at all without one.
class SecretspecProvider : public Provider {
 public:
  SecretspecProvider(const std::string& command, const std::string& file,
                     const std::string& profile, const std::string& backend,
                     const std::string& reason, const std::string& prefix)
      : command_(first(command, "secretspec")),
        file_(file),
        profile_(profile),
        backend_(backend),
        reason_(reason),
        prefix_(prefix) {}

  std::optional<std::string> lookup(const std::string& name) override {
    std::string key = envkey(name, prefix_);

    // `--file` comes BEFORE the subcommand; everything else after it.
    std::vector<std::string> argv{command_};
    if (!file_.empty()) {
      argv.push_back("--file");
      argv.push_back(file_);
    }
    argv.push_back("get");
    argv.push_back(key);
    if (!backend_.empty()) {
      argv.push_back("--provider");
      argv.push_back(backend_);
    }
    if (!profile_.empty()) {
      argv.push_back("--profile");
      argv.push_back(profile_);
    }
    argv.push_back("--reason");
    argv.push_back(first(reason_, "sekreto"));

    Ran ran = runcmd(argv, processenv(), command_);

    if (0 == ran.status) {
      // The value and one newline, and nothing else.
      return dropnewline(ran.out);
    }

    if (secretspecmiss(ran.why, key)) return std::nullopt;

    throw SekretoError("sekreto: secretspec error: " +
                       (ran.why.empty() ? "exit " + std::to_string(ran.status) : ran.why));
  }

  std::string describe() const override {
    return backend_.empty() ? "secretspec" : "secretspec:" + backend_;
  }

 private:
  std::string command_;
  std::string file_;
  std::string profile_;
  std::string backend_;
  std::string reason_;
  std::string prefix_;
};

// -------------------------------------------------------------------- aws

/// The `YYYYMMDDTHHMMSSZ` timestamp SigV4 wants, for now. The only place
/// in this port that samples the clock for a signature - `sigv4` itself is
/// pure.
std::string awsnow() {
  std::time_t stamp = std::time(nullptr);
  std::tm parts;
  gmtime_r(&stamp, &parts);

  char buf[32];
  std::strftime(buf, sizeof(buf), "%Y%m%dT%H%M%SZ", &parts);

  return buf;
}

/// Region and credentials, resolved for one call.
struct Awsauth {
  std::string region;
  std::string keyid;
  std::string secret;
  std::string session;
};

/// From config first and the standard AWS_* environment variables second -
/// those are AWS's own convention, and a pod or CI job that has them set
/// should just work. Missing either is an error: an AWS store with no
/// credentials could not answer.
Awsauth awsauth(const std::string& region, const std::string& keyid,
                const std::string& secret, const std::string& session) {
  Awsauth out;

  out.region = first(region, envvar("AWS_REGION"), envvar("AWS_DEFAULT_REGION"));
  out.keyid = first(keyid, envvar("AWS_ACCESS_KEY_ID"));
  out.secret = first(secret, envvar("AWS_SECRET_ACCESS_KEY"));
  out.session = first(session, envvar("AWS_SESSION_TOKEN"));

  if (out.region.empty()) {
    throw SekretoError("sekreto: aws: no region (set region or AWS_REGION)");
  }

  if (out.keyid.empty() || out.secret.empty()) {
    throw SekretoError(
        "sekreto: aws: no credentials"
        " (set keyid/secret or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY)");
  }

  return out;
}

/// One signed call to an AWS JSON-1.1 API.
Answer awscall(const std::string& region, const std::string& keyid,
               const std::string& secret, const std::string& session,
               const std::string& addr, const std::string& service,
               const std::string& target, const std::string& payload) {
  Awsauth auth = awsauth(region, keyid, secret, session);

  // The China partition lives under its own suffix; every other commercial
  // region is plain amazonaws.com.
  bool china = 0 == auth.region.compare(0, 3, "cn-");
  std::string suffix = china ? ".amazonaws.com.cn" : ".amazonaws.com";
  std::string useaddr = first(addr, "https://" + service + "." + auth.region + suffix);

  checkaddr(useaddr);

  std::string url = trimslash(useaddr) + "/";

  Ordered extras;
  extras.set("content-type", "application/x-amz-json-1.1");
  extras.set("x-amz-target", target);

  Signing input;
  input.method = "POST";
  input.url = url;
  input.service = service;
  input.region = auth.region;
  input.keyid = auth.keyid;
  input.secret = auth.secret;
  input.datetime = awsnow();
  input.headers = extras;
  input.body = payload;
  input.session = auth.session;

  Ordered headers = extras;
  for (const auto& entry : sigv4(input).pairs) {
    headers.set(entry.first, entry.second);
  }

  return fetchjson("POST", url, headers, payload);
}

/// Does this AWS error body name one of the not-found types? Those are a
/// miss; every other failure is a store that could not answer. AWS sends
/// `com.amazonaws...#ResourceNotFoundException`, so this is a CONTAINS.
bool awsmiss(const Json& body, const std::string& want) {
  std::string errtype;
  if (!body.get("__type").asstr(errtype)) return false;

  return std::string::npos != errtype.find(want);
}

/// AWS Secrets Manager.
///
/// `api.token` reads the secret named `api` (the vaultref path, so
/// `db.pass.main` reads `db/pass`) and takes the `token` field of its JSON
/// SecretString - the AWS idiom of one JSON map per secret. A SecretString
/// that is not JSON is the value itself, under the conventional field
/// `value`. Requests are SigV4-signed in-tree.
class AwssecretsProvider : public Provider {
 public:
  AwssecretsProvider(const std::string& region, const std::string& keyid,
                     const std::string& secret, const std::string& session,
                     const std::string& addr)
      : region_(region), keyid_(keyid), secret_(secret), session_(session), addr_(addr) {}

  std::optional<std::string> lookup(const std::string& name) override {
    VaultRef ref = vaultref(name);

    Answer res = awscall(region_, keyid_, secret_, session_, addr_, "secretsmanager",
                         "secretsmanager.GetSecretValue",
                         Json::stringify(Json::obj({{"SecretId", Json::str(ref.path)}})));

    if (400 == res.status && awsmiss(res.body, "ResourceNotFoundException")) {
      return std::nullopt;
    }

    if (200 != res.status) {
      throw SekretoError("sekreto: aws secretsmanager error: " + std::to_string(res.status));
    }

    std::string text;

    if (!res.body.get("SecretString").asstr(text)) {
      // A binary secret has no fields to address; only the conventional
      // `value` field can mean "the bytes themselves".
      std::string binary;
      if (!res.body.get("SecretBinary").asstr(binary) || "value" != ref.field) {
        return std::nullopt;
      }

      std::string decoded;
      if (!unbase64(binary, decoded)) {
        throw SekretoError("sekreto: aws secretsmanager: undecodable secret");
      }

      return decoded;
    }

    Json parsed;
    if (Json::parse(text, parsed) && parsed.isobj()) {
      return textof(parsed.get(ref.field));
    }

    // A plain-string secret is the whole value; it has no named fields.
    if ("value" == ref.field) return text;

    return std::nullopt;
  }

  // Config only, never the environment: describe() feeds the spec's
  // sources group, which must answer the same everywhere.
  std::string describe() const override { return "awssecrets:" + region_; }

 private:
  std::string region_;
  std::string keyid_;
  std::string secret_;
  std::string session_;
  std::string addr_;
};

/// AWS SSM Parameter Store.
///
/// `db.pass.main` reads the parameter `/db/pass/main` (under an optional
/// prefix path), decrypted. Parameter Store carries flat strings, so there
/// is no field indirection.
class AwsparamsProvider : public Provider {
 public:
  AwsparamsProvider(const std::string& region, const std::string& keyid,
                    const std::string& secret, const std::string& session,
                    const std::string& addr, const std::string& prefix)
      : region_(region),
        keyid_(keyid),
        secret_(secret),
        session_(session),
        addr_(addr),
        prefix_(prefix) {}

  std::optional<std::string> lookup(const std::string& name) override {
    Json payload = Json::obj({{"Name", Json::str(awsparam(name, prefix_))},
                              {"WithDecryption", Json::boolean(true)}});

    Answer res = awscall(region_, keyid_, secret_, session_, addr_, "ssm",
                         "AmazonSSM.GetParameter", Json::stringify(payload));

    if (400 == res.status && awsmiss(res.body, "ParameterNotFound")) return std::nullopt;

    if (200 != res.status) {
      throw SekretoError("sekreto: aws ssm error: " + std::to_string(res.status));
    }

    return textof(res.body.get("Parameter").get("Value"));
  }

  std::string describe() const override { return "awsparams:" + region_ + prefix_; }

 private:
  std::string region_;
  std::string keyid_;
  std::string secret_;
  std::string session_;
  std::string addr_;
  std::string prefix_;
};

// -------------------------------------------------------------------- gcp

/// GCP Secret Manager.
///
/// `api.token` reads secret `api_token` (dots flattened to `_`; Secret
/// Manager ids have no hierarchy and reject dots), latest version. The
/// token comes from config, then GOOGLE_OAUTH_ACCESS_TOKEN, then the
/// GCE/GKE metadata server - so on Google's own platform no credential
/// configuration is needed at all.
///
/// The metadata call is plain http to a link-local host by platform design
/// and carries no credential, so `checkaddr` guards the Secret Manager
/// address instead.
class GcpsecretsProvider : public Provider {
 public:
  GcpsecretsProvider(const std::string& project, const std::string& token,
                     const std::string& addr, const std::string& metadataaddr)
      : project_(project), token_(token), addr_(addr), metadataaddr_(metadataaddr) {}

  std::optional<std::string> lookup(const std::string& name) override {
    if (project_.empty()) throw SekretoError("sekreto: gcp: no project");

    std::string useaddr = first(addr_, "https://secretmanager.googleapis.com");
    checkaddr(useaddr);

    if (!livetoken_.has_value() || nowms() >= renewat_) {
      livetoken_ = login();
    }

    std::string url = trimslash(useaddr) + "/v1/projects/" + project_ + "/secrets/" +
                      flatname(name, "_") + "/versions/latest:access";

    Ordered headers;
    headers.set("authorization", "Bearer " + livetoken_.value_or(""));

    Answer res = fetchjson("GET", url, headers);

    if (404 == res.status) return std::nullopt;

    if (200 != res.status) {
      throw SekretoError("sekreto: gcp error: " + std::to_string(res.status) + ": " + url);
    }

    std::string data;
    if (!res.body.get("payload").get("data").asstr(data)) return std::nullopt;

    std::string decoded;
    if (!unbase64(data, decoded)) {
      throw SekretoError("sekreto: gcp: undecodable secret");
    }

    return decoded;
  }

  std::string describe() const override { return "gcpsecrets:" + project_; }

 private:
  std::string usemetadataaddr() const {
    if (!metadataaddr_.empty()) return metadataaddr_;

    std::string host = envvar("GCE_METADATA_HOST");
    if (!host.empty()) return "http://" + host;

    return "http://metadata.google.internal";
  }

  std::string login() {
    std::string configured = first(token_, envvar("GOOGLE_OAUTH_ACCESS_TOKEN"));
    if (!configured.empty()) return configured;

    std::string url = trimslash(usemetadataaddr()) +
                      "/computeMetadata/v1/instance/service-accounts/default/token";

    Ordered headers;
    headers.set("Metadata-Flavor", "Google");

    Answer res = fetchjson("GET", url, headers);

    std::optional<std::string> got = textof(res.body.get("access_token"));

    if (200 != res.status || !got.has_value() || got.value().empty()) {
      throw SekretoError("sekreto: gcp: no token and metadata server did not answer");
    }

    renewat_ = renewtime(res.body.get("expires_in"));

    return got.value();
  }

  std::string project_;
  std::string token_;
  std::string addr_;
  std::string metadataaddr_;

  std::optional<std::string> livetoken_;
  double renewat_ = NEVER;
};

// ------------------------------------------------------------------ azure

/// The Key Vault audience an Azure token is minted for.
const char* const AZURERESOURCE = "https://vault.azure.net";

/// Azure Key Vault.
///
/// `api.token` reads secret `api-token` (dots flattened to `-`; Key Vault
/// names allow nothing else), current version. The token comes from
/// config, then a client-credentials login when tenant/clientid/
/// clientsecret are given, then the IMDS managed-identity endpoint.
class AzuresecretsProvider : public Provider {
 public:
  AzuresecretsProvider(const std::string& vault, const std::string& token,
                       const std::string& tenant, const std::string& clientid,
                       const std::string& clientsecret, const std::string& loginaddr,
                       const std::string& imdsaddr, const std::string& apiversion)
      : vault_(vault),
        token_(token),
        tenant_(tenant),
        clientid_(clientid),
        clientsecret_(clientsecret),
        loginaddr_(loginaddr),
        imdsaddr_(imdsaddr),
        apiversion_(apiversion) {}

  std::optional<std::string> lookup(const std::string& name) override {
    if (vault_.empty()) throw SekretoError("sekreto: azure: no vault");

    // Only an explicit scheme is a URL; a vault NAMED httpvault must still
    // become https://httpvault.vault.azure.net.
    bool isurl = 0 == vault_.compare(0, 7, "http://") || 0 == vault_.compare(0, 8, "https://");
    std::string vaulturl = isurl ? vault_ : "https://" + vault_ + ".vault.azure.net";

    checkaddr(vaulturl);

    if (!livetoken_.has_value() || nowms() >= renewat_) {
      livetoken_ = login();
    }

    std::string url = trimslash(vaulturl) + "/secrets/" + flatname(name, "-") +
                      "?api-version=" + first(apiversion_, "7.4");

    Ordered headers;
    headers.set("authorization", "Bearer " + livetoken_.value_or(""));

    Answer res = fetchjson("GET", url, headers);

    if (404 == res.status) return std::nullopt;

    if (200 != res.status) {
      throw SekretoError("sekreto: azure error: " + std::to_string(res.status) + ": " +
                         bareurl(url));
    }

    return textof(res.body.get("value"));
  }

  std::string describe() const override { return "azuresecrets:" + vault_; }

 private:
  std::string login() {
    if (!token_.empty()) return token_;

    if (!tenant_.empty() && !clientid_.empty() && !clientsecret_.empty()) {
      std::string useloginaddr = first(loginaddr_, "https://login.microsoftonline.com");
      checkaddr(useloginaddr);

      std::string url = trimslash(useloginaddr) + "/" + tenant_ + "/oauth2/v2.0/token";
      std::string form = "grant_type=client_credentials&client_id=" + uriescape(clientid_) +
                         "&client_secret=" + uriescape(clientsecret_) +
                         "&scope=" + uriescape(std::string(AZURERESOURCE) + "/.default");

      Ordered headers;
      headers.set("content-type", "application/x-www-form-urlencoded");

      Answer res = fetchjson("POST", url, headers, form);

      std::optional<std::string> got = textof(res.body.get("access_token"));

      if (200 != res.status || !got.has_value() || got.value().empty()) {
        throw SekretoError("sekreto: azure login failed: " + std::to_string(res.status));
      }

      renewat_ = renewtime(res.body.get("expires_in"));

      return got.value();
    }

    std::string imds = trimslash(first(imdsaddr_, "http://169.254.169.254")) +
                       "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=" +
                       uriescape(AZURERESOURCE);

    Ordered headers;
    headers.set("Metadata", "true");

    Answer res = fetchjson("GET", imds, headers);

    std::optional<std::string> got = textof(res.body.get("access_token"));

    if (200 != res.status || !got.has_value() || got.value().empty()) {
      throw SekretoError(
          "sekreto: azure: no token, no client credentials, and IMDS did not answer");
    }

    // IMDS sends expires_in as a STRING, unlike everybody else.
    renewat_ = renewtime(res.body.get("expires_in"));

    return got.value();
  }

  std::string vault_;
  std::string token_;
  std::string tenant_;
  std::string clientid_;
  std::string clientsecret_;
  std::string loginaddr_;
  std::string imdsaddr_;
  std::string apiversion_;

  std::optional<std::string> livetoken_;
  double renewat_ = NEVER;
};

// -------------------------------------------------------------- 1password

/// 1Password, through a Connect server.
///
/// The item titled `api.token` (titles keep their dots), in the named
/// vault. The value is the field with purpose PASSWORD, or the field
/// labelled `value`. A vault that cannot be found is an ERROR - config
/// names it, so its absence is a broken store, not a missing secret.
class OnepasswordProvider : public Provider {
 public:
  OnepasswordProvider(const std::string& addr, const std::string& token,
                      const std::string& vault)
      : addr_(addr), token_(token), vault_(vault) {}

  std::optional<std::string> lookup(const std::string& name) override {
    checkname(name);

    std::string useaddr = trimslash(addr_);
    if (useaddr.empty()) throw SekretoError("sekreto: onepassword: no addr");
    checkaddr(useaddr);

    if (!vaultid_.has_value()) vaultid_ = resolvevault(useaddr);

    std::string id = vaultid_.value();

    std::string filter = uriescape("title eq \"" + name + "\"");
    Answer found =
        fetchjson("GET", useaddr + "/v1/vaults/" + id + "/items?filter=" + filter, auth());

    if (200 != found.status || !found.body.isarr()) {
      throw SekretoError("sekreto: onepassword error: " + std::to_string(found.status) +
                         ": finding " + name);
    }

    if (found.body.arrval.empty()) return std::nullopt;

    std::string itemid = textof(found.body.arrval[0].get("id")).value_or("");
    Answer item =
        fetchjson("GET", useaddr + "/v1/vaults/" + id + "/items/" + itemid, auth());

    if (200 != item.status) {
      throw SekretoError("sekreto: onepassword error: " + std::to_string(item.status) +
                         ": reading " + name);
    }

    Json fields = item.body.get("fields");
    if (!fields.isarr()) return std::nullopt;

    // Two full passes, in order: a password field wins over a field merely
    // labelled `value`.
    for (const Json& field : fields.arrval) {
      std::string purpose;
      if (field.get("purpose").asstr(purpose) && "PASSWORD" == purpose) {
        return textof(field.get("value"));
      }
    }

    for (const Json& field : fields.arrval) {
      std::string label;
      if (field.get("label").asstr(label) && "value" == label) {
        return textof(field.get("value"));
      }
    }

    return std::nullopt;
  }

  std::string describe() const override { return "onepassword:" + vault_; }

 private:
  Ordered auth() const {
    Ordered out;
    out.set("authorization", "Bearer " + token_);
    return out;
  }

  std::string resolvevault(const std::string& useaddr) {
    if (vault_.empty()) throw SekretoError("sekreto: onepassword: no vault");

    Answer res = fetchjson("GET", useaddr + "/v1/vaults", auth());

    if (200 != res.status || !res.body.isarr()) {
      throw SekretoError("sekreto: onepassword error: " + std::to_string(res.status) +
                         ": listing vaults");
    }

    for (const Json& entry : res.body.arrval) {
      std::string id = textof(entry.get("id")).value_or("");
      std::string name = textof(entry.get("name")).value_or("");

      if (vault_ == id || vault_ == name) return id;
    }

    throw SekretoError("sekreto: onepassword: no vault named " + vault_);
  }

  std::string addr_;
  std::string token_;
  std::string vault_;

  std::optional<std::string> vaultid_;
};

// ---------------------------------------------------------------- doppler

/// Doppler.
///
/// The whole config is downloaded once - Doppler's own bulk endpoint - and
/// answered from memory, like a remote .env: `api.token` is the
/// `API_TOKEN` entry. A service token is config-scoped, so project and
/// config are only needed with broader tokens.
class DopplerProvider : public Provider {
 public:
  DopplerProvider(const std::string& token, const std::string& project,
                  const std::string& config, const std::string& addr)
      : token_(token), project_(project), config_(config), addr_(addr) {}

  std::optional<std::string> lookup(const std::string& name) override {
    load();
    // The `prefix` option is deliberately not consulted by this kind.
    return values_.get(envkey(name));
  }

  std::string describe() const override {
    return project_.empty() ? "doppler" : "doppler:" + project_ + "/" + config_;
  }

 private:
  void load() {
    if (loaded_) return;

    std::string useaddr = trimslash(first(addr_, "https://api.doppler.com"));
    checkaddr(useaddr);

    std::string url = useaddr + "/v3/configs/config/secrets/download?format=json";
    if (!project_.empty()) url += "&project=" + uriescape(project_);
    if (!config_.empty()) url += "&config=" + uriescape(config_);

    Ordered headers;
    headers.set("authorization", "Bearer " + token_);

    Answer res = fetchjson("GET", url, headers);

    if (200 != res.status || !res.body.isobj()) {
      throw SekretoError("sekreto: doppler error: " + std::to_string(res.status));
    }

    Ordered values;

    for (const auto& entry : res.body.objval) {
      std::optional<std::string> text = textof(entry.second);
      if (text.has_value()) values.set(entry.first, text.value());
    }

    // Only a successful load is remembered: a failed one retries.
    values_ = values;
    loaded_ = true;
  }

  std::string token_;
  std::string project_;
  std::string config_;
  std::string addr_;

  Ordered values_;
  bool loaded_ = false;
};

// -------------------------------------------------------------- infisical

/// Infisical.
///
/// `api.token` reads the secret keyed `API_TOKEN` (Infisical's own
/// convention is environment-style keys) at a secret path in one
/// environment of a project. Auth is a token, or a universal-auth (machine
/// identity) login with clientid/clientsecret.
class InfisicalProvider : public Provider {
 public:
  InfisicalProvider(const std::string& addr, const std::string& token,
                    const std::string& clientid, const std::string& clientsecret,
                    const std::string& project, const std::string& environment,
                    const std::string& path)
      : addr_(addr),
        token_(token),
        clientid_(clientid),
        clientsecret_(clientsecret),
        project_(project),
        environment_(environment),
        path_(path) {}

  std::optional<std::string> lookup(const std::string& name) override {
    std::string useaddr = trimslash(first(addr_, "https://app.infisical.com"));
    checkaddr(useaddr);

    if (project_.empty() || environment_.empty()) {
      throw SekretoError("sekreto: infisical: no project/environment");
    }

    if (!livetoken_.has_value() || nowms() >= renewat_) {
      livetoken_ = login(useaddr);
    }

    // envkey here takes NO prefix.
    std::string url = useaddr + "/api/v3/secrets/raw/" + envkey(name) +
                      "?workspaceId=" + uriescape(project_) +
                      "&environment=" + uriescape(environment_) +
                      "&secretPath=" + uriescape(first(path_, "/"));

    Ordered headers;
    headers.set("authorization", "Bearer " + livetoken_.value_or(""));

    Answer res = fetchjson("GET", url, headers);

    if (404 == res.status) return std::nullopt;

    if (200 != res.status) {
      throw SekretoError("sekreto: infisical error: " + std::to_string(res.status));
    }

    return textof(res.body.get("secret").get("secretValue"));
  }

  std::string describe() const override {
    return "infisical:" + project_ + "/" + environment_;
  }

 private:
  std::string login(const std::string& useaddr) {
    if (!token_.empty()) return token_;

    if (clientid_.empty() || clientsecret_.empty()) {
      throw SekretoError("sekreto: infisical: no token and no client credentials");
    }

    Json payload = Json::obj({{"clientId", Json::str(clientid_)},
                              {"clientSecret", Json::str(clientsecret_)}});

    Ordered headers;
    headers.set("content-type", "application/json");

    Answer res = fetchjson("POST", useaddr + "/api/v1/auth/universal-auth/login", headers,
                           Json::stringify(payload));

    std::optional<std::string> got = textof(res.body.get("accessToken"));

    if (200 != res.status || !got.has_value() || got.value().empty()) {
      throw SekretoError("sekreto: infisical login failed: " + std::to_string(res.status));
    }

    // camelCase, unlike everyone else's expires_in.
    renewat_ = renewtime(res.body.get("expiresIn"));

    return got.value();
  }

  std::string addr_;
  std::string token_;
  std::string clientid_;
  std::string clientsecret_;
  std::string project_;
  std::string environment_;
  std::string path_;

  std::optional<std::string> livetoken_;
  double renewat_ = NEVER;
};

}  // namespace

bool borumiss(const std::string& why) {
  return std::string::npos != why.find("no alias named");
}

// MATCHED ON THE WHOLE PHRASE, NOT ON "not found". SecretSpec also says
// `Provider backend 'keyring' not found`, which is a store that could not
// answer at all - and reading that as a miss is the worst failure this
// library has, because the chain then falls through to a weaker store
// without saying so. The key is required to appear, so the two cannot be
// confused.
bool secretspecmiss(const std::string& why, const std::string& key) {
  return std::string::npos != why.find("Secret '" + key + "' not found");
}

// ------------------------------------------------------------- the switch

std::shared_ptr<Provider> makeprovider(const ProviderSpec& spec) {
  if ("env" == spec.kind) {
    return std::make_shared<EnvProvider>(spec.prefix, false, Ordered());
  }

  if ("dotenv" == spec.kind) {
    return std::make_shared<DotenvProvider>(first(spec.file, ".env"), spec.prefix);
  }

  if ("memory" == spec.kind) {
    return std::make_shared<MemoryProvider>(spec.values, spec.prefix);
  }

  if ("file" == spec.kind) {
    return std::make_shared<FileProvider>(spec.dir, spec.prefix);
  }

  if ("hashicorp" == spec.kind) {
    return std::make_shared<HashicorpProvider>(spec.addr, spec.token, spec.mount, spec.kv,
                                               spec.vaultnamespace, spec.auth);
  }

  if ("boru" == spec.kind) {
    return std::make_shared<BoruProvider>(spec.command, spec.namespace_, spec.home, spec.addr,
                                          spec.token, spec.mount);
  }

  if ("awssecrets" == spec.kind) {
    return std::make_shared<AwssecretsProvider>(spec.region, spec.keyid, spec.secret,
                                                spec.session, spec.addr);
  }

  if ("awsparams" == spec.kind) {
    return std::make_shared<AwsparamsProvider>(spec.region, spec.keyid, spec.secret,
                                               spec.session, spec.addr, spec.prefix);
  }

  if ("gcpsecrets" == spec.kind) {
    return std::make_shared<GcpsecretsProvider>(spec.project, spec.token, spec.addr,
                                                spec.metadataaddr);
  }

  if ("azuresecrets" == spec.kind) {
    return std::make_shared<AzuresecretsProvider>(spec.vault, spec.token, spec.tenant,
                                                  spec.clientid, spec.clientsecret,
                                                  spec.loginaddr, spec.imdsaddr,
                                                  spec.apiversion);
  }

  if ("onepassword" == spec.kind) {
    return std::make_shared<OnepasswordProvider>(spec.addr, spec.token, spec.vault);
  }

  if ("doppler" == spec.kind) {
    return std::make_shared<DopplerProvider>(spec.token, spec.project, spec.config, spec.addr);
  }

  if ("infisical" == spec.kind) {
    return std::make_shared<InfisicalProvider>(spec.addr, spec.token, spec.clientid,
                                               spec.clientsecret, spec.project,
                                               spec.environment, spec.path);
  }

  if ("secretspec" == spec.kind) {
    return std::make_shared<SecretspecProvider>(spec.command, spec.file, spec.profile,
                                                spec.backend, spec.reason, spec.prefix);
  }

  throw SekretoError("sekreto: unknown provider kind: " + spec.kind);
}

Sekreto makesekreto(const std::vector<ProviderSpec>& specs, bool cache) {
  std::vector<std::shared_ptr<Provider>> providers;
  std::vector<std::string> names;

  for (const ProviderSpec& spec : specs) {
    providers.push_back(makeprovider(spec));
    names.push_back(spec.name);
  }

  return Sekreto(providers, names, cache);
}

}  // namespace sekreto
