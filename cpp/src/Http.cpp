#include "Http.hpp"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <chrono>
#include <cstdlib>
#include <vector>

#include "Crypto.hpp"
#include "Tls.hpp"

namespace sekreto {

const int TIMEOUT = 10;
const size_t MAXBODY = 8 * 1024 * 1024;
const char* const CABUNDLE = "SEKRETO_CA_BUNDLE";

std::string bareurl(const std::string& url) {
  size_t at = url.find('?');
  return (std::string::npos == at) ? url : url.substr(0, at);
}

namespace {

SekretoError unreachable(const std::string& url, const std::string& why) {
  return SekretoError("sekreto: cannot reach " + bareurl(url) + ": " + why);
}

std::string oserror() {
  return strerror(errno);
}

/// A url split into the parts a request needs.
struct Target {
  /// The BARE host: what is connected to, and what the certificate is
  /// checked against. An IPv6 literal appears here without brackets.
  std::string host;
  /// The authority as it goes in `Host:`. An IPv6 literal KEEPS its
  /// brackets, because `Host: 2001:db8::1:8200` is not a valid authority
  /// and an intermediary may reject or misroute it.
  std::string authority;
  int port = 0;
  int defaultport = 0;
  std::string path;
  bool tls = false;
};

Target split(const std::string& url) {
  Target out;
  std::string rest;

  if (0 == url.compare(0, 8, "https://")) {
    out.tls = true;
    out.defaultport = 443;
    rest = url.substr(8);
  } else if (0 == url.compare(0, 7, "http://")) {
    out.tls = false;
    out.defaultport = 80;
    rest = url.substr(7);
  } else {
    throw SekretoError("sekreto: not an http url: " + bareurl(url));
  }

  std::string authority = rest;
  out.path = "/";

  size_t at = rest.find('/');
  if (std::string::npos != at) {
    authority = rest.substr(0, at);
    out.path = rest.substr(at);
  }

  out.port = out.defaultport;
  std::string host = authority;

  // A REVERSE search for the colon, so an IPv6 literal's own colons are
  // not read as a port separator.
  size_t colon = authority.rfind(':');
  if (std::string::npos != colon && colon + 1 < authority.size() &&
      ']' != authority[authority.size() - 1]) {
    host = authority.substr(0, colon);
    out.port = std::atoi(authority.c_str() + colon + 1);
    if (0 >= out.port || 65535 < out.port) {
      throw SekretoError("sekreto: bad port: " + bareurl(url));
    }
  }

  std::string bare = host;
  if (!bare.empty() && '[' == bare[0]) bare = bare.substr(1);
  if (!bare.empty() && ']' == bare[bare.size() - 1]) bare = bare.substr(0, bare.size() - 1);

  out.host = bare;
  // Re-bracketed only if it really is an IPv6 literal.
  out.authority = (std::string::npos != bare.find(':')) ? "[" + bare + "]" : bare;

  return out;
}

long nowms() {
  return static_cast<long>(std::chrono::duration_cast<std::chrono::milliseconds>(
                               std::chrono::steady_clock::now().time_since_epoch())
                               .count());
}

/// Connect, under ONE deadline across every resolved address.
///
/// A name commonly resolves to several - a dual-stack host answers with
/// both an A and an AAAA - and giving each the full ten seconds would make
/// the real bound ten seconds times however many addresses the name cares
/// to return, which is not a bound at all when the name is the attacker's.
/// Each attempt gets what is left of the one deadline.
///
/// A blocking `connect` has no bound of its own: against an address that
/// swallows SYNs the kernel retries for a little over two minutes on
/// Linux. So the socket is made non-blocking and `poll` carries the
/// deadline.
int connectto(const Target& target, const std::string& url) {
  addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  char service[16];
  snprintf(service, sizeof(service), "%d", target.port);

  addrinfo* found = nullptr;
  int code = getaddrinfo(target.host.c_str(), service, &hints, &found);

  if (0 != code || nullptr == found) {
    throw unreachable(url, gai_strerror(code));
  }

  long deadline = nowms() + TIMEOUT * 1000;
  std::string last = "no address";

  for (addrinfo* step = found; nullptr != step; step = step->ai_next) {
    long left = deadline - nowms();
    if (0 >= left) {
      last = "timed out";
      break;
    }

    int fd = socket(step->ai_family, step->ai_socktype, step->ai_protocol);
    if (0 > fd) {
      last = oserror();
      continue;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    bool ok = false;

    if (0 == connect(fd, step->ai_addr, step->ai_addrlen)) {
      ok = true;
    } else if (EINPROGRESS == errno) {
      pollfd waiting;
      waiting.fd = fd;
      waiting.events = POLLOUT;
      waiting.revents = 0;

      int ready = poll(&waiting, 1, static_cast<int>(left));

      if (0 < ready) {
        int problem = 0;
        socklen_t size = sizeof(problem);
        if (0 == getsockopt(fd, SOL_SOCKET, SO_ERROR, &problem, &size) && 0 == problem) {
          ok = true;
        } else {
          errno = problem;
          last = 0 == problem ? "connection failed" : oserror();
        }
      } else if (0 == ready) {
        last = "timed out";
      } else {
        last = oserror();
      }
    } else {
      last = oserror();
    }

    if (ok) {
      fcntl(fd, F_SETFL, flags);

      // A write blocks too, once the peer's receive window fills and it
      // stops reading, so both directions are bounded.
      timeval bound;
      bound.tv_sec = TIMEOUT;
      bound.tv_usec = 0;
      setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &bound, sizeof(bound));
      setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &bound, sizeof(bound));

      freeaddrinfo(found);
      return fd;
    }

    ::close(fd);
  }

  freeaddrinfo(found);
  throw unreachable(url, last);
}

class Plainstream : public Stream {
 public:
  Plainstream(int fd, const std::string& url) : fd_(fd), url_(url) {}

  ~Plainstream() override {
    if (0 <= fd_) ::close(fd_);
  }

  Plainstream(const Plainstream&) = delete;
  Plainstream& operator=(const Plainstream&) = delete;

  size_t readsome(char* buf, size_t len) override {
    while (true) {
      ssize_t got = ::read(fd_, buf, len);

      if (0 <= got) return static_cast<size_t>(got);
      if (EINTR == errno) continue;

      throw unreachable(url_, oserror());
    }
  }

  void writeall(const char* buf, size_t len) override {
    size_t sent = 0;

    while (sent < len) {
      ssize_t put = ::write(fd_, buf + sent, len - sent);

      if (0 > put) {
        if (EINTR == errno) continue;
        throw unreachable(url_, oserror());
      }

      sent += static_cast<size_t>(put);
    }
  }

 private:
  int fd_;
  std::string url_;
};

/// Join a chunked body back together.
///
/// Each chunk is a hex length (any `;`-separated extensions ignored), a
/// CRLF, that many BYTES, and a CRLF. A zero length ends the body and any
/// trailer is ignored.
///
/// Bytes, not characters: a chunk length counts bytes and a boundary may
/// fall inside a multibyte character, so a secret with any non-ASCII
/// character in it would otherwise come back mangled.
bool dechunk(const std::string& raw, std::string& out) {
  size_t pos = 0;

  while (true) {
    size_t at = raw.find("\r\n", pos);
    if (std::string::npos == at) return false;

    std::string header = raw.substr(pos, at - pos);
    size_t semi = header.find(';');
    if (std::string::npos != semi) header = header.substr(0, semi);

    char* stop = nullptr;
    long size = std::strtol(header.c_str(), &stop, 16);
    if (nullptr == stop || 0 > size) return false;

    size_t body = at + 2;

    if (0 == size) return true;

    if (raw.size() < body + static_cast<size_t>(size)) return false;

    out += raw.substr(body, static_cast<size_t>(size));

    pos = body + static_cast<size_t>(size) + 2;
    if (raw.size() < pos) return false;
  }
}

}  // namespace

std::vector<std::string> pemcerts(const std::string& text) {
  static const std::string OPEN = "-----BEGIN CERTIFICATE-----";
  static const std::string CLOSE = "-----END CERTIFICATE-----";

  std::vector<std::string> out;
  size_t pos = 0;

  while (true) {
    size_t start = text.find(OPEN, pos);
    if (std::string::npos == start) break;

    size_t from = start + OPEN.size();
    size_t stop = text.find(CLOSE, from);
    if (std::string::npos == stop) break;

    std::string der;
    if (unbase64(text.substr(from, stop - from), der)) out.push_back(der);

    pos = stop + CLOSE.size();
  }

  return out;
}

Response httprequest(const std::string& method, const std::string& url,
                     const Ordered& headers, const std::optional<std::string>& body) {
  Target target = split(url);

  int fd = connectto(target, url);

  std::unique_ptr<Stream> stream;

  if (target.tls) {
    // Ownership of the socket passes to the TLS stream, which closes it.
    stream = tlsstream(fd, target.host, url);
  } else {
    stream.reset(new Plainstream(fd, url));
  }

  // A default port stays implicit in `Host:`, the way a URL normalises it:
  // a SigV4 signature covers `host`, and `Host: x:443` is not what was
  // signed.
  std::string hostheader = target.authority;
  if (target.port != target.defaultport) {
    hostheader += ":" + std::to_string(target.port);
  }

  std::string request = method + " " + target.path + " HTTP/1.1\r\n";
  request += "Host: " + hostheader + "\r\n";
  request += "Accept: application/json\r\n";
  request += "Connection: close\r\n";

  for (const auto& entry : headers.pairs) {
    request += entry.first + ": " + entry.second + "\r\n";
  }

  if (body.has_value()) {
    request += "Content-Length: " + std::to_string(body.value().size()) + "\r\n";
  }

  request += "\r\n";

  if (body.has_value()) request += body.value();

  stream->writeall(request.data(), request.size());

  // Bounded, never read-to-end: an endless body would otherwise be
  // accumulated in memory until the read timeout, which on a loopback or
  // datacentre link is gigabytes. One byte over the bound is enough to
  // know it was exceeded.
  std::string raw;
  char buf[16384];

  while (raw.size() <= MAXBODY) {
    size_t got = stream->readsome(buf, sizeof(buf));
    if (0 == got) break;
    raw.append(buf, got);
  }

  // An endless body is a store that could not answer, so this is an error
  // and never a miss - the latter would fall through to a weaker store on
  // an attacker's cue.
  if (MAXBODY < raw.size()) {
    throw SekretoError("sekreto: oversized response from " + bareurl(url));
  }

  size_t split_at = raw.find("\r\n\r\n");
  if (std::string::npos == split_at) {
    throw SekretoError("sekreto: malformed response from " + bareurl(url));
  }

  // Headers are ASCII; the body is not necessarily, so it stays bytes
  // until every length-counted slice has been taken.
  std::string head = raw.substr(0, split_at);
  std::string rawbody = raw.substr(split_at + 4);

  // "HTTP/1.1 200 OK" - the second whitespace-separated field is the
  // status.
  size_t endline = head.find("\r\n");
  std::string statusline = (std::string::npos == endline) ? head : head.substr(0, endline);

  size_t firstspace = statusline.find(' ');
  if (std::string::npos == firstspace) {
    throw SekretoError("sekreto: malformed response from " + bareurl(url));
  }

  Response out;
  out.status = std::atoi(statusline.c_str() + firstspace + 1);

  if (0 == out.status) {
    throw SekretoError("sekreto: malformed response from " + bareurl(url));
  }

  // A server that does not know the body length up front sends it in
  // chunks - which is what a vault answering from a store usually does.
  bool chunked = false;
  size_t pos = (std::string::npos == endline) ? head.size() : endline + 2;

  while (pos < head.size()) {
    size_t stop = head.find("\r\n", pos);
    std::string line =
        (std::string::npos == stop) ? head.substr(pos) : head.substr(pos, stop - pos);

    size_t colon = line.find(':');
    if (std::string::npos != colon) {
      std::string name = asciilower(line.substr(0, colon));
      std::string value = asciilower(line.substr(colon + 1));
      if ("transfer-encoding" == name && std::string::npos != value.find("chunked")) {
        chunked = true;
      }
    }

    if (std::string::npos == stop) break;
    pos = stop + 2;
  }

  if (chunked) {
    std::string joined;
    if (!dechunk(rawbody, joined)) {
      throw SekretoError("sekreto: malformed response from " + bareurl(url));
    }
    out.body = joined;
  } else {
    out.body = rawbody;
  }

  return out;
}

}  // namespace sekreto
