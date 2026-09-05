// Just enough HTTP to ask a vault for a secret.
//
// C++ has no HTTP client in its standard library, so this speaks HTTP/1.1
// over a POSIX socket directly: a request with headers and an optional
// body, a status line, and a response body delimited by Content-Length, by
// chunks, or by the connection closing.
//
// The framing is in-tree deliberately. libcurl and cpp-httplib would both
// supply it, and both are HTTP clients rather than cryptographic transport
// - the one thing the dependency rule permits. So only the TLS half is
// bound out, and it is bound in Tls.cpp and nowhere else.
//
// It is not a general-purpose client: no redirect following, no
// keep-alive, no proxies, no client certificates. Each of those absences
// is load-bearing and the reasons are at their call sites.
//
// A port of rust/src/http.rs.

#ifndef SEKRETO_HTTP_HPP
#define SEKRETO_HTTP_HPP

#include <memory>
#include <optional>
#include <string>

#include "Sekreto.hpp"

namespace sekreto {

/// How long any single round-trip may take before the store is treated as
/// unreachable. Ports carry the same bound.
extern const int TIMEOUT;

/// How much of a response body will be read before the store is treated as
/// having answered incoherently. Ports carry the same bound.
///
/// Far above anything real - the largest legitimate payload this library
/// fetches is Doppler's whole-config download, measured in kilobytes. A
/// bound is needed because the timeout is not one: ten seconds on a
/// loopback or datacentre link is gigabytes, and the body is accumulated
/// in memory before it is parsed. This runs on an application's startup
/// path, so the failure is the application never starting.
extern const size_t MAXBODY;

/// The environment variable naming extra trust roots, as a PEM bundle.
/// One cross-port spelling, so a private CA is configured the same way
/// whichever port an application uses.
extern const char* const CABUNDLE;

/// Anything a request can run over: a plain socket, or a TLS session
/// wrapping one. Failure is a thrown SekretoError; `readsome` answers 0
/// at end of stream.
class Stream {
 public:
  virtual ~Stream() = default;
  virtual size_t readsome(char* buf, size_t len) = 0;
  virtual void writeall(const char* buf, size_t len) = 0;
};

/// What a vault answered: the status code and the raw body.
struct Response {
  int status = 0;
  std::string body;
};

/// A url without its query string, for a message that must not leak one.
///
/// A query here carries the vault path, the secret name or a filter -
/// `secretPath=/prod/payments/stripe` - which belongs in neither a log nor
/// a stack trace.
std::string bareurl(const std::string& url);

/// One HTTP exchange. A non-2xx status is RETURNED, not raised: a 404 from
/// a vault means "no such secret", which is a miss rather than a failure.
/// Only a transport failure raises.
Response httprequest(const std::string& method, const std::string& url,
                     const Ordered& headers, const std::optional<std::string>& body);

/// Extract every certificate from a PEM bundle, as DER blocks.
///
/// In-tree, per the rule: the TLS exception covers transport, and reading
/// a text file is not transport. No header handling, no attributes, no
/// other label types, no private keys.
std::vector<std::string> pemcerts(const std::string& text);

}  // namespace sekreto

#endif
