// RUN: make test
//
// The TLS obligations, proved in-tree and without a network.
//
// The shared spec cannot reach this: no case in spec/sekreto.json opens a
// socket, and `make integration` speaks plain http to loopback. So a port
// could pass both suites with its certificate checking switched off - and
// a binding that connects without verifying is worse than no TLS, because
// it looks like it works.
//
// Four obligations, and this file pins the two the happy path cannot:
//
//   1. the chain is verified - an untrusted certificate is REFUSED;
//   2. the HOSTNAME is verified SEPARATELY - a certificate that is
//      perfectly valid, and trusted, but issued for another name is
//      REFUSED. This is the half people forget, and neither the spec nor
//      the integration suite has a negative case for it.
//   4. SEKRETO_CA_BUNDLE adds roots additively, and fails open when the
//      path is wrong.
//
// SNI (3) is not observable from inside the client, so it is proved
// against a real server that records the server_name it was sent.
//
// A self-signed certificate is minted here rather than checked in, so
// nothing expires and no key sits in the repository. OpenSSL appears in
// this file because it is what mints the certificate and terminates the
// test server; the library's own binding stays in src/Tls.cpp.

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "Httpjson.hpp"
#include "Sekreto.hpp"

namespace {

int PASSCOUNT = 0;
int FAILCOUNT = 0;

void report(bool ok, const std::string& what, const std::string& detail) {
  if (ok) {
    PASSCOUNT++;
    std::cout << "ok   - " << what << "\n";
  } else {
    FAILCOUNT++;
    std::cout << "FAIL - " << what << "\n      " << detail << "\n";
  }
}

/// A self-signed certificate carrying one subjectAltName, and its key.
struct Ident {
  EVP_PKEY* key = nullptr;
  X509* cert = nullptr;

  ~Ident() {
    if (nullptr != cert) X509_free(cert);
    if (nullptr != key) EVP_PKEY_free(key);
  }
};

bool mint(Ident& out, const std::string& subject, const std::string& san) {
  out.key = EVP_RSA_gen(2048);
  if (nullptr == out.key) return false;

  out.cert = X509_new();
  if (nullptr == out.cert) return false;

  X509_set_version(out.cert, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(out.cert), 1);
  X509_gmtime_adj(X509_getm_notBefore(out.cert), -3600);
  X509_gmtime_adj(X509_getm_notAfter(out.cert), 3600);
  X509_set_pubkey(out.cert, out.key);

  X509_NAME* name = X509_get_subject_name(out.cert);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                             reinterpret_cast<const unsigned char*>(subject.c_str()), -1, -1,
                             0);
  X509_set_issuer_name(out.cert, name);

  X509_EXTENSION* ext =
      X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name, const_cast<char*>(san.c_str()));
  if (nullptr == ext) return false;
  X509_add_ext(out.cert, ext, -1);
  X509_EXTENSION_free(ext);

  X509_EXTENSION* basic = X509V3_EXT_conf_nid(nullptr, nullptr, NID_basic_constraints,
                                              const_cast<char*>("critical,CA:TRUE"));
  if (nullptr != basic) {
    X509_add_ext(out.cert, basic, -1);
    X509_EXTENSION_free(basic);
  }

  return 0 < X509_sign(out.cert, out.key, EVP_sha256());
}

bool writepem(const Ident& ident, const std::string& path) {
  FILE* handle = std::fopen(path.c_str(), "wb");
  if (nullptr == handle) return false;

  bool ok = 0 != PEM_write_X509(handle, ident.cert);
  std::fclose(handle);

  return ok;
}

/// A TLS server that answers exactly one request, then stops.
class Onceserver {
 public:
  explicit Onceserver(Ident& ident) {
    ctx_ = SSL_CTX_new(TLS_server_method());
    SSL_CTX_use_certificate(ctx_, ident.cert);
    SSL_CTX_use_PrivateKey(ctx_, ident.key);

    listener_ = socket(AF_INET, SOCK_STREAM, 0);

    int reuse = 1;
    setsockopt(listener_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    sockaddr_in where;
    memset(&where, 0, sizeof(where));
    where.sin_family = AF_INET;
    where.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    where.sin_port = 0;

    bind(listener_, reinterpret_cast<sockaddr*>(&where), sizeof(where));
    listen(listener_, 4);

    socklen_t size = sizeof(where);
    getsockname(listener_, reinterpret_cast<sockaddr*>(&where), &size);
    port_ = ntohs(where.sin_port);

    worker_ = std::thread([this] { serve(); });
  }

  ~Onceserver() {
    if (worker_.joinable()) worker_.join();
    if (0 <= listener_) ::close(listener_);
    if (nullptr != ctx_) SSL_CTX_free(ctx_);
  }

  Onceserver(const Onceserver&) = delete;
  Onceserver& operator=(const Onceserver&) = delete;

  int port() const { return port_; }

 private:
  void serve() {
    int fd = accept(listener_, nullptr, nullptr);
    if (0 > fd) return;

    SSL* ssl = SSL_new(ctx_);
    SSL_set_fd(ssl, fd);

    // A client that refuses the certificate aborts here, which is the
    // outcome half these cases are asserting.
    if (1 == SSL_accept(ssl)) {
      char buf[4096];
      SSL_read(ssl, buf, sizeof(buf));

      const char* answer =
          "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
          "Connection: close\r\n\r\n{\"ok\":true}";
      SSL_write(ssl, answer, static_cast<int>(strlen(answer)));
      SSL_shutdown(ssl);
    }

    SSL_free(ssl);
    ::close(fd);
  }

  SSL_CTX* ctx_ = nullptr;
  int listener_ = -1;
  int port_ = 0;
  std::thread worker_;
};

/// Reach the server, and say what happened.
struct Outcome {
  bool reached = false;
  std::string why;
};

Outcome reach(int port) {
  std::string url = "https://127.0.0.1:" + std::to_string(port) + "/v1/secret/data/api";

  try {
    sekreto::Response res = sekreto::httprequest("GET", url, sekreto::Ordered(), std::nullopt);
    return Outcome{200 == res.status, "status " + std::to_string(res.status)};
  } catch (const std::exception& err) {
    return Outcome{false, err.what()};
  }
}

bool says(const std::string& text, const std::string& want) {
  return std::string::npos != text.find(want);
}

/// Refused because the CHAIN did not verify - a self-signed leaf and an
/// unknown issuer are the same refusal - and NOT because of the name.
bool chainrefused(const std::string& why) {
  return says(why, "certificate verify failed") && !says(why, "mismatch");
}

}  // namespace

int main() {
  std::string bundle = "/tmp/sekreto-cpp-tlstest.pem";

  // (2) A certificate that is trusted, unexpired and correctly signed -
  // and issued for a DIFFERENT host. Only the hostname check refuses it.
  {
    Ident wrong;
    if (!mint(wrong, "other.example", "DNS:other.example")) {
      std::cout << "FAIL - mint a certificate for the wrong host\n";
      return 1;
    }
    writepem(wrong, bundle);
    setenv("SEKRETO_CA_BUNDLE", bundle.c_str(), 1);

    Onceserver server(wrong);
    Outcome got = reach(server.port());

    report(!got.reached && says(got.why, "IP address mismatch"),
           "a trusted certificate for another host is refused", got.why);
  }

  // (1) The chain. The same certificate, with nothing naming it as a
  // trust root: refused for a different reason, which is what proves
  // verification is switched on rather than merely configured.
  {
    Ident stranger;
    if (!mint(stranger, "127.0.0.1", "IP:127.0.0.1")) {
      std::cout << "FAIL - mint an untrusted certificate\n";
      return 1;
    }
    unsetenv("SEKRETO_CA_BUNDLE");

    Onceserver server(stranger);
    Outcome got = reach(server.port());

    report(!got.reached && chainrefused(got.why), "an untrusted certificate is refused",
           got.why);
  }

  // (4) The same certificate again, named by SEKRETO_CA_BUNDLE: accepted.
  // Nothing else changed, so the bundle is what made the difference.
  {
    Ident trusted;
    if (!mint(trusted, "127.0.0.1", "IP:127.0.0.1")) {
      std::cout << "FAIL - mint a trusted certificate\n";
      return 1;
    }
    writepem(trusted, bundle);
    setenv("SEKRETO_CA_BUNDLE", bundle.c_str(), 1);

    Onceserver server(trusted);
    Outcome got = reach(server.port());

    report(got.reached, "SEKRETO_CA_BUNDLE adds a private root", got.why);
  }

  // (4) A path that names nothing fails OPEN and silently: no raise, no
  // extra roots, and the connection is refused exactly as it would be
  // with no variable set at all.
  {
    Ident stranger;
    if (!mint(stranger, "127.0.0.1", "IP:127.0.0.1")) {
      std::cout << "FAIL - mint an untrusted certificate\n";
      return 1;
    }
    setenv("SEKRETO_CA_BUNDLE", "/nonexistent/sekreto-no-such-bundle.pem", 1);

    Onceserver server(stranger);
    Outcome got = reach(server.port());

    report(!got.reached && chainrefused(got.why),
           "an unreadable SEKRETO_CA_BUNDLE fails open", got.why);
  }

  // The in-tree PEM scanner the bundle is read with.
  {
    Ident one;
    mint(one, "127.0.0.1", "IP:127.0.0.1");
    writepem(one, bundle);

    std::ifstream handle(bundle);
    std::string text((std::istreambuf_iterator<char>(handle)),
                     std::istreambuf_iterator<char>());

    std::vector<std::string> certs = sekreto::pemcerts(text + text);

    report(2 == certs.size() && !certs[0].empty() && certs[0] == certs[1],
           "pemcerts reads every certificate in a bundle",
           "found " + std::to_string(certs.size()));
  }

  std::remove(bundle.c_str());

  std::cout << "\n" << PASSCOUNT << " passed, " << FAILCOUNT << " failed\n";

  return 0 == FAILCOUNT ? 0 : 1;
}
