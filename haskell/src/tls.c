/* The transport binding: TCP sockets, and TLS through OpenSSL.
 *
 * THIS IS THE ONLY FILE IN THE PORT THAT NAMES OPENSSL, and the only one
 * that names a socket. Everything above it - HTTP framing, JSON, base64,
 * SHA-256, HMAC, PEM-free trust configuration - is Haskell, in-tree.
 *
 * GHC's boot libraries have no networking at all, not even a socket, so
 * both halves of the transport have to come from C. `network` is not a
 * boot library and is not cryptographic transport, so it is not covered
 * by the rule that allows this file to exist; libc and OpenSSL are.
 *
 * Audit surface: `-lssl -lcrypto`, so the distribution's OpenSSL. This
 * file is compiled from source by the port's own Makefile - no package
 * index is involved - and it adds no code of its own to the handshake.
 *
 * Four obligations, all met here and nowhere else:
 *
 *   1. the chain is verified against the system trust store
 *      (SSL_CTX_set_default_verify_paths + SSL_VERIFY_PEER, checked again
 *      afterwards with SSL_get_verify_result and a peer-certificate test);
 *   2. the HOSTNAME is verified, which is a separate step - by DNS name
 *      with SSL_set1_host, or by iPAddress SAN with
 *      X509_VERIFY_PARAM_set1_ip_asc when the host is an IP literal;
 *   3. SNI is sent, for names only - RFC 6066 forbids it for an IP;
 *   4. SEKRETO_CA_BUNDLE adds roots, ADDITIVELY, and fails open.
 */

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

/* Milliseconds on a monotonic-enough clock, for the connect deadline. */
static long nowms(void) {
  struct timeval at;
  gettimeofday(&at, NULL);
  return (long)at.tv_sec * 1000L + (long)at.tv_usec / 1000L;
}

static void say(char *err, int errlen, const char *text) {
  if (NULL == err || 0 >= errlen) {
    return;
  }
  snprintf(err, (size_t)errlen, "%s", text);
}

/* The newest thing OpenSSL has to say, or a fallback. A handshake that
 * fails verification says WHICH check failed, and that is the difference
 * between "the certificate is not trusted" and "the name does not match". */
static void saysslerr(char *err, int errlen, const char *fallback) {
  unsigned long code = ERR_peek_last_error();

  if (0 == code) {
    say(err, errlen, fallback);
    return;
  }

  char buf[256];
  ERR_error_string_n(code, buf, sizeof buf);
  say(err, errlen, buf);
}

/* Read and write bounds, matched to the ten-second round-trip bound the
 * ports share. Set on the socket itself so they hold for TLS too: SSL_read
 * ultimately calls recv on this descriptor. */
static void setdeadlines(int fd, int ms) {
  struct timeval bound;
  bound.tv_sec = ms / 1000;
  bound.tv_usec = (ms % 1000) * 1000;

  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &bound, sizeof bound);
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &bound, sizeof bound);
}

/* One attempt at one resolved address, bounded by what is left of the
 * shared deadline. Non-blocking connect plus poll, because a blocking
 * connect has no bound: against an address that swallows SYNs the kernel
 * retries for over two minutes. */
static int dial(struct addrinfo *at, int leftms) {
  int fd = socket(at->ai_family, at->ai_socktype, at->ai_protocol);
  if (0 > fd) {
    return -1;
  }

  int flags = fcntl(fd, F_GETFL, 0);
  if (0 > flags || 0 > fcntl(fd, F_SETFL, flags | O_NONBLOCK)) {
    close(fd);
    return -1;
  }

  if (0 == connect(fd, at->ai_addr, at->ai_addrlen)) {
    fcntl(fd, F_SETFL, flags);
    return fd;
  }

  if (EINPROGRESS != errno) {
    close(fd);
    return -1;
  }

  struct pollfd waiting;
  waiting.fd = fd;
  waiting.events = POLLOUT;
  waiting.revents = 0;

  int ready = poll(&waiting, 1, leftms);
  if (1 != ready) {
    close(fd);
    errno = (0 == ready) ? ETIMEDOUT : errno;
    return -1;
  }

  int failure = 0;
  socklen_t failurelen = sizeof failure;
  if (0 > getsockopt(fd, SOL_SOCKET, SO_ERROR, &failure, &failurelen) || 0 != failure) {
    close(fd);
    errno = failure;
    return -1;
  }

  fcntl(fd, F_SETFL, flags);
  return fd;
}

/* Connect to host:port, giving up after budgetms.
 *
 * The bound is on the WHOLE attempt, not on each address. A name commonly
 * resolves to several - a dual-stack host answers with both an A and an
 * AAAA - and giving each the full budget would make the real bound the
 * budget times however many addresses the name cares to return, which is
 * not a bound at all when the name is the attacker's. */
int sekreto_connect(const char *host, const char *port, int budgetms, char *err, int errlen) {
  struct addrinfo hints;
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  struct addrinfo *found = NULL;
  int code = getaddrinfo(host, port, &hints, &found);
  if (0 != code) {
    say(err, errlen, gai_strerror(code));
    return -1;
  }

  long start = nowms();
  int last = 0;
  int fd = -1;

  for (struct addrinfo *at = found; NULL != at; at = at->ai_next) {
    long left = (long)budgetms - (nowms() - start);
    if (0 >= left) {
      last = ETIMEDOUT;
      break;
    }

    fd = dial(at, (int)left);
    if (0 <= fd) {
      break;
    }
    last = errno;
  }

  freeaddrinfo(found);

  if (0 > fd) {
    say(err, errlen, 0 == last ? "no address" : strerror(last));
    return -1;
  }

  setdeadlines(fd, budgetms);
  return fd;
}

void sekreto_close(int fd) {
  if (0 <= fd) {
    close(fd);
  }
}

/* Plaintext write. Returns the count written, or -1. */
int sekreto_send(int fd, const char *buf, int len) {
  ssize_t wrote = send(fd, buf, (size_t)len, MSG_NOSIGNAL);
  return (int)wrote;
}

/* Plaintext read. Returns the count read, 0 at end of stream, or -1. */
int sekreto_recv(int fd, char *buf, int len) {
  ssize_t got = recv(fd, buf, (size_t)len, 0);
  return (int)got;
}

/* The last errno, so a failed read or write can say why. */
const char *sekreto_why(void) { return strerror(errno); }

typedef struct {
  SSL_CTX *ctx;
  SSL *ssl;
} sekreto_tls;

void sekreto_tls_free(void *handle) {
  sekreto_tls *conn = (sekreto_tls *)handle;
  if (NULL == conn) {
    return;
  }
  if (NULL != conn->ssl) {
    SSL_free(conn->ssl);
  }
  if (NULL != conn->ctx) {
    SSL_CTX_free(conn->ctx);
  }
  free(conn);
}

/* Hand an already-connected descriptor to OpenSSL and complete the
 * handshake, verifying the chain AND the name. NULL on any failure, with
 * the reason in err - a handshake that could not be verified is a refusal
 * to talk to this server, never a missing secret.
 *
 * cabundle may be NULL or empty. When it names a file, its roots are added
 * to the system ones rather than replacing them, and an unreadable file or
 * an unparseable certificate is discarded silently: a wrong path adds no
 * roots and weakens nothing. */
void *sekreto_tls_connect(int fd, const char *host, const char *cabundle, char *err, int errlen) {
  sekreto_tls *conn = calloc(1, sizeof *conn);
  if (NULL == conn) {
    say(err, errlen, "out of memory");
    return NULL;
  }

  conn->ctx = SSL_CTX_new(TLS_client_method());
  if (NULL == conn->ctx) {
    saysslerr(err, errlen, "cannot create a TLS context");
    sekreto_tls_free(conn);
    return NULL;
  }

  /* (1) The chain, against the system trust store. A NULL callback means a
   * verification failure aborts the handshake rather than being reported
   * and ignored. set_default_verify_paths also honours SSL_CERT_FILE and
   * SSL_CERT_DIR, which is how the distribution points at its own store. */
  SSL_CTX_set_verify(conn->ctx, SSL_VERIFY_PEER, NULL);
  SSL_CTX_set_min_proto_version(conn->ctx, TLS1_2_VERSION);

  if (1 != SSL_CTX_set_default_verify_paths(conn->ctx)) {
    saysslerr(err, errlen, "cannot load the system trust store");
    sekreto_tls_free(conn);
    return NULL;
  }

  /* (4) SEKRETO_CA_BUNDLE, additive and failing open. */
  if (NULL != cabundle && '\0' != *cabundle) {
    if (1 != SSL_CTX_load_verify_locations(conn->ctx, cabundle, NULL)) {
      ERR_clear_error();
    }
  }

  conn->ssl = SSL_new(conn->ctx);
  if (NULL == conn->ssl) {
    saysslerr(err, errlen, "cannot create a TLS connection");
    sekreto_tls_free(conn);
    return NULL;
  }

  /* (2) The hostname, which chain verification does NOT cover.
   *
   * An IP literal and a DNS name are checked against different fields of
   * the certificate: SSL_set1_host matches dNSName SANs and the common
   * name, and will never match an iPAddress SAN. set1_ip_asc answers
   * whether the text is an address at all, so it doubles as the test. */
  X509_VERIFY_PARAM *param = SSL_get0_param(conn->ssl);
  X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);

  int isip = (1 == X509_VERIFY_PARAM_set1_ip_asc(param, host));
  ERR_clear_error();

  if (!isip) {
    if (1 != SSL_set1_host(conn->ssl, host)) {
      saysslerr(err, errlen, "cannot set the expected host name");
      sekreto_tls_free(conn);
      return NULL;
    }

    /* (3) SNI - for names only. RFC 6066 forbids a literal address here,
     * and OpenSSL will send whatever it is handed. */
    SSL_set_tlsext_host_name(conn->ssl, host);
  }

  if (1 != SSL_set_fd(conn->ssl, fd)) {
    saysslerr(err, errlen, "cannot attach the socket");
    sekreto_tls_free(conn);
    return NULL;
  }

  if (1 != SSL_connect(conn->ssl)) {
    saysslerr(err, errlen, "handshake failed");
    sekreto_tls_free(conn);
    return NULL;
  }

  /* Belt and braces. SSL_VERIFY_PEER should already have aborted, but a
   * connection that reached here unverified would look like it works,
   * which is worse than no TLS at all. */
  if (X509_V_OK != SSL_get_verify_result(conn->ssl)) {
    say(err, errlen, X509_verify_cert_error_string(SSL_get_verify_result(conn->ssl)));
    sekreto_tls_free(conn);
    return NULL;
  }

  X509 *peer = SSL_get1_peer_certificate(conn->ssl);
  if (NULL == peer) {
    say(err, errlen, "the server sent no certificate");
    sekreto_tls_free(conn);
    return NULL;
  }
  X509_free(peer);

  return conn;
}

int sekreto_tls_send(void *handle, const char *buf, int len) {
  sekreto_tls *conn = (sekreto_tls *)handle;
  int wrote = SSL_write(conn->ssl, buf, len);
  return 0 < wrote ? wrote : -1;
}

/* Returns the count read, 0 at end of stream, -1 on failure. A clean
 * close_notify and a torn-down connection both end the body, which is what
 * `Connection: close` framing means. */
int sekreto_tls_recv(void *handle, char *buf, int len) {
  sekreto_tls *conn = (sekreto_tls *)handle;
  int got = SSL_read(conn->ssl, buf, len);

  if (0 < got) {
    return got;
  }

  int why = SSL_get_error(conn->ssl, got);
  if (SSL_ERROR_ZERO_RETURN == why) {
    return 0;
  }
  if (SSL_ERROR_SYSCALL == why && 0 == ERR_peek_error()) {
    return 0;
  }

  return -1;
}

const char *sekreto_tls_why(void) {
  unsigned long code = ERR_peek_last_error();
  static char buf[256];

  if (0 == code) {
    return strerror(errno);
  }

  ERR_error_string_n(code, buf, sizeof buf);
  return buf;
}

/* Whether this build has a TLS backend at all. A port built without one
 * must raise on every https address rather than quietly reach nowhere;
 * this is what Http.hs asks. */
int sekreto_have_tls(void) { return 1; }
