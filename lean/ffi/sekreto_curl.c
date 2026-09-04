/*
 * The TLS transport binding, and the ONLY file in this port that names a
 * library outside the Lean toolchain.
 *
 * Lean has no sockets, no TLS and no HTTP: reaching any of them means
 * FFI to C. `doc/design/more-ports.md` names libcurl for Lean, because
 * that is what the Lean HTTP clients that exist already are, and because
 * the rule the repository settled on is that CRYPTOGRAPHIC TRANSPORT IS
 * NOT HAND-ROLLED - a port with TLS in its standard library uses it, and
 * a port without one binds the platform's audited library.
 *
 * AUDIT SURFACE: libcurl, plus whichever TLS backend it was built
 * against, WHICH THIS PORT DOES NOT CONTROL. libcurl may be linked to
 * OpenSSL, GnuTLS, NSS, wolfSSL or Schannel; only the OpenSSL one
 * honours CURLOPT_SSL_CTX_FUNCTION, which is how SEKRETO_CA_BUNDLE adds
 * roots ADDITIVELY. On any other backend the extra roots are not loaded
 * and the call still succeeds, which is the documented fail-open
 * behaviour of that variable.
 *
 * `-lssl -lcrypto` is here for ONE call, SSL_CTX_load_verify_locations,
 * which is trust configuration and therefore transport. SHA-256 and
 * HMAC-SHA256 are NOT taken from it: they are in-tree, in
 * src/Sekreto/Crypto.lean, because the exception covers transport and
 * nothing else.
 *
 * The four obligations every binding in this repository must meet, and
 * where each is met below:
 *
 *   1. verify the chain against the system trust store
 *      -> CURLOPT_SSL_VERIFYPEER = 1, and CURLOPT_CAINFO is never
 *         overridden, so libcurl's own default store is used.
 *   2. verify the HOSTNAME - separate from the chain, and the half
 *      people forget
 *      -> CURLOPT_SSL_VERIFYHOST = 2. Never 0, never 1.
 *   3. send SNI
 *      -> libcurl sends it itself for a DNS name and correctly omits it
 *         for an IP literal (RFC 6066 forbids it there).
 *   4. honour SEKRETO_CA_BUNDLE for extra roots, ADDITIVELY
 *      -> CURLOPT_SSL_CTX_FUNCTION, calling
 *         SSL_CTX_load_verify_locations on the context libcurl has
 *         already populated with the system roots. CURLOPT_CAINFO would
 *         REPLACE the store, which is why it is not used.
 *
 * And, on top of those: no redirects, no proxies, HTTP/1.1, TLS 1.2 or
 * better, a ten-second bound on the whole round-trip, and an eight-mebibyte
 * cap on the body.
 *
 * The answer is a ByteArray, framed so that nothing about it can be
 * mistaken for a body:
 *
 *   byte 0      'O' answered | 'E' could not reach | 'Z' oversized
 *   bytes 1..4  the HTTP status, big-endian ('O' only, else zero)
 *   bytes 5..   the body bytes ('O') or the failure text ('E')
 *
 * Bytes, not a Lean string, because a response body is arbitrary octets
 * and a Lean string must be valid UTF-8. The Lean side decodes it and
 * lets a body that is not UTF-8 fail the JSON parse, which is exactly
 * the "malformed response" the contract asks for.
 */

#include <lean/lean.h>

#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>
#include <openssl/ssl.h>

/* Eight mebibytes, plus the one byte that proves the bound was passed.
 * The ten-second timeout is not a bound of its own: ten seconds on a
 * loopback or datacentre link is gigabytes, and the body is accumulated
 * in memory before it is parsed. */
#define SEKRETO_MAXBODY (8 * 1024 * 1024)

typedef struct {
  char *data;
  size_t size;
  int over;
} sekreto_buffer;

static size_t sekreto_write(char *chunk, size_t width, size_t count, void *into) {
  sekreto_buffer *buf = (sekreto_buffer *)into;
  size_t add = width * count;

  if (buf->size + add > (size_t)SEKRETO_MAXBODY) {
    buf->over = 1;
    /* Short write: libcurl aborts the transfer with CURLE_WRITE_ERROR,
     * which the caller reports as oversized rather than unreachable. */
    return 0;
  }

  char *grown = (char *)realloc(buf->data, buf->size + add + 1);
  if (NULL == grown) {
    return 0;
  }

  buf->data = grown;
  memcpy(buf->data + buf->size, chunk, add);
  buf->size += add;
  buf->data[buf->size] = '\0';

  return add;
}

/* Extra roots, IN ADDITION to the ones libcurl has already loaded.
 *
 * Fails open, silently, exactly as rust/src/http.rs does: an unreadable
 * file, or a certificate the store rejects, adds no roots and raises
 * nothing. A wrong path is not an error - it is a private CA that was
 * not added. */
static CURLcode sekreto_sslctx(CURL *handle, void *sslctx, void *given) {
  const char *bundle = (const char *)given;
  (void)handle;

  if (NULL != bundle && '\0' != bundle[0]) {
    (void)SSL_CTX_load_verify_locations((SSL_CTX *)sslctx, bundle, NULL);
  }

  return CURLE_OK;
}

static lean_obj_res sekreto_bytes(char tag, unsigned status, const char *payload,
                                  size_t size) {
  lean_object *out = lean_alloc_sarray(1, size + 5, size + 5);
  uint8_t *at = lean_sarray_cptr(out);

  at[0] = (uint8_t)tag;
  at[1] = (uint8_t)((status >> 24) & 0xff);
  at[2] = (uint8_t)((status >> 16) & 0xff);
  at[3] = (uint8_t)((status >> 8) & 0xff);
  at[4] = (uint8_t)(status & 0xff);

  if (0 != size && NULL != payload) {
    memcpy(at + 5, payload, size);
  }

  return out;
}

/* One JSON round-trip. See the framing note at the top of this file. */
LEAN_EXPORT lean_obj_res sekreto_curl_fetch(b_lean_obj_arg method, b_lean_obj_arg url,
                                            b_lean_obj_arg headers, b_lean_obj_arg body,
                                            uint8_t hasbody, b_lean_obj_arg cabundle,
                                            lean_obj_arg world) {
  (void)world;

  const char *usemethod = lean_string_cstr(method);
  const char *useurl = lean_string_cstr(url);
  const char *useheaders = lean_string_cstr(headers);
  const char *usebody = lean_string_cstr(body);
  const char *usebundle = lean_string_cstr(cabundle);

  static int started = 0;
  if (0 == started) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    started = 1;
  }

  CURL *handle = curl_easy_init();
  if (NULL == handle) {
    return lean_io_result_mk_ok(sekreto_bytes('E', 0, "no curl handle", 14));
  }

  sekreto_buffer buf = {NULL, 0, 0};
  struct curl_slist *list = NULL;

  /* One header per line, and the caller has already trimmed them.
   * `Expect:` with no value removes libcurl's own 100-continue header,
   * which some of the vault APIs answer badly. */
  char *lines = strdup(useheaders);
  if (NULL != lines) {
    char *at = lines;
    while ('\0' != *at) {
      char *stop = strchr(at, '\n');
      if (NULL != stop) {
        *stop = '\0';
      }
      if ('\0' != *at) {
        list = curl_slist_append(list, at);
      }
      if (NULL == stop) {
        break;
      }
      at = stop + 1;
    }
  }
  list = curl_slist_append(list, "Expect:");

  curl_easy_setopt(handle, CURLOPT_URL, useurl);
  curl_easy_setopt(handle, CURLOPT_CUSTOMREQUEST, usemethod);
  curl_easy_setopt(handle, CURLOPT_HTTPHEADER, list);
  curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, sekreto_write);
  curl_easy_setopt(handle, CURLOPT_WRITEDATA, (void *)&buf);

  /* Obligation 1: the chain, against libcurl's default (system) store.
   * CURLOPT_CAINFO is deliberately left alone - setting it REPLACES the
   * store, and SEKRETO_CA_BUNDLE must ADD to it. */
  curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 1L);
  /* Obligation 2: the hostname. A separate check from the chain, and the
   * one that is usually missed. 2 is the only acceptable value. */
  curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 2L);
  curl_easy_setopt(handle, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);

  /* Obligation 4: extra roots, additively, on the OpenSSL backend. */
  if ('\0' != usebundle[0]) {
    curl_easy_setopt(handle, CURLOPT_SSL_CTX_FUNCTION, sekreto_sslctx);
    curl_easy_setopt(handle, CURLOPT_SSL_CTX_DATA, (void *)usebundle);
  }

  /* A followed redirect would carry X-Vault-Token to a host checkaddr
   * never saw, and could downgrade https to http. */
  curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 0L);
  /* libcurl reads http_proxy/https_proxy/ALL_PROXY by default. The GCP
   * and Azure metadata endpoints are not loopback, and a proxy in the
   * environment has sent a Vault token in the clear before. */
  curl_easy_setopt(handle, CURLOPT_PROXY, "");
  curl_easy_setopt(handle, CURLOPT_PROTOCOLS_STR, "http,https");
  curl_easy_setopt(handle, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
  curl_easy_setopt(handle, CURLOPT_TIMEOUT_MS, 10000L);
  curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT_MS, 10000L);
  curl_easy_setopt(handle, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(handle, CURLOPT_ACCEPT_ENCODING, "");

  if (0 != hasbody) {
    curl_easy_setopt(handle, CURLOPT_POSTFIELDS, usebody);
    curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE, (long)lean_string_size(body) - 1);
  }

  CURLcode outcome = curl_easy_perform(handle);

  long status = 0;
  curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &status);

  lean_obj_res answer;

  if (CURLE_OK == outcome) {
    answer = sekreto_bytes('O', (unsigned)status, buf.data, buf.size);
  } else if (0 != buf.over) {
    answer = sekreto_bytes('Z', 0, "", 0);
  } else {
    const char *why = curl_easy_strerror(outcome);
    answer = sekreto_bytes('E', 0, why, strlen(why));
  }

  curl_slist_free_all(list);
  free(lines);
  free(buf.data);
  curl_easy_cleanup(handle);

  return lean_io_result_mk_ok(answer);
}
