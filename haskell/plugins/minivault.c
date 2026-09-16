/* The four primitives the mini vault is made of: AES-256-GCM,
 * PBKDF2-HMAC-SHA256, HMAC-SHA256, and the entropy under them.
 *
 * THE SECOND FILE IN THIS PORT THAT NAMES OpenSSL, and the only other
 * one. `plugins/tls.c` is the first, and the exception the link is taken
 * under used to cover TRANSPORT only. AGENTS.md now says cryptography,
 * because a block cipher protecting secrets AT REST has properties no
 * known-answer vector can check - a table-driven AES passes every vector
 * in the world and still hands its key to anyone who can time a cache.
 * The in-tree SHA-256 and HMAC in `plugins/Crypto.hs` stay where they
 * are, as the widened rule says outright: they work, a SigV4 signature is
 * a chain of them so one wrong bit fails the published vectors loudly,
 * and rewriting them buys nothing.
 *
 * WHY C AT ALL. GHC's boot libraries carry no cryptography whatever, and
 * the no-new-package rule stands, so the primitives come from the library
 * this port already links. `plugins/Minivault.hs` is the whole Haskell
 * side and holds every decision about the format; this file does the four
 * calls and nothing else.
 *
 * Every function writes into a buffer the caller sized and answers the
 * number of bytes written, or -1. Lengths are explicit throughout: a
 * vault is full of NULs, so nothing here may be measured with `strlen`.
 */

#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#define SEK_MV_KEYLEN 32
#define SEK_MV_IVLEN 12
#define SEK_MV_TAGLEN 16

/* Fresh entropy from the platform's CSPRNG. A nonce repeated under one
 * AES-GCM key loses the confidentiality of both messages, so a failure
 * here is reported rather than papered over. */
int sekreto_mv_random(unsigned char *out, int len)
{
  if (0 > len) {
    return -1;
  }
  if (0 == len) {
    return 0;
  }

  return 1 == RAND_bytes(out, len) ? len : -1;
}

/* HMAC-SHA256. `out` must hold 32 bytes. */
int sekreto_mv_hmac(const unsigned char *key, int keylen, const unsigned char *msg, int msglen,
                    unsigned char *out)
{
  unsigned int len = 0;

  if (NULL == HMAC(EVP_sha256(), key, keylen, msg, (size_t) msglen, out, &len)) {
    return -1;
  }

  return (int) len;
}

/* PBKDF2-HMAC-SHA256.
 *
 * A round count below one is refused here rather than passed on: it is
 * what a damaged or hostile file records to make the derivation free, and
 * OpenSSL would accept it. */
int sekreto_mv_pbkdf2(const char *pass, int passlen, const unsigned char *salt, int saltlen,
                      int iters, unsigned char *out, int outlen)
{
  if (1 > iters || 0 >= outlen) {
    return -1;
  }

  return 1 == PKCS5_PBKDF2_HMAC(pass, passlen, salt, saltlen, iters, EVP_sha256(), outlen, out)
           ? outlen
           : -1;
}

/* AES-256-GCM, sealing. `out` must hold `plainlen + 16` bytes: the tag
 * rides at the END of the blob, which is where every other port's AEAD
 * leaves it and therefore what the format records. */
int sekreto_mv_seal(const unsigned char *key, const unsigned char *iv,
                    const unsigned char *plain, int plainlen, const unsigned char *aad,
                    int aadlen, unsigned char *out)
{
  EVP_CIPHER_CTX *ctx = NULL;
  int len = 0;
  int ok = 0;

  ctx = EVP_CIPHER_CTX_new();
  if (NULL == ctx) {
    return -1;
  }

  ok = 1 == EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) &&
       1 == EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, SEK_MV_IVLEN, NULL) &&
       1 == EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) &&
       1 == EVP_EncryptUpdate(ctx, NULL, &len, aad, aadlen) &&
       1 == EVP_EncryptUpdate(ctx, out, &len, plain, plainlen) &&
       1 == EVP_EncryptFinal_ex(ctx, out + len, &len) &&
       1 == EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, SEK_MV_TAGLEN, out + plainlen);

  EVP_CIPHER_CTX_free(ctx);

  return ok ? plainlen + SEK_MV_TAGLEN : -1;
}

/* AES-256-GCM, opening. `out` must hold `bloblen - 16` bytes.
 *
 * A tag that fails to verify answers -1, and the Haskell side turns that
 * into the message the format's contract names. The tag is the only
 * evidence there is, and it cannot tell a wrong passphrase from a damaged
 * file. */
int sekreto_mv_unseal(const unsigned char *key, const unsigned char *iv,
                      const unsigned char *blob, int bloblen, const unsigned char *aad,
                      int aadlen, unsigned char *out)
{
  EVP_CIPHER_CTX *ctx = NULL;
  int cut = 0;
  int len = 0;
  int ok = 0;

  if (SEK_MV_TAGLEN > bloblen) {
    return -1;
  }
  cut = bloblen - SEK_MV_TAGLEN;

  ctx = EVP_CIPHER_CTX_new();
  if (NULL == ctx) {
    return -1;
  }

  ok = 1 == EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) &&
       1 == EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, SEK_MV_IVLEN, NULL) &&
       1 == EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) &&
       1 == EVP_DecryptUpdate(ctx, NULL, &len, aad, aadlen) &&
       1 == EVP_DecryptUpdate(ctx, out, &len, blob, cut) &&
       1 == EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, SEK_MV_TAGLEN,
                                (void *) (blob + cut)) &&
       0 < EVP_DecryptFinal_ex(ctx, out + len, &len);

  EVP_CIPHER_CTX_free(ctx);

  return ok ? cut : -1;
}

/* Open a vault file for writing: owner-only, created if it is not there,
 * and EXCLUSIVE when asked. Answers the descriptor, or -1.
 *
 * HERE RATHER THAN IN HASKELL, and that is the interesting part. The
 * `unix` package is the only way GHC offers to ask for a file mode or for
 * O_EXCL, and `openFd` CHANGED ARITY at unix-2.8: the mode moved out of
 * its own argument and into a field of `OpenFileFlags`. This port
 * compiles with `ghc --make` and no cabal, so it has no
 * `MIN_VERSION_unix` macro to branch on, and either spelling fails to
 * compile against the other half of the versions in use. `open(2)` is the
 * call underneath both and has not changed since it was written.
 *
 * Owner-only at CREATION, not afterwards: a chmod after the write leaves
 * a window in which another local user can open the file and keep the
 * descriptor. The mode is subject to the umask, which is what every port
 * that calls open(2) gets. */
int sekreto_mv_open(const char *path, int exclusive)
{
  int flags = O_WRONLY | O_CREAT | (exclusive ? O_EXCL : O_TRUNC);

  return open(path, flags, S_IRUSR | S_IWUSR);
}
