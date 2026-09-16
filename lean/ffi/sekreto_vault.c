/*
 * The four primitives the mini vault is made of: AES-256-GCM,
 * PBKDF2-HMAC-SHA256, HMAC-SHA256, and the entropy under them.
 *
 * THE SECOND FILE IN THIS PORT THAT NAMES A LIBRARY OUTSIDE THE LEAN
 * TOOLCHAIN, and the only other one. `sekreto_curl.c` is the first, and
 * its note says `-lssl -lcrypto` is there for ONE call, trust
 * configuration, because the exception covered TRANSPORT and nothing
 * else. AGENTS.md now says cryptography, because a block cipher
 * protecting secrets AT REST has properties no known-answer vector can
 * check - a table-driven AES passes every vector in the world and still
 * hands its key to anyone who can time a cache. The in-tree SHA-256 and
 * HMAC in plugins/SekretoPlugins/Crypto.lean stay where they are, as the
 * widened rule says outright: they work, a SigV4 signature is a chain of
 * them so one wrong bit fails the published vectors loudly, and
 * rewriting them buys nothing.
 *
 * libcrypto DIRECTLY, not through libcurl: the `-lssl -lcrypto` the port
 * already carries is the same library, and nothing here goes near the
 * TLS backend libcurl happens to have been built against.
 *
 * WHY C AT ALL. Lean has no cryptography, and the no-new-package rule
 * stands. `plugins/SekretoPlugins/Minivault.lean` is the whole Lean side
 * and holds every decision about the format; this file does the four
 * calls and nothing else.
 *
 * Bytes travel as ByteArray, whose length is its own - so nothing here is
 * measured with `strlen`, which a vault full of NULs would cut short. A
 * failure answers an EMPTY ByteArray, and every caller on the Lean side
 * reads that as the refusal the format's contract names; `unseal` is the
 * one where an empty answer is also a legitimate plaintext, and its Lean
 * caller distinguishes the two with the length it already knows.
 */

#include <lean/lean.h>

#include <string.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#define SEK_MV_KEYLEN 32
#define SEK_MV_IVLEN 12
#define SEK_MV_TAGLEN 16

/* An empty ByteArray: what every function here answers on refusal. */
static lean_obj_res sekreto_mv_none(void) { return lean_alloc_sarray(1, 0, 0); }

/* Fresh entropy from the platform's CSPRNG. A nonce repeated under one
 * AES-GCM key loses the confidentiality of both messages, so a failure
 * here is reported rather than papered over. */
LEAN_EXPORT lean_obj_res sekreto_mv_random(uint32_t len, lean_obj_arg world) {
  lean_object *out;

  (void)world;

  if (4096 < len) {
    return lean_io_result_mk_ok(sekreto_mv_none());
  }

  out = lean_alloc_sarray(1, len, len);

  if (0 != len && 1 != RAND_bytes(lean_sarray_cptr(out), (int)len)) {
    lean_dec_ref(out);
    return lean_io_result_mk_ok(sekreto_mv_none());
  }

  return lean_io_result_mk_ok(out);
}

/* HMAC-SHA256 of `msg` under `key`. */
LEAN_EXPORT lean_obj_res sekreto_mv_hmac(b_lean_obj_arg key, b_lean_obj_arg msg) {
  unsigned char mac[EVP_MAX_MD_SIZE];
  unsigned int len = 0;
  lean_object *out;

  if (NULL == HMAC(EVP_sha256(), lean_sarray_cptr(key), (int)lean_sarray_size(key),
                   lean_sarray_cptr(msg), lean_sarray_size(msg), mac, &len)) {
    return sekreto_mv_none();
  }

  out = lean_alloc_sarray(1, len, len);
  memcpy(lean_sarray_cptr(out), mac, len);

  return out;
}

/* PBKDF2-HMAC-SHA256.
 *
 * A round count below one is refused here rather than passed on: it is
 * what a damaged or hostile file records to make the derivation free, and
 * OpenSSL would accept it. */
LEAN_EXPORT lean_obj_res sekreto_mv_pbkdf2(b_lean_obj_arg pass, b_lean_obj_arg salt,
                                           uint32_t iters) {
  lean_object *out;

  if (1 > iters) {
    return sekreto_mv_none();
  }

  out = lean_alloc_sarray(1, SEK_MV_KEYLEN, SEK_MV_KEYLEN);

  if (1 != PKCS5_PBKDF2_HMAC((const char *)lean_sarray_cptr(pass), (int)lean_sarray_size(pass),
                             lean_sarray_cptr(salt), (int)lean_sarray_size(salt), (int)iters,
                             EVP_sha256(), SEK_MV_KEYLEN, lean_sarray_cptr(out))) {
    lean_dec_ref(out);
    return sekreto_mv_none();
  }

  return out;
}

/* AES-256-GCM, sealing. The answer is ciphertext followed by the 16-byte
 * tag, which is where every other port's AEAD leaves it and therefore
 * what the format records. Empty on refusal, which a sealed blob never
 * is: it always carries at least the tag. */
LEAN_EXPORT lean_obj_res sekreto_mv_seal(b_lean_obj_arg key, b_lean_obj_arg iv,
                                         b_lean_obj_arg plain, b_lean_obj_arg aad) {
  EVP_CIPHER_CTX *ctx = NULL;
  size_t plainlen = lean_sarray_size(plain);
  lean_object *out;
  unsigned char *raw;
  int len = 0;
  int ok = 0;

  if (SEK_MV_KEYLEN != lean_sarray_size(key) || SEK_MV_IVLEN != lean_sarray_size(iv)) {
    return sekreto_mv_none();
  }

  out = lean_alloc_sarray(1, plainlen + SEK_MV_TAGLEN, plainlen + SEK_MV_TAGLEN);
  raw = lean_sarray_cptr(out);

  ctx = EVP_CIPHER_CTX_new();
  if (NULL == ctx) {
    lean_dec_ref(out);
    return sekreto_mv_none();
  }

  ok = 1 == EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) &&
       1 == EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, SEK_MV_IVLEN, NULL) &&
       1 == EVP_EncryptInit_ex(ctx, NULL, NULL, lean_sarray_cptr(key), lean_sarray_cptr(iv)) &&
       1 == EVP_EncryptUpdate(ctx, NULL, &len, lean_sarray_cptr(aad),
                              (int)lean_sarray_size(aad)) &&
       1 == EVP_EncryptUpdate(ctx, raw, &len, lean_sarray_cptr(plain), (int)plainlen) &&
       1 == EVP_EncryptFinal_ex(ctx, raw + len, &len) &&
       1 == EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, SEK_MV_TAGLEN, raw + plainlen);

  EVP_CIPHER_CTX_free(ctx);

  if (!ok) {
    lean_dec_ref(out);
    return sekreto_mv_none();
  }

  return out;
}

/* AES-256-GCM, opening.
 *
 * A tag that fails to verify answers an empty ByteArray. So does a
 * ciphertext that was empty to begin with, and the Lean side tells the
 * two apart by the blob's own length, which it has: a refusal is the
 * only way to get nothing back from a blob longer than the tag. */
LEAN_EXPORT lean_obj_res sekreto_mv_unseal(b_lean_obj_arg key, b_lean_obj_arg iv,
                                           b_lean_obj_arg blob, b_lean_obj_arg aad) {
  EVP_CIPHER_CTX *ctx = NULL;
  size_t bloblen = lean_sarray_size(blob);
  size_t cut = 0;
  lean_object *out;
  unsigned char *raw;
  int len = 0;
  int ok = 0;

  if (SEK_MV_KEYLEN != lean_sarray_size(key) || SEK_MV_IVLEN != lean_sarray_size(iv) ||
      SEK_MV_TAGLEN > bloblen) {
    return sekreto_mv_none();
  }

  cut = bloblen - SEK_MV_TAGLEN;
  out = lean_alloc_sarray(1, cut, cut);
  raw = lean_sarray_cptr(out);

  ctx = EVP_CIPHER_CTX_new();
  if (NULL == ctx) {
    lean_dec_ref(out);
    return sekreto_mv_none();
  }

  ok = 1 == EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) &&
       1 == EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, SEK_MV_IVLEN, NULL) &&
       1 == EVP_DecryptInit_ex(ctx, NULL, NULL, lean_sarray_cptr(key), lean_sarray_cptr(iv)) &&
       1 == EVP_DecryptUpdate(ctx, NULL, &len, lean_sarray_cptr(aad),
                              (int)lean_sarray_size(aad)) &&
       1 == EVP_DecryptUpdate(ctx, raw, &len, lean_sarray_cptr(blob), (int)cut) &&
       1 == EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, SEK_MV_TAGLEN,
                                (void *)(lean_sarray_cptr(blob) + cut)) &&
       0 < EVP_DecryptFinal_ex(ctx, raw + len, &len);

  EVP_CIPHER_CTX_free(ctx);

  if (!ok) {
    lean_dec_ref(out);
    return sekreto_mv_none();
  }

  return out;
}
