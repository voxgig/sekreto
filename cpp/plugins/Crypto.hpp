// SHA-256 and HMAC-SHA256, hand-rolled, plus hex and strict base64.
//
// This port links OpenSSL, so `EVP_Digest` and `HMAC` are a function call
// away - and calling them here would break the rule that allows the link
// at all. That exception covers cryptographic TRANSPORT and nothing else:
// SigV4 is signing, not transport. Rust is the worked precedent, with
// `ring` already inside rustls's closure and `rust/src/crypto.rs` still
// carrying both primitives in-tree.
//
// Correctness is not asserted here - it is proved by the SigV4
// known-answer vectors in the shared spec. A signature is a chain of these
// two functions, so one wrong bit anywhere fails there.
//
// A port of rust/src/crypto.rs.

#ifndef SEKRETO_CRYPTO_HPP
#define SEKRETO_CRYPTO_HPP

#include <cstdint>
#include <string>
#include <vector>

namespace sekreto {

using Bytes = std::vector<uint8_t>;

Bytes tobytes(const std::string& text);
std::string frombytes(const Bytes& data);

/// SHA-256 of some bytes, as 32 bytes.
Bytes sha256(const Bytes& data);

/// HMAC-SHA256, RFC 2104, block size 64. Argument order is (key, data);
/// PHP's and Perl's stdlib take (data, key), and the wrapper is where that
/// gets fixed, never at the call sites.
Bytes hmacsha256(const Bytes& key, const Bytes& data);

/// Lowercase, zero-padded, two digits a byte.
std::string hex(const Bytes& data);

/// Decode standard (not URL-safe) base64, STRICTLY.
///
/// Whitespace is stripped first; anything outside `A-Za-z0-9+/`, more than
/// two `=`, or a length that is not a multiple of four is a REFUSAL. A
/// lenient decoder skips bytes it does not know and hands back plausible
/// bytes for a corrupted payload - which then get returned as the secret.
/// Call sites: an AWS SecretBinary, a GCP payload, a PEM body.
bool unbase64(const std::string& text, std::string& out);

}  // namespace sekreto

#endif
