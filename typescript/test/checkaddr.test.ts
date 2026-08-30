// RUN: npm test
//
// checkaddr is the guard that refuses to put a token on the wire in
// plaintext to anything but the local machine. It is worth testing
// directly, and separately from the spec-driven suite, because both of its
// failure directions are costly: too strict refuses a legitimate dev vault,
// too loose leaks a credential.

import { describe, test } from 'node:test'
import assert from 'node:assert'

import { checkaddr } from '../src'

describe('checkaddr', () => {
  test('https is always allowed, whatever the host', () => {
    assert.doesNotThrow(() => checkaddr('https://vault.example.com:8200'))
  })

  // The bug this file was added for: splitting the authority on ':' yields
  // '[' for a bracketed IPv6 address, so these could never match and the
  // '::1' / '[::1]' entries in the allowlist were unreachable.
  test('http to IPv6 loopback is allowed', () => {
    assert.doesNotThrow(() => checkaddr('http://[::1]:8200'))
    assert.doesNotThrow(() => checkaddr('http://[::1]/'))
    assert.doesNotThrow(() => checkaddr('http://[::1]'))
  })

  test('http to IPv4 loopback and localhost is allowed', () => {
    assert.doesNotThrow(() => checkaddr('http://127.0.0.1:8200'))
    assert.doesNotThrow(() => checkaddr('http://localhost:8200'))
    assert.doesNotThrow(() => checkaddr('http://localhost'))

    // Case is not part of a host's identity.
    assert.doesNotThrow(() => checkaddr('http://LOCALHOST:8200'))
  })

  test('http to anything else is refused', () => {
    assert.throws(() => checkaddr('http://vault.example.com:8200'), /plaintext/)
    assert.throws(() => checkaddr('http://10.0.0.5:8200'), /plaintext/)
  })

  // Userinfo is not the host. Parsing must not be fooled into reading
  // '127.0.0.1@evil.com' as loopback.
  test('a loopback-looking userinfo does not make a remote host local', () => {
    assert.throws(() => checkaddr('http://127.0.0.1@evil.com/'), /plaintext/)
    assert.throws(() => checkaddr('http://localhost@evil.com/'), /plaintext/)
  })

  test('a non-http scheme is refused', () => {
    assert.throws(() => checkaddr('ftp://127.0.0.1/'), /not an http/)
    assert.throws(() => checkaddr('127.0.0.1:8200'), /not an http/)
  })

  test('an unparseable address is refused rather than crashing', () => {
    assert.throws(() => checkaddr('http://[::1'), /not a valid http/)
  })

  // Deliberately still refused. Recognising the IPv4-mapped form as
  // loopback is a decision about the ALLOWLIST, separate from parsing the
  // host correctly, and is not made here.
  test('IPv4-mapped IPv6 loopback is not (yet) in the allowlist', () => {
    assert.throws(() => checkaddr('http://[::ffff:127.0.0.1]:8200'), /plaintext/)
  })
})
