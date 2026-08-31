// RUN: npm test
//
// checkaddr is the guard that refuses to put a token on the wire in
// plaintext to anything but the local machine. It is worth testing
// directly, and separately from the spec-driven suite, because both of its
// failure directions are costly: too strict refuses a legitimate dev vault,
// too loose leaks a credential.
//
// The cases that carry across all twelve ports are in spec/def/store.aon,
// so every port is held to them. This file is the fuller table, including
// the inputs where a port's own URL parser would have disagreed - which is
// why the address is parsed by hand and not by `new URL`.

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
    assert.doesNotThrow(() => checkaddr('http://localhost/v1/secret'))
    assert.doesNotThrow(() => checkaddr('http://localhost?a=1'))

    // Case is not part of a host's identity.
    assert.doesNotThrow(() => checkaddr('http://LOCALHOST:8200'))
  })

  test('http to anything else is refused', () => {
    assert.throws(() => checkaddr('http://vault.example.com:8200'), /plaintext/)
    assert.throws(() => checkaddr('http://10.0.0.5:8200'), /plaintext/)
  })

  // Userinfo is refused outright, on https as much as on http. The attack
  // it closes is `http://localhost:8200@evil.example.com/`, which reads as
  // loopback to anything that splits the authority on ':' and is in fact a
  // request to evil.example.com.
  test('an address with userinfo is refused, however it is dressed up', () => {
    assert.throws(() => checkaddr('http://localhost:8200@evil.example.com/'), /credentials/)
    assert.throws(() => checkaddr('http://127.0.0.1@evil.example.com/'), /credentials/)
    assert.throws(() => checkaddr('http://a@127.0.0.1@evil.example.com/'), /credentials/)

    // Even when the host really is loopback: no store this library speaks
    // authenticates this way, so the address is a mistake either way.
    assert.throws(() => checkaddr('http://user:pass@localhost:8200/'), /credentials/)
    assert.throws(() => checkaddr('https://user:pass@vault.example.com/'), /credentials/)
  })

  // An '@' after the authority is part of the path, and paths are not this
  // function's business.
  test('an @ in the path is not userinfo', () => {
    assert.doesNotThrow(() => checkaddr('http://localhost:8200/v1/a@b'))
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

  // The host is compared literally. `0177.0.0.1` really is 127.0.0.1, and
  // WHATWG's URL would say so - but only three of the twelve platform
  // parsers agree, so no port guesses at a numeric form. Refusing a
  // genuine loopback address written in octal costs a config edit; the
  // alternative is twelve ports that disagree about what is local.
  test('a numeric form of loopback is refused rather than normalised', () => {
    assert.throws(() => checkaddr('http://0177.0.0.1:8200'), /plaintext/)
    assert.throws(() => checkaddr('http://2130706433:8200'), /plaintext/)
  })

  // The invariant that makes a hand parse safe: it ends the authority at
  // '/', '?' or '#' only. A client that also breaks on '\' - WHATWG does,
  // so `fetch` dials `localhost` here - can only ever see a shorter host
  // than this reads, so this can refuse where the client would have been
  // safe, and never the reverse.
  test('a backslash does not end the authority, so this refuses first', () => {
    assert.throws(() => checkaddr('http://localhost\\.evil.example.com/'), /plaintext/)
  })
})
