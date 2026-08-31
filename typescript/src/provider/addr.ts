/* Copyright (c) 2025 Voxgig Ltd, MIT License */

import { SekretoError } from './support'

export function checkaddr(addr: string): void {
  if (addr.startsWith('https://')) {
    return
  }

  if (!addr.startsWith('http://')) {
    throw new SekretoError('sekreto: not an http(s) address: ' + addr)
  }

  // Parsed, not split on ':'. Splitting the authority on the first colon
  // yields '[' for a bracketed IPv6 address, so `http://[::1]:8200` could
  // never match — which made the '::1' and '[::1]' entries below
  // unreachable, and refused a legitimate local vault.
  //
  // The ALLOWLIST is unchanged. URL only fixes what the host IS: it strips
  // userinfo (so `http://127.0.0.1@evil.com/` reads as evil.com, as
  // before), lowercases, and normalises numeric forms — `0177.0.0.1` is
  // 127.0.0.1 and is now recognised as the loopback it actually is.
  // IPv4-mapped IPv6 (`[::ffff:127.0.0.1]`) is deliberately still refused:
  // widening the set is a separate decision from parsing it correctly.
  let host: string
  try {
    host = new URL(addr).hostname
  } catch (err: any) {
    throw new SekretoError('sekreto: not a valid http(s) address: ' + addr)
  }

  if ('localhost' === host || '127.0.0.1' === host || '::1' === host || '[::1]' === host) {
    return
  }

  throw new SekretoError(
    'sekreto: refusing to send a token in plaintext to ' + addr + ' (use https)',
  )
}

/** How long any single vault round-trip may take before it is treated as
 * unreachable. Ports carry the same bound. */

/** One JSON round-trip. Network failure is always an error - an
 * unreachable store is a store that could not answer. */
