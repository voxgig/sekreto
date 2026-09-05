#!/bin/sh
# THE CORE'S DEPENDENCY LISTING, CHECKED - the half of the boundary the
# compiler draws for us.
#
# `dart compile exe --depfile` writes a ninja depfile: the binary, a colon,
# and then every source file that went into it - the port's own, the SDK's
# and voxgig/plugin's. That is this language's link map. A core that
# imported a plugin, by any spelling the compiler can follow, would put a
# `plugins/` path in it.
#
# The second half is what a dependency listing cannot see: a core that grew
# its own socket, its own cipher or its own child process rather than
# importing one. `src/` is greppped for those directly.
#
# Used by `make check-core`. Exits 0 when the core is clean, 1 otherwise.

set -eu

DEPFILE="${1:?usage: corecheck.sh <depfile>}"
HERE="$(cd "$(dirname "$0")" && pwd)"

fail=0

report() {
  fail=1
  echo "FAIL - $1"
}

# --- the compiler's own listing --------------------------------------

# Every path under plugins/, whatever it is called and however deep: a
# pattern that spelled out the file names it expected would miss a plugin
# spelled with a capital or one in a subdirectory, and pass.
reached=$(tr ' ' '\n' < "$DEPFILE" | grep -c '/plugins/.*\.dart$' || true)

if [ "0" != "$reached" ]; then
  report "the core's dependency listing names $reached file(s) under plugins/:"
  tr ' ' '\n' < "$DEPFILE" | grep '/plugins/.*\.dart$' | sed 's/^/       /'
else
  echo "ok   - the core's dependency listing names no plugin"
fi

# The listing must be real: an empty or unwritten depfile would pass the
# test above by saying nothing at all.
own=$(tr ' ' '\n' < "$DEPFILE" | grep -c '/src/[a-z0-9_]*\.dart$' || true)

if [ "4" -gt "$own" ]; then
  report "the dependency listing names only $own core file(s) - is it real?"
else
  echo "ok   - the dependency listing names $own core files and voxgig/plugin"
fi

# --- what a listing cannot see ---------------------------------------
#
# A core that opened its own socket, hashed its own bytes or forked its own
# child would import nothing under plugins/ and still be a core with a
# platform dependency. `dart:io` itself stays allowed: the two file-reading
# built-ins need `File`, and `Platform.environment` is what `env` is.

# `Socket.` covers every constructor and static this SDK spells that way -
# Socket.connect, SecureSocket.connect, ServerSocket.bind,
# RawDatagramSocket.bind. It is searched as a FIXED STRING (`-F`), so the
# dot is a dot: without that it is a regex any-character and matches the
# SocketException the two file-reading built-ins already name.
for pattern in HttpClient SecurityContext RawSocket 'Socket(' 'Socket.' 'Process.' sha256 hmac 'dart:typed_data'; do
  hit=$(grep -rlF -- "$pattern" "$HERE/src" 2>/dev/null || true)
  if [ -n "$hit" ]; then
    report "the core reaches $pattern: $hit"
  fi
done

if [ "0" = "$fail" ]; then
  echo "ok   - the core has no socket, no cipher and no child process"
  echo "core: the core reaches no plugin"
fi

exit "$fail"
