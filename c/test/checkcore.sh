#!/bin/sh
# RUN: make check-core
#
# THE CORE REACHES NO PLUGIN, read off the artifacts rather than asserted.
#
# C has no module system and no import to grep for. `socket`, `connect`,
# `getaddrinfo`, `fork`, `execve`, `posix_spawn`, `popen` and `dlopen` are
# all reachable from any translation unit with a declaration and no
# `#include` at all, so a scan of source text for library names proves
# nothing here. What cannot be talked around is the ARTIFACT: a static
# archive records every symbol it needs from outside itself, and an
# executable records what the linker actually pulled in.
#
# So the checks below are, in order of what they are worth:
#
#   1. The core LINKS AND RUNS with no plugin archive and no -lssl on the
#      command line. Nothing else in this file is as strong: a core that
#      needed a socket, a child process or a digest could not produce a
#      binary at all.
#   2. `nm -u` on the core archive, matched against EXACT undefined symbol
#      names - never substrings. `connect` is a substring of `disconnect`,
#      and a substring search for a hand-written list is what let a real
#      socket hide in another port's audit: nothing in a list of library
#      names spells `socket`.
#   3. A CONTROL on that read. The core needs libc for memory and strings,
#      so if none of malloc/calloc/free/memcpy/memset/strlen comes out of
#      `nm`, the read parsed nothing and its empty intersection with the
#      forbidden list means nothing. A check that reports success when it
#      read nothing is worse than no check.
#   4. The archive's own MEMBER LIST, so that a Makefile edit which slips
#      a plugin object into the core archive is caught even if that object
#      happens to need nothing new.
#   5. Per-plugin links, with their negative controls: a store that signs
#      nothing must not carry SHA-256, a store that spawns nothing must
#      not carry the child launcher - and the aws link MUST carry the
#      digest, or the first half was measuring nothing.
#   6. A source grep for the one thing a symbol table cannot see: a core
#      file that INCLUDES a plugins header. Preprocessor lines are code,
#      not prose, and are read as such.
#
# WHAT THIS DOES NOT COVER, stated rather than glossed: a hash function
# written out INLINE inside a core file is arithmetic with no external
# symbol, so neither `nm` nor any grep can see it. The rule is that the
# core does not IMPORT a hash function, and inline arithmetic does not
# violate it - but nothing here would notice if someone wrote one.

set -e

CC=${SEKRETO_CC:-cc}
CFLAGS=${SEKRETO_CFLAGS:--std=c99 -Wall -Wextra -Werror -O2 -I src -I plugins}
LDLIBS=${SEKRETO_LDLIBS:--lssl -lcrypto}

CORE=build/libsekreto.a
PLUGINS=build/libsekretoplugins.a
HOST=build/libvoxgigplugin.a

fail() {
  echo "sekreto: $1" >&2
  exit 1
}

for archive in $CORE $PLUGINS $HOST; do
  test -f "$archive" || fail "$archive is missing - run make build"
done

mkdir -p build/lean

# The undefined symbols of an archive or a binary, one exact name per
# line. `nm -u` prints "                 U socket" for each, and a header
# line "util.o:" for each archive member; the sed keeps only the former,
# so a member name can never be mistaken for a symbol.
undefined() {
  nm -u "$1" | sed -n 's/^ *U //p' | sed 's/@.*//' | sort -u
}

# Every symbol a binary carries, defined or not.
symbols() {
  nm "$1" | awk '{print $NF}' | sed 's/@.*//' | sort -u
}

# Exact-name membership. Never `grep symbol`, always `grep -x`.
has() {
  printf '%s\n' "$2" | grep -qx "$1"
}

# ---------------------------------------------------------------- (1)

# THE HEADLINE. A consumer whose chain is env/memory/dotenv/file links the
# core, the plugin host and libc - and nothing else. No plugins archive on
# the command line, no -lssl, no -lcrypto. If the core had grown a socket,
# a child process or a digest, this would not link.
cat > build/lean/coreonly.c <<'EOF'
#include <stdio.h>
#include <string.h>

#include "sekreto.h"

int main(void) {
  sek_pool *pool = sek_pool_new();
  sek_spec chain[2];
  sek_options options;
  sek_sekreto *secrets = NULL;
  char *found = NULL;
  sek_err err;

  chain[0] = sek_spec_new("memory");
  chain[0].values = sek_map_new(pool);
  sek_map_set(chain[0].values, "API_TOKEN", "tok01");
  chain[1] = sek_spec_new("env");

  memset(&options, 0, sizeof(options));
  options.providers = chain;
  options.count = 2;

  err = sek_new(pool, &options, &secrets);
  if (NULL != err) {
    printf("%s\n", err);
    return 1;
  }

  err = sek_get(secrets, "api.token", &found);
  if (NULL != err || NULL == found || 0 != strcmp(found, "tok01")) {
    printf("%s\n", NULL == err ? "no value" : err);
    return 1;
  }

  printf("%s\n", found);

  return 0;
}
EOF

# shellcheck disable=SC2086
$CC $CFLAGS -o build/lean/coreonly build/lean/coreonly.c $CORE $HOST 2>build/lean/coreonly.err ||
  {
    echo "sekreto: the core does not link without the plugins:" >&2
    cat build/lean/coreonly.err >&2
    exit 1
  }

got=$(./build/lean/coreonly)
test "tok01" = "$got" || fail "the core-only binary answered '$got'"

# ...and it carries no TLS at all, which `ldd` says out loud.
if ldd build/lean/coreonly 2>/dev/null | grep -qE 'libssl|libcrypto'; then
  fail "the core-only binary is linked against OpenSSL"
fi

echo "core: links, runs and resolves with no plugin archive and no -lssl"

# ---------------------------------------------------------------- (2,3)

coreneeds=$(undefined $CORE)

# (3) The control, FIRST: an empty or unparsed read must not pass.
control=""
for name in malloc calloc free memcpy memset strlen; do
  if has "$name" "$coreneeds"; then
    control="$control $name"
  fi
done
test -n "$control" || fail "nm printed no libc name for the core - the symbol read has no teeth"

# (2) What the core must not need. EXACT names, because these are C
# symbols and a substring test both hides and invents: `socket` appears
# inside no library name a grep list would carry, and `connect` appears
# inside `disconnect`.
PLATFORM="socket connect bind listen accept accept4 shutdown
send sendto recv recvfrom setsockopt getsockopt socketpair
getaddrinfo freeaddrinfo gethostbyname gethostbyname2 inet_pton inet_ntop
poll ppoll select pselect epoll_create epoll_wait
fork vfork clone posix_spawn posix_spawnp
execv execve execvp execvpe execl execlp execle popen pclose system
waitpid wait4 pipe pipe2 dup2 dlopen dlsym
SSL_new SSL_connect SSL_read SSL_write SSL_CTX_new d2i_X509
EVP_DigestInit_ex EVP_Digest HMAC SHA256"

# ...and the library's own plugin-side surface, by exact name. A core that
# called any of these would be a core that had a plugin linked into it.
OURS="sek_http sek_fetch sek_fetchjson sek_uriescape sek_unbase64
sek_sha256 sek_hmac_sha256 sek_sha256hex sek_hex sek_sigv4
sek_runcmd sek_nowms sek_renewtime sek_awsnow
sek_tls_open sek_tls_read sek_tls_write sek_tls_close sek_tls_available
sek_allplugins
sek_plugin_hashicorp sek_plugin_boru sek_plugin_awssecrets sek_plugin_awsparams
sek_plugin_gcpsecrets sek_plugin_azuresecrets sek_plugin_onepassword
sek_plugin_doppler sek_plugin_infisical sek_plugin_secretspec"

reached=""
for name in $PLATFORM $OURS; do
  if has "$name" "$coreneeds"; then
    reached="$reached $name"
  fi
done

test -z "$reached" || fail "the core archive needs$reached - that is a plugin in the core"

echo "core: needs$control from libc and none of $(printf '%s' "$PLATFORM $OURS" | wc -w) forbidden names"

# The same read of the plugins archive DOES find a socket and a digest,
# which is what makes the check above a measurement and not a tautology.
pluginneeds=$(undefined $PLUGINS)
has socket "$pluginneeds" || fail "the plugins archive needs no socket - the read is wrong"
has SSL_connect "$pluginneeds" || fail "the plugins archive needs no TLS - the read is wrong"

echo "plugins: need socket and SSL_connect, so the read above has teeth"

# ---------------------------------------------------------------- (4)

members=$(ar t $CORE | sort | tr '\n' ' ')
test "json.o providers.o sekreto.o util.o " = "$members" ||
  fail "the core archive holds '$members' - src/ alone builds it"

echo "core: the archive holds src/ and nothing else"

# ---------------------------------------------------------------- (5)

# ONE PLUGIN, ON ITS OWN. Each of these links a binary that names exactly
# one plugin and lets the linker pull what that plugin needs out of the
# archives - which is what a lean consumer's build does. `nm` on the
# result says which support objects came with it.
lean() {
  kind=$1
  printf '#include "sekretoplugins.h"\nint main(void) { return NULL == sek_plugin_%s(); }\n' \
    "$kind" > build/lean/$kind.c
  # shellcheck disable=SC2086
  $CC $CFLAGS -o build/lean/$kind build/lean/$kind.c $PLUGINS $CORE $HOST $LDLIBS
}

# A store that signs nothing must not carry SHA-256, and one that runs no
# child must not carry the child launcher.
for kind in hashicorp gcpsecrets azuresecrets onepassword doppler infisical; do
  lean $kind
  got=$(symbols build/lean/$kind)
  if has sek_sha256 "$got"; then fail "the $kind binary carries SHA-256"; fi
  if has sek_hmac_sha256 "$got"; then fail "the $kind binary carries HMAC-SHA256"; fi
  if has sek_runcmd "$got"; then fail "the $kind binary carries the child-process launcher"; fi
  has sek_uriescape "$got" || fail "the $kind binary has no percent-encoder - the read is wrong"
  echo "lean: $kind - no digest, no child process"
done

# secretspec runs a child and signs nothing: both halves, the other way up.
lean secretspec
got=$(symbols build/lean/secretspec)
if has sek_sha256 "$got"; then fail "the secretspec binary carries SHA-256"; fi
has sek_runcmd "$got" || fail "the secretspec binary has no child launcher - the read is wrong"
echo "lean: secretspec - a child process, no digest"

# THE NEGATIVE CONTROL for the whole of (5). aws is the one kind that
# signs, so its binary MUST carry the digest; if it does not, the six
# checks above were measuring nothing.
lean awssecrets
got=$(symbols build/lean/awssecrets)
has sek_sha256 "$got" || fail "the awssecrets binary has no SHA-256 - the read has no teeth"
has sek_sigv4 "$got" || fail "the awssecrets binary has no SigV4 - the read has no teeth"
echo "lean: awssecrets - carries the digest, so the six above mean something"

# ---------------------------------------------------------------- (6)

# The one thing a symbol table cannot see: a core file that INCLUDES a
# plugins header. A `#include` is CODE, not prose, so preprocessor lines
# are read as such and no comment rule exempts them.
if grep -rnE '^[[:space:]]*#[[:space:]]*include[[:space:]]*[<"](sekretoplugins\.h|support\.h|.*plugins/)' \
    src cli/cli.c > build/lean/includes.txt; then
  # The CLI is allowed to - it is a consumer, and a fat one on purpose.
  if grep -v '^cli/cli\.c:' build/lean/includes.txt | grep .; then
    fail "a core source includes a plugins header"
  fi
fi

echo "core: no source under src/ includes a plugins header"
echo "core: reaches no plugin"
