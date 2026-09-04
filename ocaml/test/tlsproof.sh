#!/usr/bin/env sh
# The four TLS obligations, proved against a real handshake.
#
# A binding that connects without verifying is worse than no TLS, because it
# looks like it works - and nothing else in this repository can catch that
# for this port. `make test` never opens a socket, `make integration` speaks
# only plaintext loopback, and `make realstores` has a happy path and an
# untrusted path but NO negative hostname case. So the negative cases are
# here:
#
#   1  chain    an untrusted CA is refused
#   2  hostname a certificate for another host is refused, by address and
#               by name - the half that gets forgotten, and the half no
#               other suite tests
#   3  SNI      sent for a DNS name, not sent for an IP literal
#   4  bundle   SEKRETO_CA_BUNDLE adds roots, never replaces them, and a
#               wrong path fails open in silence
#
# It needs node and the openssl command line, and says so and skips if
# either is missing rather than passing quietly.

set -u

here=$(cd "$(dirname "$0")" && pwd)
port=${here}/../build
probe=${port}/tlsprobe

if ! command -v node >/dev/null 2>&1; then
  echo "skipped: no node, so there is no TLS server to talk to"
  exit 0
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "skipped: no openssl command line, so there are no certificates to make"
  exit 0
fi

if [ ! -x "$probe" ]; then
  echo "sekreto: build/tlsprobe is missing - run make build first" >&2
  exit 1
fi

work=$(mktemp -d)
pids=""
cleanup() {
  for pid in $pids; do kill "$pid" 2>/dev/null; done
  rm -rf "$work"
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------- certificates

quiet() { "$@" >/dev/null 2>&1; }

quiet openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$work/ca.key" -out "$work/ca.pem" -subj "/CN=sekreto-tlsproof-ca"

quiet openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$work/other.key" -out "$work/other.pem" -subj "/CN=unrelated-ca"

make_cert() {
  name=$1
  san=$2
  quiet openssl req -newkey rsa:2048 -nodes \
    -keyout "$work/$name.key" -out "$work/$name.csr" -subj "/CN=$name"
  printf 'subjectAltName=%s\n' "$san" > "$work/$name.ext"
  quiet openssl x509 -req -days 1 -in "$work/$name.csr" \
    -CA "$work/ca.pem" -CAkey "$work/ca.key" -CAcreateserial \
    -extfile "$work/$name.ext" -out "$work/$name.pem"
}

# One certificate that names this machine, and one that names somewhere
# else - signed by the SAME CA, so only the host check can tell them apart.
make_cert good "IP:127.0.0.1,DNS:localhost"
make_cert wrong "DNS:wrong.example.com"

cat "$work/other.pem" "$work/ca.pem" > "$work/both.pem"

# ---------------------------------------------------------------- servers

free() {
  # A port nothing is listening on. Claimed before use, so a squatter is
  # noticed here rather than mistaken for the server under test.
  candidate=$1
  while [ "$candidate" -lt 65000 ]; do
    if ! node -e "
      const net = require('node:net')
      const s = net.connect($candidate, '127.0.0.1')
      s.on('connect', () => { s.destroy(); process.exit(0) })
      s.on('error', () => process.exit(1))
    " 2>/dev/null; then
      echo "$candidate"
      return 0
    fi
    candidate=$((candidate + 1))
  done
  echo "sekreto: no free port" >&2
  exit 1
}

waitup() {
  tries=0
  while [ "$tries" -lt 60 ]; do
    if node -e "
      const net = require('node:net')
      const s = net.connect($1, '127.0.0.1')
      s.on('connect', () => { s.destroy(); process.exit(0) })
      s.on('error', () => process.exit(1))
    " 2>/dev/null; then
      return 0
    fi
    tries=$((tries + 1))
    sleep 1
  done
  echo "sekreto: server on $1 never came up" >&2
  cat "$work/$1.log" 2>/dev/null
  exit 1
}

goodport=$(free 9330)
wrongport=$(free $((goodport + 1)))

node "$here/tlsserver.js" "$goodport" "$work/good.pem" "$work/good.key" \
  "$work/sni-good.json" > "$work/$goodport.log" 2>&1 &
pids="$pids $!"

node "$here/tlsserver.js" "$wrongport" "$work/wrong.pem" "$work/wrong.key" \
  "$work/sni-wrong.json" > "$work/$wrongport.log" 2>&1 &
pids="$pids $!"

waitup "$goodport"
waitup "$wrongport"

# ----------------------------------------------------------------- checks

pass=0
fail=0

# expect <label> <want-prefix> <addr> [ca-bundle]
expect() {
  label=$1
  want=$2
  addr=$3
  ca=${4:-}

  if [ -n "$ca" ]; then
    got=$(env SEKRETO_CA_BUNDLE="$ca" "$probe" "$addr")
  else
    got=$(env -u SEKRETO_CA_BUNDLE "$probe" "$addr")
  fi

  case $got in
  "$want"*)
    pass=$((pass + 1))
    printf '  ok   %-44s %s\n' "$label" "$got"
    ;;
  *)
    fail=$((fail + 1))
    printf '  FAIL %-44s %s\n' "$label" "$got"
    ;;
  esac
}

refused="ERR sekreto: cannot reach"

echo "== TLS obligations, against a real handshake =="

# (1) The chain. Without the CA the handshake must not complete: this is the
#     check that proves verification is switched on at all, and the happy
#     path alone can never fail for the reason it exists.
expect "1 chain: an untrusted CA is refused" "$refused" \
  "https://127.0.0.1:$goodport"

# (4) The bundle: additive, and never a replacement.
expect "4 bundle: our CA is trusted" "OK over-real-tls" \
  "https://127.0.0.1:$goodport" "$work/ca.pem"
expect "4 bundle: an unrelated CA alone" "$refused" \
  "https://127.0.0.1:$goodport" "$work/other.pem"
expect "4 bundle: both CAs in one file" "OK over-real-tls" \
  "https://127.0.0.1:$goodport" "$work/both.pem"
expect "4 bundle: a wrong path fails open" "$refused" \
  "https://127.0.0.1:$goodport" "$work/nosuchfile.pem"

# (2) The host. Same CA, so the chain verifies and only the name check can
#     refuse - by iPAddress SAN for a literal, by DNS name for a name.
expect "2 host: a certificate for another host" "$refused" \
  "https://127.0.0.1:$wrongport" "$work/ca.pem"
expect "2 host: that certificate by its own name" "$refused" \
  "https://localhost:$wrongport" "$work/ca.pem"
expect "2 host: the right certificate, by name" "OK over-real-tls" \
  "https://localhost:$goodport" "$work/ca.pem"

# (3) SNI: exactly one connection above used a DNS name, and only that one
#     may appear here. An IP literal must send no SNI at all - RFC 6066
#     forbids it, and OpenSSL sends whatever it is handed.
sni=$(cat "$work/sni-good.json")
if [ '["localhost"]' = "$sni" ]; then
  pass=$((pass + 1))
  printf '  ok   %-44s %s\n' "3 SNI: the name only, never the address" "$sni"
else
  fail=$((fail + 1))
  printf '  FAIL %-44s %s\n' "3 SNI: the name only, never the address" "$sni"
fi

echo
echo "$pass passed, $fail failed"

[ 0 -eq "$fail" ]
