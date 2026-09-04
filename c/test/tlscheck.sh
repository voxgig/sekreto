#!/usr/bin/env bash
# Prove the four TLS obligations, against a real TLS server.
#
# A binding that connects but does not VERIFY is worse than no TLS,
# because it looks like it works - so none of these four is asserted in a
# comment, they are each made to fail on purpose and then made to pass.
#
#   1. chain, against the system trust store   - refused with no bundle
#   2. chain, with SEKRETO_CA_BUNDLE           - accepted, ADDITIVELY
#   3. hostname, DNS name                      - refused when the SAN names
#                                                someone else
#   4. hostname, IP literal                    - accepted only with an
#                                                iPAddress SAN
#   5. SNI                                     - sent for a name, and NOT
#                                                for an IP (RFC 6066)
#   6. a wrong bundle path                     - fails open, silently
#
# Nothing here is in `make test`: that suite runs spec/sekreto.json, and
# NO CASE IN THAT SPEC OPENS A SOCKET. A port with no networking at all
# passes it. This is the gate that a port with no VERIFICATION does not.
#
# Usage: test/tlscheck.sh [port]
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
PORT=${1:-9311}
WORK=$(mktemp -d)
PIDS=()
pass=0
fail=0

cleanup() {
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
  rm -rf "$WORK"
}
trap cleanup EXIT

cd "$HERE/.." || exit 1

make build >/dev/null || exit 1
gcc -std=c99 -Wall -Wextra -Werror -O2 -I src -o build/tlsprobe \
  test/tlsprobe.c build/libsekreto.a -lssl -lcrypto || exit 1
PROBE=$(pwd)/build/tlsprobe

# --- a private CA, and two leaf certificates it signs ------------------
#
# `right` names this machine two ways: DNS:localhost and IP:127.0.0.1.
# `wrong` names someone else entirely, and is signed by the SAME CA - so
# a port that only checks the chain accepts it, and that is exactly what
# case 3 and case 5 catch.

openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -keyout "$WORK/ca.key" -out "$WORK/ca.pem" \
  -subj "/CN=sekreto test CA" >/dev/null 2>&1

makecert() {
  local name=$1 san=$2
  openssl req -newkey rsa:2048 -nodes \
    -keyout "$WORK/$name.key" -out "$WORK/$name.csr" \
    -subj "/CN=$name" >/dev/null 2>&1
  printf 'subjectAltName=%s\n' "$san" >"$WORK/$name.ext"
  openssl x509 -req -in "$WORK/$name.csr" -days 2 \
    -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" -CAcreateserial \
    -extfile "$WORK/$name.ext" -out "$WORK/$name.pem" >/dev/null 2>&1
  cat "$WORK/$name.pem" "$WORK/$name.key" >"$WORK/$name.both"
}

makecert right "DNS:localhost,IP:127.0.0.1"
makecert wrong "DNS:not-this-host.invalid"

# `openssl s_server` speaks HTTP under -www, which is all the probe wants.
# With `-servername X -servername_fatal` it also becomes an SNI OBSERVER:
# it aborts the handshake when the client sends a server_name other than
# X, and completes it when the client sends none at all. That is how case
# 5 below tells "SNI was sent" from "SNI was withheld" without needing the
# server to log anything.
serve() {
  local which=$1 port=$2
  shift 2
  openssl s_server -quiet -www -accept "$port" -naccept 40 \
    -cert "$WORK/$which.pem" -key "$WORK/$which.key" \
    -cert2 "$WORK/$which.both" -key2 "$WORK/$which.both" "$@" \
    >"$WORK/$which-$port.log" 2>&1 &
  PIDS+=("$!")

  for _ in $(seq 1 40); do
    (exec 3<>/dev/tcp/127.0.0.1/"$port") 2>/dev/null && return 0
    sleep 0.25
  done
  echo "tlscheck: server did not start on $port" >&2
  return 1
}

# expect <label> <accept|refuse> <url> [SEKRETO_CA_BUNDLE value or -]
expect() {
  local label=$1 want=$2 url=$3 bundle=${4:--}
  local out rc

  if [ "$bundle" = - ]; then
    out=$(env -u SEKRETO_CA_BUNDLE "$PROBE" "$url" 2>&1)
  else
    out=$(SEKRETO_CA_BUNDLE="$bundle" "$PROBE" "$url" 2>&1)
  fi
  rc=$?

  if [ "$want" = accept ]; then
    if [ $rc -eq 0 ] && [ "${out#status=2}" != "$out" ]; then
      pass=$((pass + 1)); printf '  ok   %-46s %s\n' "$label" "$out"; return
    fi
  else
    if [ $rc -ne 0 ]; then
      pass=$((pass + 1)); printf '  ok   %-46s %s\n' "$label" "$out"; return
    fi
  fi

  fail=$((fail + 1)); printf '  FAIL %-46s %s\n' "$label" "$out"
}

echo "== c/tls =="

serve right "$PORT" || exit 1

expect "1 chain: no bundle, private CA"        refuse "https://localhost:$PORT/" -
expect "2 chain: SEKRETO_CA_BUNDLE adds roots" accept "https://localhost:$PORT/" "$WORK/ca.pem"
expect "4 hostname: IP literal, iPAddress SAN" accept "https://127.0.0.1:$PORT/" "$WORK/ca.pem"
expect "6 bundle: wrong path fails open"       refuse "https://localhost:$PORT/" "$WORK/nope.pem"

# 3. The half people forget. The chain is perfect - same CA, trusted by
#    the bundle - and the certificate simply names somebody else. Nothing
#    in `make integration` or `test/realstores.sh` covers this.
serve wrong "$((PORT + 1))" || exit 1

expect "3 hostname: DNS name, wrong SAN"       refuse "https://localhost:$((PORT + 1))/" "$WORK/ca.pem"
expect "3 hostname: IP literal, no IP SAN"     refuse "https://127.0.0.1:$((PORT + 1))/" "$WORK/ca.pem"

# 5. SNI, both halves. This server holds the `right` certificate but
#    insists the client's server_name be `expected.invalid`, and aborts
#    the handshake when it is anything else. So:
#      - a DNS name is REFUSED, which can only happen if SNI was sent;
#      - an IP literal is ACCEPTED, which can only happen if it was not -
#        and RFC 6066 forbids sending one.
serve right "$((PORT + 2))" -servername expected.invalid -servername_fatal || exit 1

expect "5 sni: sent for a DNS name"            refuse "https://localhost:$((PORT + 2))/" "$WORK/ca.pem"
expect "5 sni: withheld for an IP literal"     accept "https://127.0.0.1:$((PORT + 2))/" "$WORK/ca.pem"

echo
echo "$pass passed, $fail failed"
[ $fail -eq 0 ]
