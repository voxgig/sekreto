#!/bin/sh
# The in-port TLS check: four assertions the shared suites cannot make.
#
# Neither `make test` nor `make integration` opens a TLS socket at all -
# every corpus case is short-circuited client-side, and every integration
# mock is plain http on loopback. `test/realstores.sh` is the repository's
# only TLS gate, and even that proves just two of the four obligations: it
# has no negative hostname case, and its untrusted half sets no reason, so
# a port that failed for something unrelated would pass it without ever
# reaching a handshake.
#
# So the hostname obligation - the half people forget, and the one that is
# a DIFFERENT OpenSSL call for an IP literal than for a name - is proved
# here, in the port, against `openssl s_server`. No node, no network.
#
# Usage: sh test/tlscheck.sh

set -e

LUA=${LUA:-lua5.4}
WORK=$(mktemp -d)
BASE=$((19000 + $$ % 800))
IPPORT=$BASE
DNSPORT=$((BASE + 1))
FAILED=0

cleanup() {
  [ -n "$IPPID" ] && kill "$IPPID" 2>/dev/null
  [ -n "$DNSPID" ] && kill "$DNSPID" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

# Two self-signed certificates, each its own root, so that "is this chain
# trusted" and "is this the right host" can be told apart: the IP one
# carries an iPAddress SAN and no name, the DNS one a dNSName SAN and no
# address.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$WORK/ip.key" -out "$WORK/ip.crt" \
  -subj "/CN=sekreto-tlscheck-ip" \
  -addext "subjectAltName=IP:127.0.0.1" 2>/dev/null

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$WORK/dns.key" -out "$WORK/dns.crt" \
  -subj "/CN=sekreto-tlscheck-dns" \
  -addext "subjectAltName=DNS:sekreto-tlscheck.invalid" 2>/dev/null

openssl s_server -quiet -www -naccept 20 -accept "$IPPORT" \
  -cert "$WORK/ip.crt" -key "$WORK/ip.key" >/dev/null 2>&1 &
IPPID=$!

openssl s_server -quiet -www -naccept 20 -accept "$DNSPORT" \
  -cert "$WORK/dns.crt" -key "$WORK/dns.key" >/dev/null 2>&1 &
DNSPID=$!

# s_server takes a moment to bind.
sleep 2

# probe <label> <expected: OK|REFUSED> <bundle-or-empty> <host> <port>
probe() {
  label=$1
  want=$2
  bundle=$3
  host=$4
  port=$5

  if [ -z "$bundle" ]; then
    got=$(SEKRETO_CA_BUNDLE= $LUA test/tlsprobe.lua "$host" "$port")
  else
    got=$(SEKRETO_CA_BUNDLE="$bundle" $LUA test/tlsprobe.lua "$host" "$port")
  fi

  case "$got" in
  "$want"*) echo "ok   - $label" ;;
  *)
    echo "FAIL - $label"
    echo "       wanted $want, got: $got"
    FAILED=$((FAILED + 1))
    ;;
  esac
}

# (1) The chain, against the system trust store. A self-signed server is
#     not in it, so the handshake must be refused.
probe "an untrusted chain is refused" REFUSED "" 127.0.0.1 "$IPPORT"

# (4) SEKRETO_CA_BUNDLE adds a root, ADDITIVELY, and the same request
#     then succeeds - which is also (2) for an IP literal: this is the
#     X509_VERIFY_PARAM_set1_ip_asc path, and SSL_set1_host alone would
#     refuse an iPAddress SAN.
probe "SEKRETO_CA_BUNDLE trusts a private root" OK "$WORK/ip.crt" 127.0.0.1 "$IPPORT"

# (4) A bundle that names the wrong root adds nothing and refuses; a
#     bundle path that does not exist fails open and silently, adding no
#     roots and raising nothing.
probe "the wrong root is not enough" REFUSED "$WORK/dns.crt" 127.0.0.1 "$IPPORT"
probe "a missing bundle adds nothing and raises nothing" \
  REFUSED "$WORK/nosuch.pem" 127.0.0.1 "$IPPORT"

# (2) The hostname, and it is a SEPARATE step from the chain. This
#     certificate IS trusted here - it is passed as the root - and its
#     only SAN is a dNSName. Dialling it by address must still be
#     refused: a port that skips hostname verification passes every other
#     check in this file and fails only this one.
probe "a trusted chain with the wrong address is refused" \
  REFUSED "$WORK/dns.crt" 127.0.0.1 "$DNSPORT"

# (2) The same, for a name: the IP certificate carries no dNSName at all,
#     so `localhost` must not match it however trusted the root is.
probe "a trusted chain with the wrong name is refused" \
  REFUSED "$WORK/ip.crt" localhost "$IPPORT"

if [ 0 -eq "$FAILED" ]; then
  echo ""
  echo "6 passed, 0 failed"
  exit 0
fi

echo ""
echo "$FAILED failed"
exit 1
