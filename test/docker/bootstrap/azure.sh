#!/usr/bin/env bash
#
# Put the test secret into the Key Vault emulator, and write out the
# certificate a client needs in order to trust it.
#
#   AZURE_ADDR=https://127.0.0.1:8304 SEKRETO_TOKEN=... CA_OUT=/tmp/ca.pem \
#     bootstrap/azure.sh
#
# WHY THIS ONE IS HTTPS AND THE REST ARE NOT
#
# Every other server in the stack speaks plain http on loopback, which is
# what `vault server -dev` and its kind do and what sekreto's checkaddr
# permits. lowkey-vault does not offer that for the Key Vault API - only
# its /ping is on the plaintext port - so this is the one store that
# forces real TLS.
#
# That turns out to be worth having rather than working around: it is the
# only place in either suite where a port's TLS stack is exercised at all.
# The certificate is self-signed, so it is its own CA, and the caller
# hands it to each port in whatever way that language accepts one.
#
# Auth is a stand-in: lowkey-vault accepts any bearer token and issues
# none, so the client-credentials login sekreto performs against real
# Entra has no counterpart here. That path stays covered by
# test/mockazure.js, which does implement the token endpoint. What this
# proves is the vault read itself - over TLS, with real certificate
# verification, against a server that answers Key Vault's own shapes.

set -eu

ADDR=${AZURE_ADDR:?AZURE_ADDR is required}
SECRET=${SEKRETO_TOKEN:?SEKRETO_TOKEN is required}
CA_OUT=${CA_OUT:?CA_OUT is required}
APIVERSION=${AZURE_API_VERSION:-7.4}

ADDR=${ADDR%/}
HOSTPORT=${ADDR#https://}

echo "azure: seeding $ADDR" >&2

# The certificate the emulator is serving, taken from the handshake
# rather than from inside the image: whatever it presents is what a
# client has to trust, and reading it from the wire cannot go stale.
if ! echo | openssl s_client -connect "$HOSTPORT" -servername localhost 2>/dev/null |
  openssl x509 -out "$CA_OUT" 2>/dev/null; then
  echo "azure: could not read the emulator's certificate from $HOSTPORT" >&2
  exit 1
fi

if [ ! -s "$CA_OUT" ]; then
  echo "azure: the emulator presented no certificate" >&2
  exit 1
fi

# `api.token` is Key Vault secret `api-token`: dots flatten to hyphens,
# because Key Vault names allow letters, digits and hyphens and nothing
# else. Every port computes that name for itself.
#
# --cacert, not -k: seeding is also the first check that the certificate
# just written is actually usable to verify this server.
code=$(curl -sS --cacert "$CA_OUT" --resolve "localhost:${HOSTPORT##*:}:127.0.0.1" \
  -o /dev/null -w '%{http_code}' \
  -X PUT "$ADDR/secrets/api-token?api-version=$APIVERSION" \
  -H 'authorization: Bearer bootstrap' \
  -H 'content-type: application/json' \
  -d "{\"value\":\"$SECRET\"}")

case $code in
200 | 201) ;;
*)
  echo "azure: seeding failed with status $code" >&2
  exit 1
  ;;
esac

echo "azure: seeded secret api-token, certificate written to $CA_OUT" >&2
