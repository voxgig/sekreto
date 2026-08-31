#!/usr/bin/env bash
#
# Put the test secret into a real HashiCorp Vault, and set up the auth
# methods sekreto knows how to use.
#
#   VAULT_ADDR=http://127.0.0.1:8300 VAULT_TOKEN=... SEKRETO_TOKEN=... \
#     bootstrap/vault.sh
#
# Credentials the suite needs come back on stdout as shell assignments,
# for the caller to eval; everything else goes to stderr. That is what
# lets this run against the compose service or against a vault someone
# already has, with no other difference.
#
# Only the HTTP API is used - no vault CLI, no `docker compose exec` - so
# a developer pointing at their own vault needs nothing installed.
#
# WHAT THIS SETS UP THAT THE MOCK DOES NOT
#
# test/mockhashicorp.js hands out one token that can read everything. A
# real Vault issues a token scoped by policy, so an AppRole login that
# "works" against the mock can still be refused by the real thing - which
# is exactly what happened the first time this was run. The policy below
# is the part that was missing, and the reason a real-store run is worth
# doing at all.

set -eu

ADDR=${VAULT_ADDR:?VAULT_ADDR is required}
TOKEN=${VAULT_TOKEN:?VAULT_TOKEN is required}
SECRET=${SEKRETO_TOKEN:?SEKRETO_TOKEN is required}

ADDR=${ADDR%/}

# Vault answers 204 to a write and 200 to a read; a mount that already
# exists answers 400 with "path is already in use", which is a fine
# outcome for a script that may run twice against a long-lived dev vault.
api() {
  local method=$1 path=$2 body=${3:-}
  if [ -n "$body" ]; then
    curl -sS -X "$method" -H "X-Vault-Token: $TOKEN" \
      -H 'content-type: application/json' -d "$body" "$ADDR$path"
  else
    curl -sS -X "$method" -H "X-Vault-Token: $TOKEN" "$ADDR$path"
  fi
}

quiet() { api "$@" >/dev/null 2>&1 || true; }

echo "vault: seeding $ADDR" >&2

# KV v2 is mounted at secret/ by dev mode. `api.token` is the `token`
# field of the secret at path `api` - vaultref's split, which every port
# computes for itself.
api POST /v1/secret/data/api "{\"data\":{\"token\":\"$SECRET\"}}" >/dev/null

# A KV v1 engine as well, because the two read shapes differ: v1 returns
# the fields directly under `data`, v2 nests them under `data.data`.
quiet POST /v1/sys/mounts/kv1 '{"type":"kv","options":{"version":"1"}}'
api POST /v1/kv1/api "{\"token\":\"$SECRET\"}" >/dev/null

# A mount with nothing in it, for the miss check.
#
# A miss and a failure are the two things a provider must never confuse:
# a 404 means this store does not hold the secret and the chain carries
# on, while anything else means it could not answer. Reading from an
# empty mount is a real 404 from a real Vault - the only way to test that
# distinction against the server that actually produces it.
quiet POST /v1/sys/mounts/empty '{"type":"kv","options":{"version":"2"}}'

# The policy an AppRole token gets. Without it the login succeeds and the
# read is refused, which is the failure mode the mock cannot show.
api PUT /v1/sys/policies/acl/sekreto-read \
  '{"policy":"path \"secret/data/*\" { capabilities = [\"read\"] }\npath \"kv1/*\" { capabilities = [\"read\"] }\n"}' >/dev/null

quiet POST /v1/sys/auth/approle '{"type":"approle"}'
api POST /v1/auth/approle/role/app \
  '{"token_policies":"sekreto-read","token_ttl":"20m"}' >/dev/null

ROLEID=$(api GET /v1/auth/approle/role/app/role-id |
  sed -n 's/.*"role_id":"\([^"]*\)".*/\1/p')
SECRETID=$(api POST /v1/auth/approle/role/app/secret-id '{}' |
  sed -n 's/.*"secret_id":"\([^"]*\)".*/\1/p')

if [ -z "$ROLEID" ] || [ -z "$SECRETID" ]; then
  echo "vault: could not obtain approle credentials" >&2
  exit 1
fi

echo "vault: seeded secret/api, kv1/api, and an approle scoped to sekreto-read" >&2

echo "REAL_VAULT_ROLE_ID=$ROLEID"
echo "REAL_VAULT_SECRET_ID=$SECRETID"
