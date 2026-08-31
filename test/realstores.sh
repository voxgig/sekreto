#!/usr/bin/env bash
#
# The same proof as test/integration.sh, against the REAL servers.
#
# test/integration.sh runs every port against mocks that reimplement each
# vendor's published wire protocol. That is fast, hermetic, and a claim.
# This checks the claim: HashiCorp Vault, LocalStack, Infisical, a Key
# Vault emulator and a real boru, in containers, seeded with the same one
# secret, read by the same CLIs.
#
# It is not a replacement. The mocks test things these servers cannot -
# test/mockaws.js re-derives every SigV4 signature, which LocalStack does
# not check at all - and they run in two seconds. This suite is the other
# half: it catches what only a real server can catch, and it has already
# earned its place twice, finding an AppRole token that the mock's
# permissive stand-in hid and an HTTP/2 upgrade that no mock objected to.
#
# Usage:
#   test/realstores.sh [lang...]
#
#   SEKRETO_COMPOSE=0     do not touch docker; the stores are already up
#   SEKRETO_KEEP=1        leave the stack running afterwards
#   REQUIRE_STORES=1      a store that is not up fails the run (CI sets this)
#   REQUIRE_ALL=1         a port that is not built fails the run
#
# Every store's address can be overridden, so this also runs against
# servers you already have - a vault on your own machine, a real AWS
# account, a real Infisical. Nothing here assumes docker except the part
# that starts docker.
#
# doc/design/real-stores.md says which of these are the vendor's own
# server, which are emulators, and which cannot be run locally at all.

set -u

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)

# shellcheck source=test/checks.sh
. "$HERE/checks.sh"

COMPOSE_FILE="$HERE/docker/compose.yaml"

# The API the CLIs must reach. 8398 sits in this suite's own block, clear
# of test/integration.sh's 82xx mocks, so both suites can run at once.
API_PORT=${SEKRETO_API_PORT:-8398}
API_URL=http://127.0.0.1:$API_PORT/whoami

# The one secret. Every store is seeded with this and only this.
TOKEN=${SEKRETO_TOKEN:-s3cr3t-realstores-token}

VAULT_ADDR=${REAL_VAULT_ADDR:-http://127.0.0.1:${SEKRETO_VAULT_PORT:-8300}}
# Both names, because compose.yaml reads SEKRETO_VAULT_TOKEN: honouring
# only one of them starts Vault with one root token and authenticates
# with another, and the seed then fails in a way that reads as a store
# problem rather than a configuration one.
VAULT_ROOT=${REAL_VAULT_TOKEN:-${SEKRETO_VAULT_TOKEN:-sekreto-root-token}}
AWS_ENDPOINT=${REAL_AWS_ENDPOINT:-http://127.0.0.1:${SEKRETO_AWS_PORT:-8302}}
AZURE_ADDR=${REAL_AZURE_ADDR:-https://127.0.0.1:8304}
INFISICAL_ADDR=${REAL_INFISICAL_ADDR:-http://127.0.0.1:${SEKRETO_INFISICAL_PORT:-8307}}
BORU_ADDR=${REAL_BORU_ADDR:-http://127.0.0.1:${SEKRETO_BORU_PORT:-8308}}

WORK=$(mktemp -d)
APIPID=""

cleanup() {
  [ -n "$APIPID" ] && kill "$APIPID" 2>/dev/null
  [ -n "${BORUPID:-}" ] && kill "$BORUPID" 2>/dev/null
  if [ "${SEKRETO_COMPOSE:-1}" = 1 ] && [ -z "${SEKRETO_KEEP:-}" ]; then
    docker compose -f "$COMPOSE_FILE" down -v >/dev/null 2>&1
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

# --------------------------------------------------------------- the stack

if [ "${SEKRETO_COMPOSE:-1}" = 1 ]; then
  if ! docker compose version >/dev/null 2>&1; then
    echo "realstores: docker compose is not available." >&2
    echo "realstores: install it, or set SEKRETO_COMPOSE=0 and point the" >&2
    echo "realstores: REAL_*_ADDR variables at servers you already have." >&2
    exit 1
  fi

  echo '== bringing up the real stores =='

  # Claimed BEFORE compose binds them. test/integration.sh refuses to
  # start a mock on a busy port for a reason - a squatter answers the
  # readiness probe and the suite tests the wrong server - and the same
  # reasoning applies here with a sharper edge: the bootstrap WRITES.
  # Seeding someone else's Vault creates mounts, a policy and an AppRole
  # in it, and `docker compose down -v` undoes none of that.
  for claim in \
    "${SEKRETO_VAULT_PORT:-8300} hashicorp" \
    "${SEKRETO_AWS_PORT:-8302} aws" \
    "8304 azure" \
    "${SEKRETO_INFISICAL_PORT:-8307} infisical"; do
    # shellcheck disable=SC2086
    portfree $claim || exit 1
  done

  # In two steps, and the split is deliberate.
  #
  # --wait blocks on every healthcheck, so when this returns each server
  # is ready rather than merely listening: Vault unsealed, LocalStack's
  # services loaded, Infisical migrated.
  #
  # boru comes second because it is the only service built from source,
  # and a build needs the network in a way a pull does not. Brought up
  # together, a boru whose build fails takes the whole stack with it and
  # the run proves nothing. Brought up separately, it becomes one skipped
  # check on a run that still tests everything else.
  # Not piped into `tail`: without `set -o pipefail` a pipeline reports
  # the LAST command's status, so `if ! compose ... | tail` tests tail,
  # which never fails. The branch below was unreachable, and a compose
  # failure - a port already allocated, most of all - fell through to the
  # probes, which then adopted whatever was squatting the port.
  if ! docker compose -f "$COMPOSE_FILE" up -d --wait vault aws azure infisical >"$WORK/up.log" 2>&1; then
    echo "realstores: the stack did not come up" >&2
    tail -20 "$WORK/up.log" >&2
    docker compose -f "$COMPOSE_FILE" ps >&2
    exit 1
  fi
  tail -5 "$WORK/up.log"

  docker compose -f "$COMPOSE_FILE" up -d --wait boru >/dev/null 2>&1 ||
    echo "   (the boru service did not build or start)" >&2
  echo
else
  echo '== using the stores already running =='
  echo
fi

# ---------------------------------------------------------- boru on the host
#
# The container is the preferred way to get a boru, but it is the only
# service built from source and so the only one that can fail for reasons
# that have nothing to do with sekreto. A boru binary on the machine is
# just as real - it is the same binary the container would build - so it
# is used when the container is not there. test/integration.sh finds one
# the same way, and $BORU means the same thing in both.
BORU=${BORU:-$(command -v boru || true)}
BORUPID=""

if ! curl -s -o /dev/null --max-time 2 "$BORU_ADDR/" 2>/dev/null && [ -n "$BORU" ]; then
  BORU_HOME_DIR="$WORK/boruhome"
  mkdir -p "$BORU_HOME_DIR"
  boruport=${BORU_ADDR##*:}
  if BORU_HOME="$BORU_HOME_DIR" BORU_VAULT_PASSPHRASE=realstores-passphrase \
    "$BORU" vault init --backend=file >"$WORK/boru.log" 2>&1 &&
    printf '%s\n' "$TOKEN" | BORU_HOME="$BORU_HOME_DIR" \
      BORU_VAULT_PASSPHRASE=realstores-passphrase \
      "$BORU" vault add api.token --from-stdin >>"$WORK/boru.log" 2>&1; then
    HOST_BORU_TOKEN=$(BORU_HOME="$BORU_HOME_DIR" BORU_VAULT_PASSPHRASE=realstores-passphrase \
      "$BORU" vault grant '*' 2>>"$WORK/boru.log" | awk '/^token:/{print $2}')
    if [ -n "$HOST_BORU_TOKEN" ]; then
      BORU_HOME="$BORU_HOME_DIR" BORU_VAULT_PASSPHRASE=realstores-passphrase \
        "$BORU" vault serve --listen=127.0.0.1:"$boruport" >"$WORK/boruserve.log" 2>&1 &
      BORUPID=$!
      if ! waitport "$boruport" boru 2>/dev/null; then
        # Killed, not merely forgotten: a serve that is slow rather than
        # dead keeps the port bound after this run, its vault directory
        # is deleted from under it by the cleanup, and the NEXT run's
        # probe finds it and calls it a working store.
        kill "$BORUPID" 2>/dev/null
        BORUPID=""
      fi
    fi
  fi
fi

# ------------------------------------------------------------- which stores

# A store answers, or its checks are skipped by name. Nothing here
# silently substitutes a mock: if Infisical is not up, the Infisical
# checks do not run, and the tally says so.
HAVE_VAULT=0 HAVE_AWS=0 HAVE_AZURE=0 HAVE_INFISICAL=0 HAVE_BORU=0

# A store is present when it ANSWERS LIKE ITSELF, not merely when
# something accepts a connection on its port. "Anything replied" would
# let a holding page, a 404 from an unrelated service, or a half-started
# server count as the store - and the bootstrap would then write into it.
probe() {
  local url=$1 want=$2
  curl -sk --max-time 5 "$url" 2>/dev/null | grep -q "$want"
}

probe "$VAULT_ADDR/v1/sys/health" '"sealed"' && HAVE_VAULT=1
probe "$AWS_ENDPOINT/_localstack/health" '"services"' && HAVE_AWS=1
probe "$AZURE_ADDR/ping" 'pong' && HAVE_AZURE=1
probe "$INFISICAL_ADDR/api/status" '"message"' && HAVE_INFISICAL=1
# boru refuses an unauthenticated read, and the refusal is boru's own.
probe "$BORU_ADDR/v1/secret/data/api.token" '.' && HAVE_BORU=1

say() { printf '   %-12s %s\n' "$1" "$2"; }
say hashicorp "$([ $HAVE_VAULT = 1 ] && echo "$VAULT_ADDR" || echo 'not running')"
say aws "$([ $HAVE_AWS = 1 ] && echo "$AWS_ENDPOINT (LocalStack)" || echo 'not running')"
say azure "$([ $HAVE_AZURE = 1 ] && echo "$AZURE_ADDR (lowkey-vault)" || echo 'not running')"
say infisical "$([ $HAVE_INFISICAL = 1 ] && echo "$INFISICAL_ADDR" || echo 'not running')"
say boru "$([ $HAVE_BORU = 1 ] && echo "$BORU_ADDR (vault serve${BORUPID:+, host binary})" || echo 'not running')"
echo

# ------------------------------------------------------------- the seeding

REAL_VAULT_ROLE_ID=""
REAL_VAULT_SECRET_ID=""
INF_CLIENT=""
INF_SECRET=""
INF_PROJECT=""

if [ $HAVE_VAULT = 1 ]; then
  if out=$(VAULT_ADDR="$VAULT_ADDR" VAULT_TOKEN="$VAULT_ROOT" SEKRETO_TOKEN="$TOKEN" \
    "$HERE/docker/bootstrap/vault.sh" 2>"$WORK/vault.err"); then
    eval "$out"
  else
    cat "$WORK/vault.err" >&2
    HAVE_VAULT=0
  fi
fi

if [ $HAVE_AWS = 1 ]; then
  if ! AWS_ENDPOINT="$AWS_ENDPOINT" SEKRETO_TOKEN="$TOKEN" \
    "$HERE/docker/bootstrap/aws.sh" 2>"$WORK/aws.err"; then
    cat "$WORK/aws.err" >&2
    HAVE_AWS=0
  fi
fi

if [ $HAVE_AZURE = 1 ]; then
  if ! AZURE_ADDR="$AZURE_ADDR" SEKRETO_TOKEN="$TOKEN" CA_OUT="$WORK/azure-ca.pem" \
    "$HERE/docker/bootstrap/azure.sh" 2>"$WORK/azure.err"; then
    cat "$WORK/azure.err" >&2
    HAVE_AZURE=0
  fi
fi

if [ $HAVE_INFISICAL = 1 ]; then
  if out=$(INFISICAL_ADDR="$INFISICAL_ADDR" SEKRETO_TOKEN="$TOKEN" \
    "$HERE/docker/bootstrap/infisical.sh" 2>"$WORK/infisical.err"); then
    eval "$out"
  else
    cat "$WORK/infisical.err" >&2
    HAVE_INFISICAL=0
  fi
fi

# Checked HERE, after the seeding, and not before it.
#
# Coming up and being usable are different things: a store can answer its
# health endpoint and still fail to seed - an Infisical that already has
# an admin, a Vault whose root token does not match, a certificate curl
# will not verify. Each of those turns HAVE_* back off above, and a gate
# that ran earlier would have already waved the run through. Every check
# for that store then becomes a skip, and since skips do not fail a run,
# CI reports PASS having tested that store not at all - which is the
# exact failure this suite exists to prevent elsewhere.
if [ -n "${REQUIRE_STORES:-}" ]; then
  missing=""
  [ $HAVE_VAULT = 1 ] || missing="$missing hashicorp"
  [ $HAVE_AWS = 1 ] || missing="$missing aws"
  [ $HAVE_AZURE = 1 ] || missing="$missing azure"
  [ $HAVE_INFISICAL = 1 ] || missing="$missing infisical"
  if [ -n "$missing" ]; then
    echo "realstores: REQUIRE_STORES is set and these are not usable:$missing" >&2
    echo "realstores: they either did not start or could not be seeded." >&2
    exit 1
  fi
fi

if [ $HAVE_BORU = 1 ]; then
  if [ -n "$BORUPID" ]; then
    BORU_WIRE_TOKEN=$HOST_BORU_TOKEN
  else
    BORU_WIRE_TOKEN=$(docker compose -f "$COMPOSE_FILE" exec -T boru cat /work/token 2>/dev/null | tr -d '\r\n')
  fi
  [ -n "${BORU_WIRE_TOKEN:-}" ] || HAVE_BORU=0
fi

echo

# --------------------------------------------------------------- TLS trust
#
# The Key Vault emulator is the only store here that speaks HTTPS, and it
# does so with a self-signed certificate. That makes it the only place any
# port's TLS stack is exercised at all - the mocks are all plain http - so
# it is worth the trouble of trusting the certificate rather than skipping.
#
# Every language finds its trust roots differently, and there is no
# arrangement that satisfies all of them at once: OpenSSL-based runtimes
# read SSL_CERT_FILE, Node needs NODE_EXTRA_CA_CERTS, the JVM wants a
# keystore, and the Rust port carries a compiled-in root set with
# SEKRETO_CA_BUNDLE as its documented way in. A port with no entry here
# has its Azure check skipped by name.
# Sets TRUST, an ARRAY of environment assignments - not a string.
#
# The JVM's setting is one variable whose value holds two -D options with
# a space between them. Returned as a string and expanded unquoted, the
# caller splits it there and passes the second half to `env` as a command
# rather than an assignment: the keystore password never arrives, the
# keystore cannot be opened, and the failure surfaces as "Remote host
# terminated the handshake" - which reads like a TLS bug in the port and
# is not one. An array keeps the value whole.
tlsenv() {
  local lang=$1 ca=$2
  TRUST=()
  case $lang in
  typescript | javascript) TRUST=("NODE_EXTRA_CA_CERTS=$ca") ;;
  python | ruby | php | go | csharp) TRUST=("SSL_CERT_FILE=$ca") ;;
  rust) TRUST=("SEKRETO_CA_BUNDLE=$ca") ;;
  # Only if the keystore was actually built. keytool may be absent, or
  # may have refused the certificate; handing the JVM a trustStore path
  # that is not there fails the handshake and records a JAVA failure for
  # something the port did not do.
  # kotlin runs on the same JVM as java and takes the same keystore.
  java | kotlin)
    if [ -s "$WORK/azure-ca.jks" ]; then
      TRUST=("JAVA_TOOL_OPTIONS=-Djavax.net.ssl.trustStore=$WORK/azure-ca.jks -Djavax.net.ssl.trustStorePassword=changeit")
    fi
    ;;
  # The Perl port needs IO::Socket::SSL for https, and it is not a core
  # module. Where it is missing, the check is skipped rather than failed:
  # that is the environment's gap, not the port's.
  # zig has no entry, and that is a real finding rather than an
  # oversight: std.crypto.Certificate.Bundle scans a fixed list of system
  # paths (/etc/ssl/certs/ca-certificates.crt and friends) and reads no
  # environment variable at all, so the port cannot be told about a
  # private CA without installing it system-wide. The Rust port faced the
  # same wall - a compiled-in root set - and answered it with
  # SEKRETO_CA_BUNDLE; the Zig port wants the same, and until it has one
  # this check skips by name rather than pretending.
  perl)
    if perl -MIO::Socket::SSL -e1 >/dev/null 2>&1; then
      # SSL_CERT_FILE, which is what HTTP::Tiny (via IO::Socket::SSL)
      # reads. The port uses HTTP::Tiny, not LWP.
      TRUST=("SSL_CERT_FILE=$ca")
    fi
    ;;
  esac
}

if [ $HAVE_AZURE = 1 ] && command -v keytool >/dev/null 2>&1; then
  keytool -importcert -noprompt -alias sekreto-azure \
    -file "$WORK/azure-ca.pem" -keystore "$WORK/azure-ca.jks" \
    -storepass changeit >/dev/null 2>&1 || true
fi

# ----------------------------------------------------------------- the API

portfree "$API_PORT" api || exit 1
API_TOKEN="$TOKEN" PORT="$API_PORT" node "$ROOT/api/server.js" >"$WORK/api.log" 2>&1 &
APIPID=$!
waitport "$API_PORT" api || { cat "$WORK/api.log"; exit 1; }

mkdir -p "$WORK/run"
RUNDIR="$WORK/run"

# --------------------------------------------------------------- the runs

LANGS=${*:-$ALL_LANGS}

for lang in $LANGS; do
  port_ready "$lang" || continue

  # ---- HashiCorp Vault, the real one ----
  if [ $HAVE_VAULT = 1 ]; then
    # KV v2, with a root token: the same exchange the mock serves.
    LABEL="$lang/vault-kv2" STORE= check "$lang" hashicorp ok \
      VAULT_ADDR="$VAULT_ADDR" VAULT_TOKEN="$VAULT_ROOT" VAULT_MOUNT=secret

    # KV v1, whose response nests the fields one level less deeply.
    LABEL="$lang/vault-kv1" STORE= check "$lang" hashicorp ok \
      VAULT_ADDR="$VAULT_ADDR" VAULT_TOKEN="$VAULT_ROOT" \
      VAULT_KV=1 VAULT_MOUNT=kv1

    # AppRole, and this is the one that matters. The mock issues a token
    # that can read anything; a real Vault issues one scoped by policy,
    # so this exercises login AND the authorisation that follows it.
    LABEL="$lang/vault-approle" STORE= check "$lang" hashicorp ok \
      VAULT_ADDR="$VAULT_ADDR" VAULT_AUTH=approle \
      VAULT_ROLE_ID="$REAL_VAULT_ROLE_ID" VAULT_SECRET_ID="$REAL_VAULT_SECRET_ID"

    # A wrong token must be refused, and must not print the secret.
    # The opposite assertion to vault-miss: a bad token is a store that
    # COULD NOT ANSWER, so it must raise rather than read as a miss.
    LABEL="$lang/vault-badtoken" WHY='hashicorp' STORE= check "$lang" hashicorp deny \
      VAULT_ADDR="$VAULT_ADDR" VAULT_TOKEN=not-the-root-token

    # A secret the vault does not hold is a MISS, not a failure: the read
    # is a real 404 from a real Vault, the provider must return "not here"
    # rather than raising, and the CLI must then fail for want of a
    # secret. Getting this backwards is the worst bug the library can
    # have - a chain that silently falls through to a weaker store.
    #
    # WHY matters more than the exit status here. A provider that raises
    # on a 404 and one that correctly reports a miss BOTH exit non-zero,
    # so without it this check passes either way and tests nothing. The
    # CLI only says "unknown secret" when it walked the chain and no
    # provider had it; a store that raised says something else.
    LABEL="$lang/vault-miss" WHY='unknown secret' STORE= check "$lang" hashicorp deny \
      VAULT_ADDR="$VAULT_ADDR" VAULT_TOKEN="$VAULT_ROOT" VAULT_MOUNT=empty
  else
    noted_skip "$lang/vault" "no hashicorp vault"
  fi

  # ---- AWS, via LocalStack ----
  #
  # No wrong-credentials check here, deliberately: LocalStack does not
  # verify signatures, so such a check would fail against a correct port.
  # Signing is guarded by test/mockaws.js, which does verify.
  if [ $HAVE_AWS = 1 ]; then
    LABEL="$lang/aws-secrets" STORE= check "$lang" awssecrets ok \
      AWS_ENDPOINT="$AWS_ENDPOINT" AWS_REGION=us-east-1 \
      AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test

    LABEL="$lang/aws-params" STORE= check "$lang" awsparams ok \
      AWS_ENDPOINT="$AWS_ENDPOINT" AWS_REGION=us-east-1 \
      AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test

    # A parameter that is not there must read as a miss - which means the
    # port recognised ParameterNotFound in the error body rather than
    # treating the 400 that carries it as a broken store.
    LABEL="$lang/aws-miss" WHY='unknown secret' STORE= check "$lang" awsparams deny \
      AWS_ENDPOINT="$AWS_ENDPOINT" AWS_REGION=us-east-1 \
      AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test \
      AWS_PARAM_PREFIX=/nosuch
  else
    noted_skip "$lang/aws" "no localstack"
  fi

  # ---- Azure Key Vault, via lowkey-vault, over real TLS ----
  if [ $HAVE_AZURE = 1 ]; then
    tlsenv "$lang" "$WORK/azure-ca.pem"
    if [ ${#TRUST[@]} -gt 0 ]; then
      LABEL="$lang/azure-tls" STORE= check "$lang" azuresecrets ok \
        "${TRUST[@]}" AZURE_VAULT="$AZURE_ADDR" AZURE_TOKEN=lowkey-accepts-any-bearer
    else
      noted_skip "$lang/azure-tls" "no way to trust a private CA in this port"
    fi
  else
    noted_skip "$lang/azure-tls" "no key vault emulator"
  fi

  # ---- Infisical, the real server ----
  if [ $HAVE_INFISICAL = 1 ]; then
    LABEL="$lang/infisical" STORE= check "$lang" infisical ok \
      INFISICAL_ADDR="$INFISICAL_ADDR" \
      INFISICAL_CLIENT_ID="$INF_CLIENT" \
      INFISICAL_CLIENT_SECRET="$INF_SECRET" \
      INFISICAL_PROJECT="$INF_PROJECT" INFISICAL_ENV=prod
  else
    noted_skip "$lang/infisical" "no infisical"
  fi

  # ---- boru, the real binary, over its wire protocol ----
  if [ $HAVE_BORU = 1 ]; then
    LABEL="$lang/boru-wire" STORE= check "$lang" boruwire ok \
      BORU_ADDR="$BORU_ADDR" BORU_TOKEN="$BORU_WIRE_TOKEN"
  else
    noted_skip "$lang/boru-wire" "no boru"
  fi

  # ---- the chain, over real stores ----
  #
  # Nothing local holds the secret, so the answer has to come from the
  # vault at the end of the chain - the shape an application actually
  # ships with.
  if [ $HAVE_VAULT = 1 ]; then
    LABEL="$lang/chain" STORE= check "$lang" chain ok \
      SEKRETO_DOTENV="$WORK/nonexistent/.env" \
      VAULT_ADDR="$VAULT_ADDR" VAULT_TOKEN="$VAULT_ROOT" \
      BORU_COMMAND=/nonexistent/boru

    # A miss must let the chain CARRY ON, and only a chain can show it.
    # The vault is pointed at an empty mount and boru holds the secret,
    # so this passes only if the 404 was a miss: a provider that raises
    # breaks the chain before boru is ever asked.
    if [ $HAVE_BORU = 1 ]; then
      LABEL="$lang/chain-past-miss" STORE= check "$lang" chain ok \
        SEKRETO_DOTENV="$WORK/nonexistent/.env" \
        VAULT_ADDR="$VAULT_ADDR" VAULT_TOKEN="$VAULT_ROOT" VAULT_MOUNT=empty \
        BORU_COMMAND="$BORU" BORU_HOME="$WORK/boruhome" \
        BORU_VAULT_PASSPHRASE=realstores-passphrase
    else
      noted_skip "$lang/chain-past-miss" "needs boru as the store after the vault"
    fi

    # Directed: everything holds it, but one store is named.
    LABEL="$lang/chain->vault" STORE=hashicorp check "$lang" chain ok \
      API_TOKEN="$TOKEN" \
      VAULT_ADDR="$VAULT_ADDR" VAULT_TOKEN="$VAULT_ROOT" \
      BORU_COMMAND=/nonexistent/boru
  fi
done

tally
