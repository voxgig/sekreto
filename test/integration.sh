#!/usr/bin/env bash
#
# The end-to-end proof, against mock servers.
#
# spec/sekreto.json proves each port computes the same answers. This proves
# they can actually get a secret and use it: for every language, and for
# every secret source, run that port's CLI against a real token-protected
# API and check what comes back.
#
# The token lives in four different places - an environment variable, a
# .env file, a HashiCorp vault and a boru vault - and the CLI is never told
# which one it came from. That indirection is the whole library.
#
# The servers here are MOCKS: each speaks its vendor's published wire
# protocol, reimplemented in-tree (see test/mockhashicorp.js and friends).
# That makes this suite fast and hermetic enough to run on every push. It
# also makes it a claim - "this is what the real server does" - which
# test/realstores.sh checks against the real servers in Docker.
#
# Usage: test/integration.sh [lang...]      (default: every built port)
#
# A port that is not built is skipped, so a partial checkout still tests
# what it has. Set REQUIRE_ALL=1 to turn that skip into a failure - CI does,
# because there a missing CLI means a build broke, and a skipped port that
# reads as green is how a broken port ships.

set -u

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)

# What a check is, and how a port's CLI is invoked, is shared with
# test/realstores.sh so that the two suites cannot drift.
# shellcheck source=test/checks.sh
. "$HERE/checks.sh"

API_PORT=${API_PORT:-8099}
VAULT_PORT=${VAULT_PORT:-8200}
VAULT2_PORT=${VAULT2_PORT:-8201}
AWS_PORT=${AWS_PORT:-8202}
GCP_PORT=${GCP_PORT:-8203}
AZURE_PORT=${AZURE_PORT:-8204}
OP_PORT=${OP_PORT:-8205}
DOPPLER_PORT=${DOPPLER_PORT:-8206}
INFISICAL_PORT=${INFISICAL_PORT:-8207}
BORU_SERVE_PORT=${BORU_SERVE_PORT:-8208}

# The one secret that matters. Long enough that redaction applies to it.
TOKEN=${API_TOKEN:-s3cr3t-integration-token}
VAULT_TOKEN=vault-root-token

# Fixed test credentials for the cloud mocks. The AWS pair is the same
# example pair AWS's own SigV4 test suite publishes.
AWS_KEYID=AKIDEXAMPLE
AWS_SECRETKEY=wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY
SA_JWT=eyJhbGciOiJub25lIn0.integration-service-account.jwt
APPROLE_ID=approle-role-id
APPROLE_SECRET=approle-secret-id
GCP_PROJECT=proj-integration
AZ_TENANT=tenant-integration
AZ_CLIENT=client-integration
AZ_SECRET=azure-client-secret
OP_TOKEN=op-connect-token
OP_VAULT_NAME=devvault
DOPPLER_TOK=dp.st.integration
INF_CLIENT=machine-integration
INF_SECRET=infisical-client-secret
INF_WORKSPACE=w-integration
INF_ENV=prod

# boru is read through its own CLI, not a wire protocol, so the boru checks
# need the real binary. Point BORU at it, or drop it on PATH; without it the
# boru checks are skipped rather than faked.
BORU=${BORU:-$(command -v boru || true)}
BORU_PASSPHRASE=integration-passphrase

API_URL=http://127.0.0.1:$API_PORT/whoami

WORK=$(mktemp -d)
PIDS=()

cleanup() {
  for pid in "${PIDS[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null
  done
  rm -rf "$WORK"
}
trap cleanup EXIT

# Start one mock, and prove the server that answers is OURS.
#
#   startmock <port> <name> <logfile> <command...>
#
# waitport alone is not enough. A mock that cannot bind - because a real
# Vault, a leftover run, or an unrelated service already holds the port -
# dies, but waitport connects to the squatter and reports success, so the
# suite goes on to test the wrong server. That is not hypothetical: a
# `vault server -dev` on its own default port 8200 turns every HashiCorp
# check into a test of the real Vault with the mock's credentials, which
# reads as a sekreto failure. A friendlier squatter would read as a pass.
#
# So the port is claimed before anything is started, where the answer is
# knowable without a race.
startmock() {
  local port=$1 name=$2 log=$3
  shift 3

  portfree "$port" "$name" || exit 1

  "$@" >"$log" 2>&1 &
  PIDS+=("$!")

  if ! waitport "$port" "$name"; then
    cat "$log"
    exit 1
  fi
}

# ---------------------------------------------------------------- servers

echo '== starting servers =='

startmock "$API_PORT" api "$WORK/api.log" \
  env API_TOKEN="$TOKEN" PORT="$API_PORT" node "$ROOT/api/server.js"

startmock "$VAULT_PORT" hashicorp "$WORK/vault.log" \
  node "$HERE/mockhashicorp.js" "$VAULT_PORT" "$VAULT_TOKEN" "api.token=$TOKEN"

# A second vault that behaves like Vault Enterprise: it demands a
# namespace on every request, serves KV v1 as well as v2, and hands out
# its token only through kubernetes/approle logins - so the auth paths
# are proven, not just the happy GET.
startmock "$VAULT2_PORT" hashicorp2 "$WORK/vault2.log" \
  node "$HERE/mockhashicorp.js" "$VAULT2_PORT" "$VAULT_TOKEN" \
  --namespace=teamA --jwt="$SA_JWT" --role=app \
  --roleid="$APPROLE_ID" --secretid="$APPROLE_SECRET" \
  "api.token=$TOKEN"

startmock "$AWS_PORT" aws "$WORK/aws.log" \
  node "$HERE/mockaws.js" "$AWS_PORT" "$AWS_KEYID" "$AWS_SECRETKEY" "api.token=$TOKEN"

startmock "$GCP_PORT" gcp "$WORK/gcp.log" \
  node "$HERE/mockgcp.js" "$GCP_PORT" "$GCP_PROJECT" gcp-access-token "api.token=$TOKEN"

startmock "$AZURE_PORT" azure "$WORK/azure.log" \
  node "$HERE/mockazure.js" "$AZURE_PORT" "$AZ_TENANT" "$AZ_CLIENT" "$AZ_SECRET" \
  azure-access-token "api.token=$TOKEN"

startmock "$OP_PORT" onepassword "$WORK/op.log" \
  node "$HERE/mockonepassword.js" "$OP_PORT" "$OP_TOKEN" "$OP_VAULT_NAME" "api.token=$TOKEN"

startmock "$DOPPLER_PORT" doppler "$WORK/doppler.log" \
  node "$HERE/mockdoppler.js" "$DOPPLER_PORT" "$DOPPLER_TOK" "api.token=$TOKEN"

startmock "$INFISICAL_PORT" infisical "$WORK/infisical.log" \
  node "$HERE/mockinfisical.js" "$INFISICAL_PORT" "$INF_CLIENT" "$INF_SECRET" \
  "$INF_WORKSPACE" "$INF_ENV" "api.token=$TOKEN"

echo "   api        http://127.0.0.1:$API_PORT"
echo "   hashicorp  http://127.0.0.1:$VAULT_PORT (and enterprise-style on $VAULT2_PORT)"
echo "   aws        http://127.0.0.1:$AWS_PORT"
echo "   gcp        http://127.0.0.1:$GCP_PORT"
echo "   azure      http://127.0.0.1:$AZURE_PORT"
echo "   1password  http://127.0.0.1:$OP_PORT"
echo "   doppler    http://127.0.0.1:$DOPPLER_PORT"
echo "   infisical  http://127.0.0.1:$INFISICAL_PORT"

# A real boru vault, holding the same secret under the same name. boru
# stores it in an encrypted keyring on disk; nothing goes over a socket.
BORU_HOME_DIR="$WORK/boruhome"

BORU_WIRE_TOKEN=""

if [ -n "$BORU" ]; then
  mkdir -p "$BORU_HOME_DIR"
  if BORU_HOME="$BORU_HOME_DIR" BORU_VAULT_PASSPHRASE="$BORU_PASSPHRASE" \
       "$BORU" vault init --backend=file >"$WORK/boru.log" 2>&1 &&
     printf '%s\n' "$TOKEN" | BORU_HOME="$BORU_HOME_DIR" \
       BORU_VAULT_PASSPHRASE="$BORU_PASSPHRASE" \
       "$BORU" vault add api.token --from-stdin >>"$WORK/boru.log" 2>&1; then
    echo "   boru       $BORU (vault at $BORU_HOME_DIR)"
  else
    echo "   boru       FAILED to set up; see $WORK/boru.log" >&2
    BORU=""
  fi
fi

# The same boru vault over its wire protocol: grant a root-namespace
# capability and start `boru vault serve`. A boru without the serve mode
# (an older build) skips these checks rather than faking them - like the
# CLI checks, the wire checks run against the real binary or not at all.
if [ -n "$BORU" ]; then
  BORU_WIRE_TOKEN=$(BORU_HOME="$BORU_HOME_DIR" BORU_VAULT_PASSPHRASE="$BORU_PASSPHRASE" \
    "$BORU" vault grant '*' 2>>"$WORK/boru.log" | awk '/^token:/{print $2}')
  if [ -n "$BORU_WIRE_TOKEN" ]; then
    BORU_HOME="$BORU_HOME_DIR" BORU_VAULT_PASSPHRASE="$BORU_PASSPHRASE" \
      "$BORU" vault serve --listen=127.0.0.1:"$BORU_SERVE_PORT" \
      >"$WORK/boruserve.log" 2>&1 &
    PIDS+=($!)
    if waitport "$BORU_SERVE_PORT" boru-serve 2>/dev/null; then
      echo "   boru wire  http://127.0.0.1:$BORU_SERVE_PORT (vault serve)"
    else
      echo "   boru wire  serve did not start, wire checks skipped" >&2
      BORU_WIRE_TOKEN=""
    fi
  else
    echo "   boru wire  this boru has no wildcard grant/serve, wire checks skipped"
  fi
fi

if [ -z "$BORU" ]; then
  echo "   boru       not installed, boru checks skipped"
fi
echo

# Every CLI runs from an empty directory, so a stray .env anywhere in the
# repo cannot make a run pass by accident. Each .env used is named outright.
mkdir -p "$WORK/run" "$WORK/dotenv" "$WORK/wrong"
RUNDIR="$WORK/run"

cat >"$WORK/dotenv/.env" <<EOF
# written by test/integration.sh
API_TOKEN=$TOKEN
EOF

# A .env holding the wrong token, to prove a source is really being used.
cat >"$WORK/wrong/.env" <<EOF
API_TOKEN=not-the-real-token
EOF

# A mounted-secret directory, as Kubernetes or Docker would write it: one
# file per secret, environment-style name, trailing newline and all - the
# provider must strip that newline or the bearer token goes over the wire
# broken.
mkdir -p "$WORK/filedir"
printf '%s\n' "$TOKEN" >"$WORK/filedir/API_TOKEN"

# The service-account JWT the kubernetes-auth login presents.
printf '%s' "$SA_JWT" >"$WORK/jwt"

# --------------------------------------------------------------- the runs

LANGS=${*:-$ALL_LANGS}

for lang in $LANGS; do
  port_ready "$lang" || continue

  # 1. The secret in an environment variable.
  check "$lang" env ok API_TOKEN="$TOKEN"

  # 2. The secret in a .env file. Note that API_TOKEN is NOT in the
  #    environment here, so a port that quietly falls back would fail.
  check "$lang" dotenv ok SEKRETO_DOTENV="$WORK/dotenv/.env"

  # 3. The secret in a HashiCorp vault, over its real KV v2 wire protocol.
  STORE= check "$lang" hashicorp ok \
    VAULT_ADDR="http://127.0.0.1:$VAULT_PORT" \
    VAULT_TOKEN="$VAULT_TOKEN" \
    VAULT_MOUNT=secret

  # 4. The secret in a real boru vault, read through the boru CLI.
  if [ -n "$BORU" ]; then
    STORE= check "$lang" boru ok \
      BORU_COMMAND="$BORU" \
      BORU_HOME="$BORU_HOME_DIR" \
      BORU_VAULT_PASSPHRASE="$BORU_PASSPHRASE"
  else
    noted_skip "$lang/boru" "no boru binary"
  fi

  # 5. The full chain, with only the HashiCorp vault holding the secret:
  #    this is the real configuration, where earlier providers miss and a
  #    later one hits.
  STORE= check "$lang" chain ok \
    SEKRETO_DOTENV="$WORK/nonexistent/.env" \
    VAULT_ADDR="http://127.0.0.1:$VAULT_PORT" \
    VAULT_TOKEN="$VAULT_TOKEN" \
    BORU_COMMAND=/nonexistent/boru

  # 6. Directed access. The whole chain is configured and every store holds
  #    the secret, but --store names one: the answer must come from it.
  STORE=hashicorp check "$lang" chain ok \
    API_TOKEN="$TOKEN" \
    SEKRETO_DOTENV="$WORK/dotenv/.env" \
    VAULT_ADDR="http://127.0.0.1:$VAULT_PORT" \
    VAULT_TOKEN="$VAULT_TOKEN" \
    BORU_COMMAND=/nonexistent/boru

  if [ -n "$BORU" ]; then
    STORE=boru check "$lang" chain ok \
      API_TOKEN=not-the-real-token \
      BORU_COMMAND="$BORU" \
      BORU_HOME="$BORU_HOME_DIR" \
      BORU_VAULT_PASSPHRASE="$BORU_PASSPHRASE"
  else
    noted_skip "$lang/chain->boru" "no boru binary"
  fi

  # 7. The secret in a mounted-secret directory (a Kubernetes/Docker
  #    secret volume), trailing newline stripped.
  STORE= check "$lang" file ok SEKRETO_FILEDIR="$WORK/filedir"

  # 8. Vault Enterprise manners, all in one pass: a kubernetes login
  #    (JWT from a file), the namespace header on every request, and a
  #    KV v1 read.
  STORE= check "$lang" hashicorp ok \
    VAULT_ADDR="http://127.0.0.1:$VAULT2_PORT" \
    VAULT_KV=1 \
    VAULT_NAMESPACE=teamA \
    VAULT_AUTH=kubernetes \
    VAULT_ROLE=app \
    VAULT_JWT_FILE="$WORK/jwt"

  # 9. The same vault via an approle login, back on KV v2.
  STORE= check "$lang" hashicorp ok \
    VAULT_ADDR="http://127.0.0.1:$VAULT2_PORT" \
    VAULT_NAMESPACE=teamA \
    VAULT_AUTH=approle \
    VAULT_ROLE_ID="$APPROLE_ID" \
    VAULT_SECRET_ID="$APPROLE_SECRET"

  # 10. AWS, both stores. The mock re-derives the SigV4 signature of
  #     every request, so a port whose signing is off by a byte fails
  #     here the way it would against real AWS.
  STORE= check "$lang" awssecrets ok \
    AWS_ENDPOINT="http://127.0.0.1:$AWS_PORT" \
    AWS_REGION=us-east-1 \
    AWS_ACCESS_KEY_ID="$AWS_KEYID" \
    AWS_SECRET_ACCESS_KEY="$AWS_SECRETKEY"

  STORE= check "$lang" awsparams ok \
    AWS_ENDPOINT="http://127.0.0.1:$AWS_PORT" \
    AWS_REGION=us-east-1 \
    AWS_ACCESS_KEY_ID="$AWS_KEYID" \
    AWS_SECRET_ACCESS_KEY="$AWS_SECRETKEY"

  # 11. The wrong AWS secret key signs a wrong signature: refused, and
  #     the real token must not appear in the failure output.
  STORE= check "$lang" awssecrets deny \
    AWS_ENDPOINT="http://127.0.0.1:$AWS_PORT" \
    AWS_REGION=us-east-1 \
    AWS_ACCESS_KEY_ID="$AWS_KEYID" \
    AWS_SECRET_ACCESS_KEY=not-the-signing-key

  # 12. GCP Secret Manager, with the token fetched from the (mock)
  #     metadata server - the on-platform auth path.
  STORE= check "$lang" gcpsecrets ok \
    GCP_ADDR="http://127.0.0.1:$GCP_PORT" \
    GCP_METADATA_ADDR="http://127.0.0.1:$GCP_PORT" \
    GCP_PROJECT="$GCP_PROJECT"

  # 13. Azure Key Vault, via a client-credentials login.
  STORE= check "$lang" azuresecrets ok \
    AZURE_VAULT="http://127.0.0.1:$AZURE_PORT" \
    AZURE_TENANT="$AZ_TENANT" \
    AZURE_CLIENT_ID="$AZ_CLIENT" \
    AZURE_CLIENT_SECRET="$AZ_SECRET" \
    AZURE_LOGIN_ADDR="http://127.0.0.1:$AZURE_PORT"

  # 14. 1Password, through a Connect server.
  STORE= check "$lang" onepassword ok \
    OP_CONNECT_HOST="http://127.0.0.1:$OP_PORT" \
    OP_CONNECT_TOKEN="$OP_TOKEN" \
    OP_VAULT="$OP_VAULT_NAME"

  # 15. Doppler, via its bulk download.
  STORE= check "$lang" doppler ok \
    DOPPLER_ADDR="http://127.0.0.1:$DOPPLER_PORT" \
    DOPPLER_TOKEN="$DOPPLER_TOK"

  # 16. Infisical, via a universal-auth (machine identity) login.
  STORE= check "$lang" infisical ok \
    INFISICAL_ADDR="http://127.0.0.1:$INFISICAL_PORT" \
    INFISICAL_CLIENT_ID="$INF_CLIENT" \
    INFISICAL_CLIENT_SECRET="$INF_SECRET" \
    INFISICAL_PROJECT="$INF_WORKSPACE" \
    INFISICAL_ENV="$INF_ENV"

  # 17. The boru vault again, over its wire protocol (`vault serve`)
  #     with a granted capability token.
  if [ -n "$BORU_WIRE_TOKEN" ]; then
    STORE= check "$lang" boruwire ok \
      BORU_ADDR="http://127.0.0.1:$BORU_SERVE_PORT" \
      BORU_TOKEN="$BORU_WIRE_TOKEN"
  else
    noted_skip "$lang/boruwire" "no boru vault serve"
  fi

  # 18. A store that is not in the chain is a mistake, not a miss.
  STORE=nosuchstore check "$lang" env deny API_TOKEN="$TOKEN"

  # 19. No secret anywhere: the CLI must fail, not call the API unauthenticated.
  STORE= check "$lang" env deny SEKRETO_PREFIX=NOSUCH_

  # 20. The wrong secret: the API must refuse it, and the CLI must not print
  #    the real token while complaining.
  STORE= check "$lang" dotenv deny SEKRETO_DOTENV="$WORK/wrong/.env"
done

# --------------------------------------------------------------- the tally

tally
