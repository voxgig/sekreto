#!/usr/bin/env bash
#
# The end-to-end proof.
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
# Usage: test/integration.sh [lang...]      (default: every built port)
#
# A port that is not built is skipped, so a partial checkout still tests
# what it has. Set REQUIRE_ALL=1 to turn that skip into a failure - CI does,
# because there a missing CLI means a build broke, and a skipped port that
# reads as green is how a broken port ships.

set -u

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)

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

pass=0
fail=0
FAILED=()

green() { printf '\033[32m%s\033[0m' "$1"; }
red() { printf '\033[31m%s\033[0m' "$1"; }

cleanup() {
  for pid in "${PIDS[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null
  done
  rm -rf "$WORK"
}
trap cleanup EXIT

# Wait for a port to answer, rather than sleeping and hoping.
waitport() {
  local port=$1 name=$2 tries=0
  while [ $tries -lt 100 ]; do
    if (exec 3<>/dev/tcp/127.0.0.1/"$port") 2>/dev/null; then
      exec 3<&- 3>&-
      return 0
    fi
    tries=$((tries + 1))
    sleep 0.1
  done
  echo "integration: $name did not start on port $port" >&2
  return 1
}

# ---------------------------------------------------------------- servers

echo '== starting servers =='

API_TOKEN=$TOKEN PORT=$API_PORT node "$ROOT/api/server.js" >"$WORK/api.log" 2>&1 &
PIDS+=($!)

node "$HERE/mockhashicorp.js" "$VAULT_PORT" "$VAULT_TOKEN" \
  "api.token=$TOKEN" >"$WORK/vault.log" 2>&1 &
PIDS+=($!)

# A second vault that behaves like Vault Enterprise: it demands a
# namespace on every request, serves KV v1 as well as v2, and hands out
# its token only through kubernetes/approle logins - so the auth paths
# are proven, not just the happy GET.
node "$HERE/mockhashicorp.js" "$VAULT2_PORT" "$VAULT_TOKEN" \
  --namespace=teamA --jwt="$SA_JWT" --role=app \
  --roleid="$APPROLE_ID" --secretid="$APPROLE_SECRET" \
  "api.token=$TOKEN" >"$WORK/vault2.log" 2>&1 &
PIDS+=($!)

node "$HERE/mockaws.js" "$AWS_PORT" "$AWS_KEYID" "$AWS_SECRETKEY" \
  "api.token=$TOKEN" >"$WORK/aws.log" 2>&1 &
PIDS+=($!)

node "$HERE/mockgcp.js" "$GCP_PORT" "$GCP_PROJECT" gcp-access-token \
  "api.token=$TOKEN" >"$WORK/gcp.log" 2>&1 &
PIDS+=($!)

node "$HERE/mockazure.js" "$AZURE_PORT" "$AZ_TENANT" "$AZ_CLIENT" "$AZ_SECRET" \
  azure-access-token "api.token=$TOKEN" >"$WORK/azure.log" 2>&1 &
PIDS+=($!)

node "$HERE/mockonepassword.js" "$OP_PORT" "$OP_TOKEN" "$OP_VAULT_NAME" \
  "api.token=$TOKEN" >"$WORK/op.log" 2>&1 &
PIDS+=($!)

node "$HERE/mockdoppler.js" "$DOPPLER_PORT" "$DOPPLER_TOK" \
  "api.token=$TOKEN" >"$WORK/doppler.log" 2>&1 &
PIDS+=($!)

node "$HERE/mockinfisical.js" "$INFISICAL_PORT" "$INF_CLIENT" "$INF_SECRET" \
  "$INF_WORKSPACE" "$INF_ENV" "api.token=$TOKEN" >"$WORK/infisical.log" 2>&1 &
PIDS+=($!)

waitport "$API_PORT" api || { cat "$WORK/api.log"; exit 1; }
waitport "$VAULT_PORT" hashicorp || { cat "$WORK/vault.log"; exit 1; }
waitport "$VAULT2_PORT" hashicorp2 || { cat "$WORK/vault2.log"; exit 1; }
waitport "$AWS_PORT" aws || { cat "$WORK/aws.log"; exit 1; }
waitport "$GCP_PORT" gcp || { cat "$WORK/gcp.log"; exit 1; }
waitport "$AZURE_PORT" azure || { cat "$WORK/azure.log"; exit 1; }
waitport "$OP_PORT" onepassword || { cat "$WORK/op.log"; exit 1; }
waitport "$DOPPLER_PORT" doppler || { cat "$WORK/doppler.log"; exit 1; }
waitport "$INFISICAL_PORT" infisical || { cat "$WORK/infisical.log"; exit 1; }

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

# How to invoke each port's CLI. A port is skipped, not failed, when it has
# not been built - so a partial checkout still tests what it has.
cli_cmd() {
  case $1 in
  typescript) echo "node $ROOT/typescript/dist/cli/sekreto-cli.js" ;;
  javascript) echo "node $ROOT/javascript/cli/sekreto-cli.js" ;;
  python) echo "python3 $ROOT/python/cli/sekreto_cli.py" ;;
  ruby) echo "ruby $ROOT/ruby/cli/sekreto_cli.rb" ;;
  php) echo "php $ROOT/php/cli/sekreto-cli.php" ;;
  perl) echo "perl -I$ROOT/perl/lib $ROOT/perl/cli/sekreto-cli.pl" ;;
  go) echo "$ROOT/go/build/sekreto-cli" ;;
  rust) echo "$ROOT/rust/target/release/sekreto-cli" ;;
  java) echo "java -cp $ROOT/java/build/classes sekreto.Cli" ;;
  csharp) echo "dotnet $ROOT/csharp/cli/bin/Release/net8.0/SekretoCli.dll" ;;
  *) echo "" ;;
  esac
}

cli_ready() {
  local lang=$1
  case $lang in
  typescript) [ -f "$ROOT/typescript/dist/cli/sekreto-cli.js" ] ;;
  javascript) [ -f "$ROOT/javascript/cli/sekreto-cli.js" ] ;;
  python) [ -f "$ROOT/python/cli/sekreto_cli.py" ] ;;
  ruby) [ -f "$ROOT/ruby/cli/sekreto_cli.rb" ] ;;
  php) [ -f "$ROOT/php/cli/sekreto-cli.php" ] ;;
  perl) [ -f "$ROOT/perl/cli/sekreto-cli.pl" ] ;;
  go) [ -x "$ROOT/go/build/sekreto-cli" ] ;;
  rust) [ -x "$ROOT/rust/target/release/sekreto-cli" ] ;;
  java) [ -f "$ROOT/java/build/classes/sekreto/Cli.class" ] ;;
  csharp) [ -f "$ROOT/csharp/cli/bin/Release/net8.0/SekretoCli.dll" ] ;;
  *) false ;;
  esac
}

ALL_LANGS="typescript javascript python ruby php perl go rust java csharp"
LANGS=${*:-$ALL_LANGS}

# Run one CLI once, with one secret source configured, and check the result.
#
#   check <lang> <source> <expect: ok|deny> <env assignments...>
#
# STORE, when set, is passed as --store: the CLI must then take the secret
# from that named store rather than from whichever provider answers first.
check() {
  local lang=$1 source=$2 expect=$3
  shift 3

  local cmd
  cmd=$(cli_cmd "$lang")

  local storeargs=()
  if [ -n "${STORE:-}" ]; then
    storeargs=(--store "$STORE")
  fi

  local out rc
  out=$(cd "$WORK/run" && env -i \
    PATH="$PATH" HOME="$HOME" \
    JAVA_HOME="${JAVA_HOME:-}" DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_NOLOGO=1 \
    "$@" \
    $cmd "$API_URL" --source "$source" "${storeargs[@]}" 2>&1)
  rc=$?

  local label="$lang/$source"
  [ -n "${STORE:-}" ] && label="$lang/$source->${STORE}"

  if [ "$expect" = ok ]; then
    # The API echoes the caller back, so a pass means the whole path worked:
    # secret read -> bearer token accepted -> response parsed.
    if [ $rc -eq 0 ] && [ "$out" = "{\"ok\":true,\"lang\":\"$lang\",\"source\":\"$source\",\"store\":\"${STORE:-}\",\"caller\":\"$lang\"}" ]; then
      pass=$((pass + 1))
      printf '   %s %-28s\n' "$(green ok)" "$label"
      return 0
    fi
  else
    # A wrong or absent secret must be refused, and the output must not leak
    # the real token even so.
    if [ $rc -ne 0 ] && ! echo "$out" | grep -qF "$TOKEN"; then
      pass=$((pass + 1))
      printf '   %s %-28s (denied, as expected)\n' "$(green ok)" "$label"
      return 0
    fi
  fi

  fail=$((fail + 1))
  FAILED+=("$label")
  printf '   %s %-28s rc=%s\n' "$(red FAIL)" "$label" "$rc"
  echo "        $out" | head -5
  return 1
}

for lang in $LANGS; do
  if [ -z "$(cli_cmd "$lang")" ]; then
    echo "== $lang == unknown language, skipped"
    continue
  fi

  if ! cli_ready "$lang"; then
    if [ -n "${REQUIRE_ALL:-}" ]; then
      echo "== $lang == $(red "NOT BUILT") (REQUIRE_ALL is set)"
      fail=$((fail + 1))
      FAILED+=("$lang/not-built")
      continue
    fi
    echo "== $lang == not built, skipped"
    continue
  fi

  echo "== $lang =="

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

echo
if [ $fail -eq 0 ]; then
  echo "$(green PASS) $pass checks"
  exit 0
fi

echo "$(red FAIL) $fail of $((pass + fail)) checks:"
for name in "${FAILED[@]}"; do
  echo "   $name"
done
exit 1
