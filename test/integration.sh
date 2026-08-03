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

set -u

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)

API_PORT=${API_PORT:-8099}
VAULT_PORT=${VAULT_PORT:-8200}

# The one secret that matters. Long enough that redaction applies to it.
TOKEN=${API_TOKEN:-s3cr3t-integration-token}
VAULT_TOKEN=vault-root-token

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

waitport "$API_PORT" api || { cat "$WORK/api.log"; exit 1; }
waitport "$VAULT_PORT" hashicorp || { cat "$WORK/vault.log"; exit 1; }

echo "   api        http://127.0.0.1:$API_PORT"
echo "   hashicorp  http://127.0.0.1:$VAULT_PORT"

# A real boru vault, holding the same secret under the same name. boru
# stores it in an encrypted keyring on disk; nothing goes over a socket.
BORU_HOME_DIR="$WORK/boruhome"

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
else
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

  # 7. A store that is not in the chain is a mistake, not a miss.
  STORE=nosuchstore check "$lang" env deny API_TOKEN="$TOKEN"

  # 8. No secret anywhere: the CLI must fail, not call the API unauthenticated.
  STORE= check "$lang" env deny SEKRETO_PREFIX=NOSUCH_

  # 9. The wrong secret: the API must refuse it, and the CLI must not print
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
