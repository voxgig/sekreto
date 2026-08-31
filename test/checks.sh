#!/usr/bin/env bash
#
# What "a check" means, defined once.
#
# There are two integration suites and they must not drift:
#
#   test/integration.sh   every port's CLI against MOCK servers - the
#                         published wire protocols, reimplemented in-tree.
#                         Fast, hermetic, and runs on every CI push.
#   test/realstores.sh    the same CLIs against the REAL servers, in
#                         Docker. Slow, needs images, runs on demand and
#                         on a schedule.
#
# The mocks are a claim about what the real servers do. That claim is
# only worth something if both suites agree on what passing means, so
# the check itself - how a CLI is invoked, what output counts as a pass,
# what counts as a leak - lives here rather than in either script.
#
# A caller sources this file, sets the four variables below, calls
# `check` as many times as it likes, and ends with `tally`.
#
#   ROOT     the repository root
#   RUNDIR   an empty directory to run each CLI from, so that a stray
#            .env anywhere in the repo cannot make a run pass by accident
#   API_URL  the token-protected API the CLI must reach
#   TOKEN    the secret that API expects - checked for in failure output,
#            because a port that leaks the secret while complaining has
#            failed even if it also failed correctly

# ------------------------------------------------------------------ state

pass=0
fail=0
skip=0
FAILED=()
SKIPPED=()

green() { printf '\033[32m%s\033[0m' "$1"; }
red() { printf '\033[31m%s\033[0m' "$1"; }
yellow() { printf '\033[33m%s\033[0m' "$1"; }

# ------------------------------------------------------------------ waiting

# Wait for a port to answer, rather than sleeping and hoping.
#
#   waitport <port> <name> [tries]
#
# Tries are tenths of a second. The default suits a process that is
# already running; a container that has to start a JVM or migrate a
# database wants a much larger one.
waitport() {
  local port=$1 name=$2 limit=${3:-100} tries=0
  while [ "$tries" -lt "$limit" ]; do
    if (exec 3<>/dev/tcp/127.0.0.1/"$port") 2>/dev/null; then
      exec 3<&- 3>&-
      return 0
    fi
    tries=$((tries + 1))
    sleep 0.1
  done
  echo "sekreto: $name did not start on port $port" >&2
  return 1
}

# Refuse to start a server on a port something else already holds.
#
#   portfree <port> <name>
#
# Checked BEFORE the server is launched, deliberately. Checking afterwards
# cannot work: a mock that loses the bind takes a few milliseconds to die,
# while a squatter answers the readiness probe instantly, so the race is
# always lost in the squatter's favour - and the suite then tests whatever
# else is on the port. Here the answer is knowable with no race at all.
portfree() {
  local port=$1 name=$2
  if (exec 3<>/dev/tcp/127.0.0.1/"$port") 2>/dev/null; then
    exec 3<&- 3>&-
    echo "sekreto: something is already listening on port $port, which $name needs." >&2
    echo "sekreto: stop it, or set the port variable for $name, and run again." >&2
    return 1
  fi
  return 0
}

# Wait for an HTTP endpoint to return one of a set of status codes.
#
#   waithttp <url> <name> <codes> [tries]
#
# A port being open is not the same as a server being ready: Vault
# answers 501 while uninitialised, Infisical serves a holding page while
# it migrates, and LocalStack accepts connections long before a service
# is up. `codes` is a space-separated list of what ready looks like.
waithttp() {
  local url=$1 name=$2 codes=$3 limit=${4:-300} tries=0 got=''
  while [ "$tries" -lt "$limit" ]; do
    got=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$url" 2>/dev/null || echo 000)
    for want in $codes; do
      if [ "$got" = "$want" ]; then
        return 0
      fi
    done
    tries=$((tries + 1))
    sleep 1
  done
  echo "sekreto: $name not ready at $url (last status $got)" >&2
  return 1
}

# ------------------------------------------------------------------- ports

# Every port, in the order the top-level Makefile lists them.
ALL_LANGS="typescript javascript python ruby php perl go rust java csharp zig"

# How to invoke each port's CLI.
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
  zig) echo "$ROOT/zig/build/sekreto-cli" ;;
  *) echo "" ;;
  esac
}

# Has this port been built? A port that has not is skipped, not failed,
# so a partial checkout still tests what it has - unless REQUIRE_ALL is
# set, which CI does, because there a missing CLI means a build broke.
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
  zig) [ -x "$ROOT/zig/build/sekreto-cli" ] ;;
  *) false ;;
  esac
}

# Decide, once per port, whether to run it at all. Prints the heading.
#
#   port_ready <lang> || continue
port_ready() {
  local lang=$1

  if [ -z "$(cli_cmd "$lang")" ]; then
    echo "== $lang == unknown language, skipped"
    return 1
  fi

  if ! cli_ready "$lang"; then
    if [ -n "${REQUIRE_ALL:-}" ]; then
      echo "== $lang == $(red "NOT BUILT") (REQUIRE_ALL is set)"
      fail=$((fail + 1))
      FAILED+=("$lang/not-built")
      return 1
    fi
    echo "== $lang == not built, skipped"
    return 1
  fi

  echo "== $lang =="
  return 0
}

# ------------------------------------------------------------------ checks

# Run one CLI once, with one secret source configured, and check the
# result.
#
#   check <lang> <source> <expect: ok|deny> <env assignments...>
#
# STORE, when set, is passed as --store: the CLI must then take the
# secret from that named store rather than from whichever provider
# answers first.
#
# LABEL, when set, replaces the printed label - a real-store run wants
# to say which server answered, since several sources share one.
#
# WHY, when set on a `deny` check, is a substring the output must
# contain. Without it a deny check passes on ANY non-zero exit, which
# leaves it blind to the distinction that matters most in this library: a
# provider that correctly reports a MISS and one that wrongly RAISES both
# exit non-zero, and only one of them is a bug. `WHY='unknown secret'`
# says the CLI ran out of providers - what a miss looks like from
# outside - where a store error says something else entirely.
check() {
  local lang=$1 source=$2 expect=$3
  shift 3

  local cmd
  cmd=$(cli_cmd "$lang")

  local storeargs=()
  if [ -n "${STORE:-}" ]; then
    storeargs=(--store "$STORE")
  fi

  # stdout and stderr are captured SEPARATELY, and they are used for
  # different things.
  #
  # What a port promises is a single line of JSON on STDOUT; a runtime is
  # entitled to write to stderr without that being the port's doing. The
  # JVM, told about a truststore through JAVA_TOOL_OPTIONS, announces
  # "Picked up JAVA_TOOL_OPTIONS: ..." on every start - merged into one
  # stream that turns a correct run into a failure over a notice the port
  # never emitted.
  #
  # The leak check reads BOTH, on BOTH paths, and must. A secret printed
  # while succeeding is every bit as leaked as one printed while
  # complaining, and it was the merged capture that used to catch it: the
  # exact-match on stdout no longer sees stderr at all.
  local out err rc
  local errfile="$RUNDIR/.stderr"
  out=$(cd "$RUNDIR" && env -i \
    PATH="$PATH" HOME="$HOME" \
    JAVA_HOME="${JAVA_HOME:-}" DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_NOLOGO=1 \
    "$@" \
    $cmd "$API_URL" --source "$source" "${storeargs[@]}" 2>"$errfile")
  rc=$?
  err=$(cat "$errfile" 2>/dev/null)

  local label="${LABEL:-$lang/$source}"
  [ -n "${STORE:-}" ] && [ -z "${LABEL:-}" ] && label="$lang/$source->${STORE}"

  # Printing the secret is a failure whatever else the run did. Checked
  # before the outcome, so neither branch can forget it.
  local leaked=0
  if printf '%s\n%s\n' "$out" "$err" | grep -qF "$TOKEN"; then
    leaked=1
  fi

  if [ "$expect" = ok ]; then
    # The API echoes the caller back, so a pass means the whole path
    # worked: secret read -> bearer token accepted -> response parsed.
    #
    # The CLI prints the token to the API, never to its own output, so
    # even a successful run must not have it anywhere.
    if [ $rc -eq 0 ] && [ 0 -eq $leaked ] &&
      [ "$out" = "{\"ok\":true,\"lang\":\"$lang\",\"source\":\"$source\",\"store\":\"${STORE:-}\",\"caller\":\"$lang\"}" ]; then
      pass=$((pass + 1))
      printf '   %s %-34s\n' "$(green ok)" "$label"
      return 0
    fi
  else
    # A wrong or absent secret must be refused, and the output must not
    # leak the real token even so.
    local why=0
    if [ -z "${WHY:-}" ] || printf '%s\n%s\n' "$out" "$err" | grep -qF "${WHY}"; then
      why=1
    fi
    if [ $rc -ne 0 ] && [ 0 -eq $leaked ] && [ 1 -eq $why ]; then
      pass=$((pass + 1))
      printf '   %s %-34s (denied, as expected)\n' "$(green ok)" "$label"
      return 0
    fi
  fi

  fail=$((fail + 1))
  FAILED+=("$label")
  if [ 1 -eq $leaked ]; then
    printf '   %s %-34s rc=%s LEAKED THE SECRET\n' "$(red FAIL)" "$label" "$rc"
  else
    printf '   %s %-34s rc=%s\n' "$(red FAIL)" "$label" "$rc"
  fi
  # Redacted, because this output goes to a CI log.
  printf '%s\n%s\n' "$out" "$err" | grep -v '^$' | head -5 |
    sed "s|$TOKEN|[redacted]|g" | sed 's/^/        /'
  return 1
}

# Record a check that could not be run, and say why.
#
#   noted_skip <label> <why>
#
# A skipped check is honest; a faked one is not. Skips are counted and
# listed at the end so a green run cannot quietly mean "nothing ran".
noted_skip() {
  skip=$((skip + 1))
  SKIPPED+=("$1 ($2)")
  printf '   %s %-34s (%s)\n' "$(yellow skip)" "$1" "$2"
}

# ------------------------------------------------------------------- tally

# The final report, and the exit status.
#
# Zero checks is not a pass: if every port was skipped, the suite proved
# nothing, and a vacuous green is worse than a red.
tally() {
  echo
  # The counter, not ${#SKIPPED[@]}: expanding an empty array under
  # `set -u` aborts on bash before 4.4, which is still what stock macOS
  # ships. Inside the branch the array is known non-empty.
  if [ "$skip" -gt 0 ]; then
    echo "$(yellow SKIPPED) $skip:"
    for name in "${SKIPPED[@]}"; do
      echo "   $name"
    done
    echo
  fi

  if [ $pass -eq 0 ] && [ $fail -eq 0 ]; then
    echo "$(red FAIL) 0 checks ran - nothing was built or exercised"
    return 1
  fi

  if [ $fail -eq 0 ]; then
    echo "$(green PASS) $pass checks"
    return 0
  fi

  echo "$(red FAIL) $fail of $((pass + fail)) checks:"
  for name in "${FAILED[@]}"; do
    echo "   $name"
  done
  return 1
}
