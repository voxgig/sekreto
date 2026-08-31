#!/bin/sh
#
# Create a boru vault holding the one test secret, mint a capability
# token for it, and serve boru's wire protocol.
#
# The token is written to /work/token for the harness to read back with
# `docker compose exec`, and /work/ready is only created once serving has
# actually started - a container that is listening but has not yet been
# granted a token would otherwise look ready and refuse every read.

set -eu

: "${BORU_VAULT_PASSPHRASE:?BORU_VAULT_PASSPHRASE is required}"
: "${SEKRETO_TOKEN:?SEKRETO_TOKEN is required}"

export BORU_HOME=/work

rm -f /work/ready /work/token

boru vault init --backend=file >/work/init.log 2>&1

# `api.token` is a valid boru alias as it stands - boru aliases keep their
# dots, so there is no `api`/`token` split here, unlike a HashiCorp KV.
printf '%s\n' "$SEKRETO_TOKEN" | boru vault add api.token --from-stdin >>/work/init.log 2>&1

# A namespace wildcard: read of every root-namespace secret, wire protocol
# only. The token is shown once, so it is captured here or not at all.
boru vault grant '*' 2>>/work/init.log | awk '/^token:/{print $2}' >/work/token

if [ ! -s /work/token ]; then
  echo "boru: no capability token was issued" >&2
  cat /work/init.log >&2
  exit 1
fi

# --allow-public because a container has to bind its published interface,
# not loopback. Nothing outside the compose network can reach it: the
# published port is bound to 127.0.0.1 on the host.
boru vault serve --listen=0.0.0.0:8308 --allow-public &
SERVE=$!

# Ready means answering, not merely started. Any HTTP response counts,
# including the 403 an unauthenticated read earns: what is being waited
# for is the server, not a successful read.
tries=0
while [ "$tries" -lt 60 ]; do
  if wget -S -q -O /dev/null http://127.0.0.1:8308/ 2>&1 | grep -q 'HTTP/'; then
    touch /work/ready
    break
  fi
  tries=$((tries + 1))
  sleep 1
done

wait "$SERVE"
