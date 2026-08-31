#!/usr/bin/env bash
#
# Bring a fresh self-hosted Infisical up to the point where sekreto can
# read a secret from it: an admin, an organisation, a project, a machine
# identity with Universal Auth, and the secret itself.
#
#   INFISICAL_ADDR=http://127.0.0.1:8307 SEKRETO_TOKEN=... \
#     bootstrap/infisical.sh
#
# The machine identity's credentials come back on stdout as shell
# assignments; everything else goes to stderr.
#
# ALL OF THIS IS THE API, NOT THE WEB UI. Infisical is normally set up by
# clicking through onboarding, which a test run cannot do, so each step
# below is the endpoint behind one of those screens. The sequence matters
# and is not obvious:
#
#   1. /api/v1/admin/signup       creates the first user AND its org, and
#                                 hands back a JWT. Only works once, on an
#                                 instance with no admin - which is why
#                                 this suite starts from an empty database.
#   2. /api/v3/auth/select-organization
#                                 the signup JWT carries no organisation,
#                                 and every org-scoped call refuses it with
#                                 "no organization found in request". This
#                                 exchanges it for one that works.
#   3. the project, the identity, its Universal Auth configuration, its
#      client secret, and its membership of the project - five calls,
#      because an identity that is not a member of the project can log in
#      perfectly well and then read nothing.
#
# Steps 2 and 3's last call are the two that are easy to miss and produce
# confusing failures rather than obvious ones.

set -eu

ADDR=${INFISICAL_ADDR:?INFISICAL_ADDR is required}
SECRET=${SEKRETO_TOKEN:?SEKRETO_TOKEN is required}

ADDR=${ADDR%/}

EMAIL=${INFISICAL_ADMIN_EMAIL:-admin@sekreto.test}
PASSWORD=${INFISICAL_ADMIN_PASSWORD:-Sekreto-Test-1234!}

# node, not jq: the suite already requires node for api/server.js and the
# mocks, and jq is not everywhere.
field() {
  node -e '
    let text = ""
    process.stdin.on("data", (d) => (text += d))
    process.stdin.on("end", () => {
      let value
      try {
        value = process.argv[1].split(".").reduce((o, k) => (o ? o[k] : undefined), JSON.parse(text))
      } catch (err) {
        value = undefined
      }
      process.stdout.write(undefined === value || null === value ? "" : String(value))
    })
  ' "$1"
}

# The body goes in on STDIN, not the command line: this script is also
# how someone points the suite at a real Infisical, and there the secret
# is real. /proc/*/cmdline is world-readable.
#
# The status is checked, because curl exits 0 on a 4xx as happily as on a
# 200 - so `set -e` catches nothing, and a membership or a secret that
# silently did not get written leaves an instance that logs in fine and
# then reads nothing.
post() {
  local path=$1 body=$2 auth=${3:-}
  local out code
  if [ -n "$auth" ]; then
    out=$(printf '%s' "$body" | curl -sS -X POST "$ADDR$path" \
      -H "authorization: Bearer $auth" -H 'content-type: application/json' \
      --data @- -w '\n%{http_code}')
  else
    out=$(printf '%s' "$body" | curl -sS -X POST "$ADDR$path" \
      -H 'content-type: application/json' --data @- -w '\n%{http_code}')
  fi
  code=${out##*$'\n'}
  case $code in
  2*) printf '%s' "${out%$'\n'*}" ;;
  *)
    echo "infisical: POST $path answered $code" >&2
    return 1
    ;;
  esac
}

echo "infisical: bootstrapping $ADDR" >&2

signup=$(post /api/v1/admin/signup \
  "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\",\"firstName\":\"Sek\",\"lastName\":\"Reto\"}" || true)

jwt=$(printf '%s' "$signup" | field token)
org=$(printf '%s' "$signup" | field organization.id)

if [ -z "$jwt" ] || [ -z "$org" ]; then
  # The message only. The body of a signup response carries the admin
  # JWT, and this goes straight into a CI log.
  echo "infisical: admin signup failed - is this instance already set up?" >&2
  echo "infisical: $(printf '%s' "$signup" | field message | head -c 200)" >&2
  exit 1
fi

# The signup JWT is not org-scoped; without this every call below is a 401.
orgjwt=$(post /api/v3/auth/select-organization "{\"organizationId\":\"$org\"}" "$jwt" | field token)
[ -n "$orgjwt" ] || { echo "infisical: could not select the organisation" >&2; exit 1; }

project=$(post /api/v2/workspace "{\"projectName\":\"sekreto\",\"organizationId\":\"$org\"}" "$orgjwt" |
  field project.id)
[ -n "$project" ] || { echo "infisical: could not create the project" >&2; exit 1; }

identity=$(post /api/v1/identities \
  "{\"name\":\"sekreto-machine\",\"organizationId\":\"$org\",\"role\":\"member\"}" "$orgjwt" |
  field identity.id)
[ -n "$identity" ] || { echo "infisical: could not create the machine identity" >&2; exit 1; }

clientid=$(post "/api/v1/auth/universal-auth/identities/$identity" \
  '{"clientSecretTrustedIps":[{"ipAddress":"0.0.0.0/0"}],"accessTokenTrustedIps":[{"ipAddress":"0.0.0.0/0"}],"accessTokenTTL":2592000,"accessTokenMaxTTL":2592000,"accessTokenNumUsesLimit":0}' \
  "$orgjwt" | field identityUniversalAuth.clientId)
[ -n "$clientid" ] || { echo "infisical: could not configure universal auth" >&2; exit 1; }

clientsecret=$(post "/api/v1/auth/universal-auth/identities/$identity/client-secrets" \
  '{"description":"sekreto realstores","numUsesLimit":0,"ttl":0}' "$orgjwt" | field clientSecret)
[ -n "$clientsecret" ] || { echo "infisical: could not mint a client secret" >&2; exit 1; }

# Without this the identity logs in and then reads nothing.
post "/api/v2/workspace/$project/identity-memberships/$identity" '{"role":"admin"}' "$orgjwt" >/dev/null ||
  { echo "infisical: could not add the identity to the project" >&2; exit 1; }

# Infisical keys secrets the way the environment does, so `api.token` is
# the entry `API_TOKEN` - envkey's answer, which every port computes.
post /api/v3/secrets/raw/API_TOKEN \
  "{\"workspaceId\":\"$project\",\"environment\":\"prod\",\"secretPath\":\"/\",\"secretValue\":\"$SECRET\",\"type\":\"shared\"}" \
  "$orgjwt" >/dev/null ||
  { echo "infisical: could not write the secret" >&2; exit 1; }

echo "infisical: project $project seeded, machine identity ready" >&2

# Quoted, because the caller evals these and a client secret is opaque.
printf 'INF_PROJECT=%q\n' "$project"
printf 'INF_CLIENT=%q\n' "$clientid"
printf 'INF_SECRET=%q\n' "$clientsecret"
