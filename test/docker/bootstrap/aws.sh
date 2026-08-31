#!/usr/bin/env bash
#
# Put the test secret into LocalStack's Secrets Manager and SSM Parameter
# Store.
#
#   AWS_ENDPOINT=http://127.0.0.1:8302 SEKRETO_TOKEN=... bootstrap/aws.sh
#
# THIS SEEDS AN EMULATOR, AND IT USES THAT FACT.
#
# The calls below carry a SigV4-shaped Authorization header whose
# signature is nonsense, because LocalStack does not check it - it reads
# the header only far enough to find the access key. That was measured,
# not assumed: a CreateSecret signed `Signature=deadbeef` is accepted and
# fails later, on a missing ClientRequestToken.
#
# Two things follow. Seeding needs no SigV4 implementation, which is why
# this script is thirty lines of curl instead of a dependency on the aws
# CLI. And the AWS signing checks stay with test/mockaws.js, which does
# re-derive every signature: against LocalStack a port with broken
# signing would pass, so a green run here says nothing about signing.
# What it does prove is the rest - the JSON-1.1 envelope, X-Amz-Target
# dispatch, the response shapes, and the not-found error types that
# separate a miss from a failure.
#
# Against REAL AWS none of this applies: seed with the aws CLI and real
# credentials. See doc/design/real-stores.md.

set -eu

ENDPOINT=${AWS_ENDPOINT:?AWS_ENDPOINT is required}
SECRET=${SEKRETO_TOKEN:?SEKRETO_TOKEN is required}
REGION=${AWS_REGION:-us-east-1}
KEYID=${AWS_ACCESS_KEY_ID:-test}

ENDPOINT=${ENDPOINT%/}

call() {
  local target=$1 body=$2
  curl -sS -X POST "$ENDPOINT/" \
    -H 'content-type: application/x-amz-json-1.1' \
    -H "x-amz-target: $target" \
    -H "x-amz-date: 20260101T000000Z" \
    -H "Authorization: AWS4-HMAC-SHA256 Credential=$KEYID/20260101/$REGION/x/aws4_request, SignedHeaders=host, Signature=unchecked-by-localstack" \
    -d "$body"
}

echo "aws: seeding $ENDPOINT" >&2

# `api.token` reads Secrets Manager secret `api` and takes the `token`
# field of its JSON SecretString - the AWS idiom of one JSON map per
# secret, which every port computes from the name for itself.
out=$(call secretsmanager.CreateSecret \
  "{\"Name\":\"api\",\"ClientRequestToken\":\"11111111-2222-3333-4444-555555555555\",\"SecretString\":\"{\\\"token\\\":\\\"$SECRET\\\"}\"}")

# A second run against a live stack finds it already there; update it so
# the value is right either way.
case $out in
*ResourceExistsException*)
  call secretsmanager.PutSecretValue \
    "{\"SecretId\":\"api\",\"ClientRequestToken\":\"66666666-7777-8888-9999-000000000000\",\"SecretString\":\"{\\\"token\\\":\\\"$SECRET\\\"}\"}" >/dev/null
  ;;
esac

# Parameter Store carries flat strings, so the name becomes the path:
# `api.token` is `/api/token`.
call AmazonSSM.PutParameter \
  "{\"Name\":\"/api/token\",\"Value\":\"$SECRET\",\"Type\":\"SecureString\",\"Overwrite\":true}" >/dev/null

echo "aws: seeded secretsmanager api and ssm /api/token" >&2
