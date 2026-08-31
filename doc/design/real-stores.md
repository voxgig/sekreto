# Testing against the real secret stores

sekreto has ten ports and thirteen provider kinds, and until now every
network provider was tested against a mock: `test/mockhashicorp.js`,
`test/mockaws.js` and their five siblings, each reimplementing a
vendor's published wire protocol in a hundred lines of Node.

Those mocks are good, and they are not going anywhere. But a mock is a
**claim** — "this is what the real server does" — written by the same
people who wrote the client, from the same reading of the same
documentation. Where that reading is wrong, the mock and the port are
wrong together and agree with each other, which is exactly the shape of
bug no amount of mock testing can find.

`test/realstores.sh` is the other half: the same CLIs, the same one
secret, against the real servers in Docker.

## The two suites

|  | `test/integration.sh` | `test/realstores.sh` |
|---|---|---|
| servers | mocks, in-tree | real, in containers |
| runs in | ~20 seconds | ~3 minutes, plus image pulls |
| when | every push and PR | on demand, and weekly |
| proves | the protocol as we understand it | the protocol as the vendor implements it |
| unique strength | verifies SigV4 signatures byte for byte; models Vault Enterprise namespaces; covers stores with no local server | real auth, real authorization, real TLS, real error bodies |

Neither subsumes the other, and the mock suite remains the one that
guards every push. A real-store run is slow, needs images, and depends
on servers we do not control; making it a gate on every PR would trade a
fast, hermetic signal for a flaky one. It is a periodic check on whether
the fast signal is still telling the truth.

## What it has already found

Both of these passed the mock suite and failed against the real server.

### RS-1 — AppRole tokens are scoped, and the mock's are not

`test/mockhashicorp.js` issues one token that reads anything. A real
Vault issues a token scoped by policy, so a login can succeed and every
read after it be refused. Against a real Vault every port failed the
AppRole check with `403` until the bootstrap attached a policy granting
`read` on `secret/data/*`.

Nothing was wrong with the ports here — but nothing in the mock suite
was testing the half of AppRole that actually goes wrong in production,
and now something is.

### RS-2 — the Java port could not talk to any Fastify server *(fixed)*

`java.net.http.HttpClient` defaults to `HTTP_2`, and over cleartext that
means an h2c upgrade: the first request goes out carrying `Upgrade: h2c`,
the declared `Content-Length`, and **no body**; the body follows only
after the server declines. Fastify checks the two against each other and
rejects the request outright:

```
FST_ERR_CTP_INVALID_CONTENT_LENGTH: Request body size did not match Content-Length
```

Infisical is a Fastify application, so every POST the Java port made to
it failed before it was read — `infisical login failed: 500`, with the
cause visible only in the server's log. The mocks are Node's own `http`
module, which does not object, so nine ports passed and the tenth had a
bug that would have hit any user with a real Infisical.

Fixed in `java/src/com/voxgig/sekreto/Providers.java` by pinning the
client to HTTP/1.1. No vault API sekreto speaks needs HTTP/2.

## What can actually be run, and what that is worth

Not every store can be run locally, and the differences matter enough to
be written down rather than discovered.

| store | what runs locally | fidelity | credentials really checked? |
|---|---|---|---|
| HashiCorp Vault | `hashicorp/vault` dev mode | **the vendor's own server** | yes — token, policy, AppRole |
| Infisical | `infisical/infisical` self-hosted | **the vendor's own server** | yes — real Universal Auth login |
| boru | the real binary, built from source | **the real thing** | yes — capability tokens |
| AWS | LocalStack | third-party emulator | **no** — see below |
| Azure Key Vault | lowkey-vault | third-party emulator | no (any bearer accepted), but **real TLS** |
| GCP Secret Manager | nothing worth running | — | no |
| 1Password Connect | nothing (needs a paid account) | — | — |
| Doppler | nothing (SaaS only) | — | — |

### HashiCorp Vault — the real server

`vault server -dev`, unsealed, in memory, KV v2 at `secret/`. The
bootstrap adds what dev mode does not: a KV v1 engine, an empty mount to
read misses from, an AppRole, and the policy that scopes its token.

This is the strongest service in the stack. It is the vendor's own
binary, it really validates `X-Vault-Token`, and it really enforces
policy — which is how RS-1 surfaced.

Two things it cannot cover, both of which stay with the mock:

- **Namespaces** (`X-Vault-Namespace`) are Vault Enterprise, and the
  Enterprise image needs a licence. `test/mockhashicorp.js` demands the
  header on every request, so the port's namespace support is tested
  there or not at all.
- **Kubernetes auth** validates the service-account JWT by calling a
  cluster's TokenReview API, so it needs a cluster. The mock's
  kubernetes login is the only coverage. (Vault's `jwt` auth method can
  validate a static key offline, but sekreto posts to
  `/v1/auth/kubernetes/login`, so that would test a different endpoint
  from the one the library uses.)

### AWS — LocalStack, and what it does not check

Secrets Manager and SSM Parameter Store are both in LocalStack's
community edition, and neither AWS service can be run locally for real:
AWS distributes no server for either, unlike DynamoDB.

**LocalStack does not verify SigV4 signatures.** Measured, not assumed —
a `CreateSecret` signed `Signature=deadbeef` is accepted and fails only
later, on an unrelated missing field. A port whose signing was broken in
every byte would pass every check here.

So the division of labour is the reverse of the usual one: for AWS
**the mock is the stronger test**. `test/mockaws.js` re-derives the
signature of every request from scratch and refuses a mismatch, and that
is where AWS signing is guarded. What LocalStack proves is everything
else — the JSON-1.1 envelope, `X-Amz-Target` dispatch, response shapes,
and the `ResourceNotFoundException` / `ParameterNotFound` error types
that separate a miss from a failure.

**On moto.** `motoserver/moto` does verify signatures when
`INITIAL_NO_AUTH_ACTION_COUNT` is set, re-deriving them with botocore —
an implementation independent of both our mock and our ports, which is
the one thing that could catch a misreading shared by both. It is not in
the stack because moto's standalone server routes to a service by the
**Host** header, and sekreto sends `Host: 127.0.0.1:<port>`; using it
would need a per-service hostname or a rewriting proxy in front, plus a
SigV4-signing bootstrap, since seeding must itself be signed once auth
is on. Worth doing, and worth doing deliberately rather than as a
footnote to this change.

### Azure Key Vault — an emulator, but the only real TLS anywhere

Microsoft ships no Key Vault emulator (Azurite is storage only).
lowkey-vault is a third-party one, and it accepts any bearer token — so
the client-credentials login sekreto performs against Entra has no
counterpart here and stays covered by `test/mockazure.js`.

What makes it worth running anyway is the transport. lowkey-vault serves
the Key Vault API over **HTTPS only**, with a self-signed certificate.
Every other server in both suites is plain HTTP on loopback, which means
this is **the only place any port's TLS stack is exercised at all** —
certificate verification included, against a certificate the port must
be told to trust.

That immediately found two things.

The **Perl** port needs `IO::Socket::SSL` for HTTPS and it is not a core
module, so on a machine without it the Perl port cannot reach any real
vault. That is the environment's gap rather than the port's, so the check
skips by name.

The **Zig** port cannot be told about a private CA at all.
`std.crypto.Certificate.Bundle` scans a fixed list of system paths —
`/etc/ssl/certs/ca-certificates.crt` and its equivalents — and reads no
environment variable, so short of installing the certificate system-wide
there is no way in. The Rust port hit the same wall, its root set being
compiled into the binary, and answered it with `SEKRETO_CA_BUNDLE`; the
Zig port wants the same and does not have it yet. Until then the check
skips, which is the honest reading: an internal Vault behind a corporate
CA is not reachable from the Zig port today.

Neither of these is visible from the mock suite, because nothing in it
speaks TLS.

Each language is told about the certificate in the way it accepts one,
and there is no arrangement that satisfies all of them at once:

| port | how |
|---|---|
| typescript, javascript | `NODE_EXTRA_CA_CERTS` |
| python, ruby, php, go, csharp | `SSL_CERT_FILE` |
| rust | `SEKRETO_CA_BUNDLE` — rustls carries a compiled-in root set, so this is the port's own documented way in |
| java | a keystore via `-Djavax.net.ssl.trustStore` |
| kotlin | the same keystore as java — one JVM, one mechanism |
| perl | `SSL_CERT_FILE`, if `IO::Socket::SSL` is installed |
| **zig** | **nothing** — see below |

### Infisical — the real server, and a bootstrap worth reading

Self-hosted Infisical with its Postgres and Redis. The Universal Auth
login sekreto performs is the real endpoint issuing a real JWT, which is
what makes RS-2 visible.

Infisical is normally set up by clicking through onboarding, which a
test run cannot do, so `bootstrap/infisical.sh` drives the endpoints
behind those screens. Two steps are easy to miss and fail confusingly:

1. The JWT from `/api/v1/admin/signup` carries **no organisation**, and
   every org-scoped call refuses it with "no organization found in
   request". `/api/v3/auth/select-organization` exchanges it for one
   that works.
2. A machine identity that is not a **member of the project** logs in
   perfectly well and then reads nothing.

The signup endpoint only works on an instance with no admin, so this
suite always starts from an empty database.

### boru — the real binary, as always

There is no boru mock in this repository and there should not be one:
boru's wire protocol ships inside the same binary its CLI does, so a
mock would test the imitation. The container builds boru from source and
runs `boru vault serve`; where that build cannot run, a `boru` binary on
the machine is used instead — it is the same binary — and where there is
neither, the boru checks skip.

### The three that cannot be run at all

- **GCP Secret Manager.** Google ships emulators for Pub/Sub, Firestore,
  Datastore, Bigtable and Spanner, and has never shipped one for Secret
  Manager. Third-party fakes exist, but none can validate a Google
  access token — they are signed by Google's own token endpoints and no
  offline process can check one, so the best of them only checks that an
  `Authorization` header is *present*. Adding one would put a container
  in the stack whose green means less than the mock's, while reading as
  "GCP is covered". It is deliberately not here.
- **1Password Connect.** The official images are real, but they need a
  `1password-credentials.json` that only a paid Business or Teams
  account can issue. There is no offline mode.
- **Doppler.** SaaS only. There is no on-premises or container
  distribution of the Doppler API to run.

For all three, `test/integration.sh`'s mocks remain the only coverage,
and the honest way to do better is a job against the real service gated
on repository secrets — see below.

## Rules the harness keeps

The same ones `test/integration.sh` keeps, because a real-store run has
more ways to be vacuous, not fewer.

- **A store that is not up is skipped by name, and counted.** Nothing
  silently falls back to a mock. `REQUIRE_STORES=1` turns a skip into a
  failure, which is what CI sets.
- **Zero checks is a failure.** A run where every store was absent and
  every port unbuilt proves nothing, and must not read as green.
- **Every CLI runs from an empty directory with a scrubbed environment**
  (`env -i`), so a stray `.env` cannot make a run pass by accident.
- **A denial must not leak.** Every failure check greps the output for
  the real secret; printing it while refusing is still a failure.
- **The port is claimed before a server is started.** A mock that cannot
  bind dies while whatever already holds the port answers the readiness
  probe, and the suite then tests the wrong server — which is how a
  developer's own `vault server -dev` on port 8200 turned every
  HashiCorp check red. Both suites now refuse to start on a busy port
  and say so.

The two suites use separate port blocks — 82xx for the mocks, 83xx for
the real stores — so they can run at the same time, and neither collides
with a store's own default.

## Running it

```sh
make realstores                 # bring the stack up, run, tear it down
test/realstores.sh go rust      # just these ports
SEKRETO_KEEP=1 test/realstores.sh   # leave the stack running
```

Against servers you already have, with no Docker involved at all:

```sh
SEKRETO_COMPOSE=0 \
  REAL_VAULT_ADDR=https://vault.example.com \
  REAL_VAULT_TOKEN=... \
  test/realstores.sh
```

Every store's address is a variable, so the same harness runs against a
vault on your machine, a real AWS account, or a real Infisical.

## When CI runs it

`.github/workflows/real-stores.yml`, on `workflow_dispatch` and on a
weekly schedule. Not on push, and not on pull requests.

The reasoning is the same as for any slow, externally-dependent suite:
it pulls several images, waits on database migrations, and depends on
servers whose new releases can change behaviour without anything in this
repository changing at all. As a gate on every PR it would be a flake
generator. On a schedule it is exactly what it should be — a periodic
check on whether the fast suite is still telling the truth, arriving as
its own failure rather than as noise on someone's PR.

A scheduled failure is still a failure, and means one of two things: a
port has a bug the mocks do not model, or a mock has drifted from the
server it imitates. Both are worth a morning.

### Testing against the real cloud services

Out of scope here, and the shape is known: a second workflow, also
`workflow_dispatch` and scheduled, holding real credentials in
repository secrets and skipping wholesale when they are absent —

| store | what the secret would have to be |
|---|---|
| GCP Secret Manager | a service-account key or workload identity federation, with `roles/secretmanager.secretAccessor` |
| 1Password Connect | a Connect credentials file and token from a Business/Teams account |
| Doppler | a service token for a throwaway project |
| AWS | an IAM role, which would also test signature rejection properly |
| Vault Enterprise | a licence, which would cover namespaces |

Each is a live account, a cost, and a credential that a fork's PR must
never reach. Worth doing for GCP and Doppler in particular, since they
have no local coverage of any kind — but as its own change, with its own
review of who can trigger it.
