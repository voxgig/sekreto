# sekreto — Perl

The Perl port of [sekreto](../README.md): one interface for secrets,
wherever they live.

```sh
make test                     # the conformance suite
```

`HTTP::Tiny` and `JSON::PP` are both core Perl, so this port declares no
CPAN dependency.

**https is the exception, and it is not this port's to fix.** `HTTP::Tiny`
loads `IO::Socket::SSL` and `Net::SSLeay` on demand for an https request,
and neither is core — a stock Perl reaches an `http://` vault and cannot
reach an `https://` one. Which kind of Perl you have:

```sh
perl -MHTTP::Tiny -e 'my ($ok, $why) = HTTP::Tiny->can_ssl;
                      print $ok ? "https: yes\n" : "https: no\n$why"'
```

Where that says no, install both from CPAN — on Debian and Ubuntu they are
`libio-socket-ssl-perl` and `libnet-ssleay-perl`.

Missing, it fails closed and says so — `sekreto: cannot reach https://…:
IO::Socket::SSL 1.42 must be installed for https support` — which is a
store that could not answer, never a miss, so the chain stops rather than
falling through to a weaker store. Verification stays on either way
(`verify_SSL => 1`); this port never trades TLS checking for reachability.

`validname` returns 1/0, as Perl truth goes; the conformance suite adapts
that to the spec's `true`/`false` rather than the library handing back JSON
booleans. The redact-what-was-resolved method is `redactall`, to leave
`redact` free as the plain function.

## Layout

| | |
|---|---|
| `lib/Voxgig/Sekreto.pm` | the facade, the name helpers, `parsedotenv`, `redact` |
| `lib/Voxgig/Sekreto/Providers.pm` | the five providers |
| `t/sekreto.t` | the conformance suite |
| `cli/sekreto-cli.pl` | the app that needs a secret |

## Testing

The conformance suite runs [`spec/sekreto.json`](../spec/sekreto.json) —
the same file every port runs — through the Perl
[voxgig/omni](https://github.com/voxgig/omni) runner. Set `OMNI_HOME` if
your omni checkout is not a sibling of this repository.

That suite proves this port computes the same answers as the others. What
proves it can actually *fetch* a secret is the integration run, from the
repository root:

```sh
make integration              # every port
./test/integration.sh perl    # just this one
```

It starts a token-protected API and stand-in HashiCorp and boru vaults,
then runs this port's CLI against them from each secret source in turn:

```sh
(nothing to build)
perl -Ilib cli/sekreto-cli.pl http://127.0.0.1:8099/whoami --source vault
```

## API

See [DOCS.md](../DOCS.md) for the full API. Anything named differently in
Perl is listed there.
