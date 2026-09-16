# sekreto — Perl

The Perl port of [sekreto](../README.md): one interface for secrets,
wherever they live.

```sh
make deps                     # find (or fetch) voxgig/plugin
make test                     # the conformance suite and the plugin seam
```

`HTTP::Tiny` and `JSON::PP` are both core Perl, so this port declares no
CPAN dependency. Its one dependency is
[voxgig/plugin](https://github.com/voxgig/plugin), which itself takes
nothing: perl has no manifest to declare it in, so the checkout is found the
way omni is - `$PLUGIN_HOME`, then a sibling checkout - and `make deps`
fetches a shallow clone when there is none. The library searches no path;
`t/PluginHome.pm` does the searching for both the tests and the CLI.

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
| `lib/Voxgig/Sekreto/Providers.pm` | the four built-in kinds, and `providerplugin` |
| `lib/Voxgig/Sekreto/Addr.pm` | `checkaddr` - may a token be sent here in the clear? |
| `plugins/Voxgig/Sekreto/Plugins/` | the eleven plugin kinds, one module each |
| `plugins/Voxgig/Sekreto/Plugins.pm` | the full set, `allplugins` |
| `t/sekreto.t` | the conformance suite |
| `t/plugins.t` | the plugin seam, from both sides |
| `t/minivault.t` | the mini vault, and the committed files every port reads |
| `cli/sekreto-cli.pl` | the app that needs a secret |

## Four kinds are built in; the rest are plugins

`env`, `memory`, `dotenv` and `file` read at most a local file, and they are
in `lib/`. Every kind that opens a socket, signs a request, or spawns a
process - the vault clients, the cloud stores, the two CLIs, and `sigv4`
with them - is a [voxgig/plugin](https://github.com/voxgig/plugin)
definition under `plugins/`, and a `Sekreto` can build only the kinds its
constructor was handed:

```perl
use Voxgig::Sekreto ();
use Voxgig::Sekreto::Plugins::Hashicorp qw(hashicorp);

my $secrets = Voxgig::Sekreto->new({
    plugins   => [ hashicorp() ],
    providers => [ { kind => 'env' },
                   { kind => 'hashicorp', addr => $addr, token => $token } ],
});
```

`allplugins()` from `Voxgig::Sekreto::Plugins` is every kind at once, for a
program - the CLI, the conformance suite - whose chain is decided at run
time.

**`plugins/` is a second `@INC` root, not a subdirectory of `lib/`.** That is
what makes the boundary real rather than nominal: with `-Ilib` alone not one
plugin module is findable, so the core cannot reach one even by mistake, and
`t/plugins.t` proves it in a fresh interpreter with `PERL5LIB` cleared. A
kind that was not passed in is refused by name, saying what to pass.

## The mini vault

`plugins/Voxgig/Sekreto/Plugins/Minivault.pm` is a store this port owns
outright rather than a client for a server somebody else runs: every
secret, encrypted, in one binary file. It has a master key and restricted
keys, and it is the port's worked example of a definition publishing an
API beside its provider.

```perl
use Voxgig::Sekreto::Plugins::Minivault qw(createvault minivault vaultof);

my $vault = createvault( { file => 'app.skmv', passphrase => $master } );
$vault->set( 'api.token', 'tok01' );
$vault->grant( { key => 'ci', passphrase => $ci, names => ['api.token'] } );

my $secrets = Voxgig::Sekreto->new({
    plugins   => [ minivault() ],
    providers => [ { kind => 'minivault', file => 'app.skmv',
                     vaultkey => 'ci', passphrase => $ci } ],
});

$secrets->get('api.token');          # the chain reads
vaultof($secrets)->list;             # the API writes
```

A chain reads; writing is a deliberate act with an API of its own, so the
definition exports `vault` beside `provider` and `vaultof` reads it back
off the chain's host. That is why this one definition is written out
rather than built by `providerplugin`, which publishes the provider and
nothing else. `master` and `write` come back as 1/0, as Perl truth goes,
which is what `validname` in the core does with the same question.

**CryptX is the one kind with a package behind it, and it is declared the
way https is.** The format needs AES-256-GCM, PBKDF2-HMAC-SHA256,
HMAC-SHA256 and a CSPRNG. Perl's core has SHA-256 in `Digest::SHA` and
none of the other three, so the whole of the cryptography comes from
`CryptX` — one audited module rather than three of them plus a block
cipher written in the plugin, which is the thing the dependency rule
exists to forbid: a table-driven AES passes every known-answer test in the
world and still hands its key to anyone who can time a cache.

```sh
perl -e 'print eval { require Crypt::AuthEnc::GCM; 1 } ? "vault: yes\n" : "vault: no\n"'
```

Where that says no, install it from CPAN — on Debian and Ubuntu it is
`libcryptx-perl`. Missing, the kind fails closed and names the package:
`sekreto: minivault: no AES-256-GCM available: CryptX must be installed
for the mini vault`. It is loaded at the FIRST SEAL and never at compile
time, so `allplugins` costs nothing on a Perl without it, and a chain that
configures no vault runs as before.

**The vault takes text, and stores its UTF-8 encoding.** That is what the
other twenty ports store, so a passphrase, a key id, or a value that reached
a KDF or a cipher as anything else would produce a vault none of them
could open. Perl holds the same string of characters as Latin-1 bytes or as
UTF-8 depending on what has happened to it, and `utf8::upgrade` moves it
between the two without changing the string — so the conversion is
unconditional rather than a test of `utf8::is_utf8`, which would hash one
passphrase two ways. ASCII is unchanged by it, which is every passphrase
in the fixtures and most in the world.

The other side of that contract is the boundary: a scalar that is already
UTF-8 bytes, which is what `%ENV` and a file hand back, is decoded before
it reaches the vault. `cli/sekreto-cli.pl` does that for the three vault
environment variables, and a program reading a passphrase from a file
should do the same. Values come back decoded, as `JSON::PP` hands a
provider its values.

**No lock, and for a reason that is not the usual one.** Every port that
can reach one file from two threads keys a lock by the vault's absolute
path. Perl's interpreter threads copy rather than share: `threads->create`
hands the child its own copy of every variable, a lock table included, so
a table here would serialize nothing — and `threads::shared` cannot lock a
hash element, which is what a per-path table is made of. Without ithreads,
which Perl's own documentation discourages, there is no second thread of
execution to interleave with, exactly as in typescript, javascript, php,
lua and ocaml. Two ithreads writing one vault are the cross-process case,
which the exclusive create and the atomic rename bound and do not
serialize.

Ports carrying this kind read each other's files, which `t/minivault.t`
checks against every committed vault in `test/fixture/`, including the one
this port wrote:

```sh
make vaulttest
```

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
