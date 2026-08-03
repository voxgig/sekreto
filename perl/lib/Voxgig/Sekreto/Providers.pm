package Voxgig::Sekreto::Providers;

# The providers a Sekreto chains together.
#
# A provider answers one question: "do you have this secret?" It returns the
# value, or undef to mean "ask the next one". Nothing else about a provider
# is visible to the caller - which is the point: an app reads `api.token`
# and never learns whether it came from the environment, a .env file,
# HashiCorp Vault or a boru vault.
#
# A port of typescript/src/Providers.ts, which is canonical.
#
# HTTP::Tiny and JSON::PP are both core Perl, so this port stays free of
# third-party dependencies.

use strict;
use warnings;

use Exporter 'import';

use HTTP::Tiny ();
use IPC::Open3 ();
use JSON::PP   ();
use Symbol     ();

our @EXPORT_OK = qw(makechain makeprovider);

# Loaded lazily inside the subs below: Voxgig::Sekreto uses this module, so
# a `use` here would be a cycle.
sub envkey   { return Voxgig::Sekreto::envkey(@_) }
sub vaultref { return Voxgig::Sekreto::vaultref(@_) }
sub fail     { return Voxgig::Sekreto::fail(@_) }

# Environment variables: `api.token` from `API_TOKEN`.
{

    package Voxgig::Sekreto::Providers::Env;

    sub new {
        my ( $class, $prefix, $source ) = @_;
        return bless { prefix => $prefix, source => $source }, $class;
    }

    sub lookup {
        my ( $self, $name ) = @_;
        my $key    = Voxgig::Sekreto::Providers::envkey( $name, $self->{prefix} );
        my $source = $self->{source} || \%ENV;
        return $source->{$key};
    }

    sub describe {
        my ($self) = @_;
        return 'env' . ( $self->{prefix} ? ':' . $self->{prefix} : '' );
    }
}

# A `.env` file, read once, keyed exactly like the environment.
{

    package Voxgig::Sekreto::Providers::Dotenv;

    sub new {
        my ( $class, $file, $prefix ) = @_;
        return bless { file => $file, prefix => $prefix, values => undef }, $class;
    }

    sub load {
        my ($self) = @_;

        if ( !defined $self->{values} ) {
            my $text = '';

            # A missing .env file is not an error: it means "no secrets here".
            if ( open( my $handle, '<', $self->{file} ) ) {
                local $/ = undef;
                $text = <$handle>;
                close($handle);
            }

            $self->{values} = Voxgig::Sekreto::parsedotenv($text);
        }

        return $self->{values};
    }

    sub lookup {
        my ( $self, $name ) = @_;
        return $self->load()->{ Voxgig::Sekreto::Providers::envkey( $name, $self->{prefix} ) };
    }

    sub describe {
        my ($self) = @_;
        return 'dotenv:' . $self->{file};
    }
}

# Literal values, keyed like environment variables. The spec uses this to
# test chain behaviour without touching the outside world.
{

    package Voxgig::Sekreto::Providers::Memory;

    sub new {
        my ( $class, $values, $prefix ) = @_;
        return bless { values => $values || {}, prefix => $prefix }, $class;
    }

    sub lookup {
        my ( $self, $name ) = @_;
        return $self->{values}{ Voxgig::Sekreto::Providers::envkey( $name, $self->{prefix} ) };
    }

    sub describe {
        my ($self) = @_;
        return 'memory' . ( $self->{prefix} ? ':' . $self->{prefix} : '' );
    }
}

# GET a URL, returning (status, decoded-json-or-undef). A 404 is a normal
# answer here, not a failure: it means the vault has no such secret.
sub httpget {
    my ( $url, $headers ) = @_;

    my $response = HTTP::Tiny->new( timeout => 10 )->get( $url, { headers => $headers } );

    # HTTP::Tiny reports transport failures as a synthetic 599.
    fail( 'sekreto: cannot reach ' . $url . ': ' . ( $response->{content} || '' ) )
      if 599 == $response->{status};

    my $body = eval { JSON::PP->new->decode( $response->{content} ) };

    return ( $response->{status}, $body );
}

# Refuse to send a Vault token in the clear.
#
# Vault's API is HTTPS in any real deployment; plaintext is a dev-mode
# convenience. Sending `X-Vault-Token` over http to anything but the local
# machine puts both the token and the secret it fetches on the wire for
# anyone on the path, so sekreto will not do it. Loopback stays allowed:
# that is `vault server -dev` and this repo's own test harness.
sub checkaddr {
    my ($addr) = @_;

    return if 0 == index( $addr, 'https://' );

    fail( 'sekreto: not an http(s) address: ' . $addr ) if 0 != index( $addr, 'http://' );

    my $host = ( split( /:/, ( split( m{/}, substr( $addr, 7 ) ) )[0] ) )[0];
    $host = '' if !defined $host;

    return if grep { $_ eq $host } ( 'localhost', '127.0.0.1', '::1', '[::1]' );

    fail( 'sekreto: refusing to send a token in plaintext to ' . $addr . ' (use https)' );
}

# HashiCorp Vault, KV v2.
#
# `api.token` reads `{addr}/v1/{mount}/data/api` and takes the `token` field
# of `data.data`. A 404 means "not here", which is a miss rather than an
# error, so a vault can sit in a chain with fallbacks.
{

    package Voxgig::Sekreto::Providers::Hashicorp;

    sub new {
        my ( $class, $addr, $token, $mount ) = @_;
        return bless {
            addr  => defined $addr  ? $addr  : '',
            token => defined $token ? $token : '',
            mount => $mount || 'secret',
        }, $class;
    }

    sub lookup {
        my ( $self, $name ) = @_;

        Voxgig::Sekreto::Providers::checkaddr( $self->{addr} );

        my $ref  = Voxgig::Sekreto::Providers::vaultref($name);
        my $addr = $self->{addr};
        $addr =~ s{/$}{};

        my $url = $addr . '/v1/' . $self->{mount} . '/data/' . $ref->{path};

        my ( $status, $body ) =
          Voxgig::Sekreto::Providers::httpget( $url, { 'X-Vault-Token' => $self->{token} } );

        return undef if 404 == $status;

        Voxgig::Sekreto::Providers::fail(
            'sekreto: hashicorp error: ' . $status . ': ' . $url )
          if 200 != $status;

        my $data =
          ( 'HASH' eq ref( $body || '' ) && 'HASH' eq ref( $body->{data} || '' ) )
          ? $body->{data}{data}
          : undef;

        return 'HASH' eq ref( $data || '' ) ? $data->{ $ref->{field} } : undef;
    }

    sub describe {
        my ($self) = @_;
        return 'hashicorp:' . $self->{addr} . '/' . $self->{mount};
    }
}

# A boru vault (https://github.com/boru-lang/boru).
#
# boru keeps secrets in a local encrypted keyring and hands a value out
# through its own CLI: `boru vault get --reveal <alias>` prints the secret on
# stdout, and nothing else.
#
# There is deliberately no HTTP read here. boru's `vault proxy` and
# `vault mcp` are a *credential broker*: they inject the real secret into an
# outbound request and forward it, so an agent can call an API without ever
# holding the credential. Handing a value back is the one thing that broker
# is built not to do, so sekreto reads the vault the way boru itself does -
# through the CLI.
#
# A sekreto name is already a valid boru alias, so `api.token` crosses over
# unchanged. A `namespace` qualifies it the way boru writes it,
# `<namespace>:<name>`.
#
# The passphrase is read by boru itself from `BORU_VAULT_PASSPHRASE`. sekreto
# never accepts it as config and never puts it on a command line, where it
# would show up in the process table.
{

    package Voxgig::Sekreto::Providers::Boru;

    sub new {
        my ( $class, $command, $namespace, $home ) = @_;
        return bless {
            command   => $command || 'boru',
            namespace => $namespace,
            home      => $home,
        }, $class;
    }

    sub lookup {
        my ( $self, $name ) = @_;

        Voxgig::Sekreto::checkname($name);

        my $alias = $self->{namespace} ? $self->{namespace} . ':' . $name : $name;

        # BORU_HOME is set for the child only, then restored.
        local $ENV{BORU_HOME} = $self->{home} if $self->{home};

        my ( $out, $err, $status ) = Voxgig::Sekreto::Providers::runcmd(
            $self->{command}, 'vault', 'get', '--reveal', $alias );

        if ( 0 == $status ) {
            # boru prints the value and one newline, and nothing else.
            $out =~ s/\n\z//;
            return $out;
        }

        $err =~ s/^\s+|\s+$//g;

        # "no alias named" is boru saying it does not hold this secret, which
        # is a miss: the chain carries on to the next provider. A locked vault
        # or a wrong passphrase is not a miss - treating it as one would fall
        # through to a weaker store without saying so.
        return undef if Voxgig::Sekreto::Providers::borumiss($err);

        Voxgig::Sekreto::Providers::fail(
            'sekreto: boru vault error: ' . ( '' eq $err ? 'exit ' . $status : $err ) );
    }

    sub describe {
        my ($self) = @_;
        return 'boru' . ( $self->{namespace} ? ':' . $self->{namespace} : '' );
    }
}

# Run a command, returning (stdout, stderr, exit status).
#
# open3 rather than backticks: the argument list is passed through without a
# shell, so an alias never gets word-split or interpreted, and stderr is
# captured separately from the secret on stdout.
sub runcmd {
    my (@argv) = @_;

    my ( $in, $out );
    my $err = Symbol::gensym();

    my $pid = eval { IPC::Open3::open3( $in, $out, $err, @argv ) };

    fail( 'sekreto: cannot run ' . $argv[0] . ': ' . $@ ) if !$pid;

    close($in);

    local $/ = undef;
    my $outtext = <$out>;
    my $errtext = <$err>;

    close($out);
    close($err);

    waitpid( $pid, 0 );

    return (
        defined $outtext ? $outtext : '',
        defined $errtext ? $errtext : '',
        $? >> 8,
    );
}

# Does this boru failure mean "no such secret" rather than "I could not
# answer"? Matched on boru's own wording for a missing alias.
sub borumiss {
    my ($why) = @_;
    return index( $why, 'no alias named' ) >= 0 ? 1 : 0;
}

# Build a provider from its declarative form.
sub makeprovider {
    my ($spec) = @_;

    my $kind = $spec->{kind};

    return Voxgig::Sekreto::Providers::Env->new( $spec->{prefix} ) if 'env' eq ( $kind || '' );

    return Voxgig::Sekreto::Providers::Dotenv->new( $spec->{file} || '.env', $spec->{prefix} )
      if 'dotenv' eq ( $kind || '' );

    return Voxgig::Sekreto::Providers::Memory->new( $spec->{values} || {}, $spec->{prefix} )
      if 'memory' eq ( $kind || '' );

    return Voxgig::Sekreto::Providers::Hashicorp->new(
        $spec->{addr} || '',
        $spec->{token} || '',
        $spec->{mount}
    ) if 'hashicorp' eq ( $kind || '' );

    return Voxgig::Sekreto::Providers::Boru->new(
        $spec->{command}, $spec->{namespace}, $spec->{home} )
      if 'boru' eq ( $kind || '' );

    fail( 'sekreto: unknown provider kind: ' . ( defined $kind ? $kind : '' ) );
}

# Build a whole provider chain from its declarative form.
sub makechain {
    my ($specs) = @_;
    return [ map { makeprovider($_) } @{ $specs || [] } ];
}

1;
