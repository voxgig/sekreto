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
use JSON::PP   ();

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

# HashiCorp Vault, KV v2.
#
# `api.token` reads `{addr}/v1/{mount}/data/api` and takes the `token` field
# of `data.data`. A 404 means "not here", which is a miss rather than an
# error, so a vault can sit in a chain with fallbacks.
{

    package Voxgig::Sekreto::Providers::Vault;

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

        my $ref  = Voxgig::Sekreto::Providers::vaultref($name);
        my $addr = $self->{addr};
        $addr =~ s{/$}{};

        my $url = $addr . '/v1/' . $self->{mount} . '/data/' . $ref->{path};

        my ( $status, $body ) =
          Voxgig::Sekreto::Providers::httpget( $url, { 'X-Vault-Token' => $self->{token} } );

        return undef if 404 == $status;

        Voxgig::Sekreto::Providers::fail(
            'sekreto: vault error: ' . $status . ': ' . $url )
          if 200 != $status;

        my $data =
          ( 'HASH' eq ref( $body || '' ) && 'HASH' eq ref( $body->{data} || '' ) )
          ? $body->{data}{data}
          : undef;

        return 'HASH' eq ref( $data || '' ) ? $data->{ $ref->{field} } : undef;
    }

    sub describe {
        my ($self) = @_;
        return 'vault:' . $self->{addr} . '/' . $self->{mount};
    }
}

# A boru vault.
#
# The boru vault protocol as sekreto uses it: a GET of
# `{addr}/vault/{path}?field={field}` with an `X-Boru-Token` header,
# answering `{"ok":true,"value":"..."}` when the secret exists and
# `{"ok":false}` (or 404) when it does not.
{

    package Voxgig::Sekreto::Providers::Boru;

    sub new {
        my ( $class, $addr, $token ) = @_;
        return bless {
            addr  => defined $addr  ? $addr  : '',
            token => defined $token ? $token : '',
        }, $class;
    }

    sub lookup {
        my ( $self, $name ) = @_;

        my $ref  = Voxgig::Sekreto::Providers::vaultref($name);
        my $addr = $self->{addr};
        $addr =~ s{/$}{};

        my $field = $ref->{field};
        $field =~ s/([^A-Za-z0-9_.~-])/sprintf('%%%02X', ord($1))/ge;

        my $url = $addr . '/vault/' . $ref->{path} . '?field=' . $field;

        my ( $status, $body ) =
          Voxgig::Sekreto::Providers::httpget( $url, { 'X-Boru-Token' => $self->{token} } );

        return undef if 404 == $status;

        Voxgig::Sekreto::Providers::fail(
            'sekreto: boru vault error: ' . $status . ': ' . $url )
          if 200 != $status;

        return undef if 'HASH' ne ref( $body || '' );
        return undef if !$body->{ok};

        return $body->{value};
    }

    sub describe {
        my ($self) = @_;
        return 'boru:' . $self->{addr};
    }
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

    return Voxgig::Sekreto::Providers::Vault->new(
        $spec->{addr} || '',
        $spec->{token} || '',
        $spec->{mount}
    ) if 'vault' eq ( $kind || '' );

    return Voxgig::Sekreto::Providers::Boru->new( $spec->{addr} || '', $spec->{token} || '' )
      if 'boru' eq ( $kind || '' );

    fail( 'sekreto: unknown provider kind: ' . ( defined $kind ? $kind : '' ) );
}

# Build a whole provider chain from its declarative form.
sub makechain {
    my ($specs) = @_;
    return [ map { makeprovider($_) } @{ $specs || [] } ];
}

1;
