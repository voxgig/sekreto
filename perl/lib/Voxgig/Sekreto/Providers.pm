package Voxgig::Sekreto::Providers;

# The providers a Sekreto chains together.
#
# A provider answers one question: "do you have this secret?" It returns the
# value, or undef to mean "ask the next one". Nothing else about a provider
# is visible to the caller - which is the point: an app reads `api.token`
# and never learns whether it came from the environment, a .env file,
# HashiCorp Vault, AWS, GCP, Azure or a boru vault.
#
# Two failure shapes, and they are never interchangeable. A store that does
# not hold the secret is a MISS (undef) - the chain carries on. A store that
# could not answer - bad credentials, unreachable host, missing
# configuration - is an ERROR: falling through there would quietly reach
# for a weaker store.
#
# A port of typescript/src/Providers.ts, which is canonical.
#
# HTTP::Tiny, JSON::PP, Digest::SHA and MIME::Base64 are all core Perl, so
# this port stays free of third-party dependencies.

use strict;
use warnings;

use Exporter 'import';

use Errno        ();
use File::Spec   ();
use HTTP::Tiny   ();
use IPC::Open3   ();
use JSON::PP     ();
use MIME::Base64 ();
use Symbol       ();

use Voxgig::Sekreto::Sigv4 ();

our @EXPORT_OK = qw(makechain makeprovider);

# Loaded lazily inside the subs below: Voxgig::Sekreto uses this module, so
# a `use` here would be a cycle.
sub envkey    { return Voxgig::Sekreto::envkey(@_) }
sub vaultref  { return Voxgig::Sekreto::vaultref(@_) }
sub flatname  { return Voxgig::Sekreto::flatname(@_) }
sub awsparam  { return Voxgig::Sekreto::awsparam(@_) }
sub checkname { return Voxgig::Sekreto::checkname(@_) }
sub fail      { return Voxgig::Sekreto::fail(@_) }

# The string a JSON value reads as, the way the canonical port's String()
# spells it: booleans as words, numbers as themselves, undef stays undef.
sub stringof {
    my ($value) = @_;
    return undef if !defined $value;
    return ( $value ? 'true' : 'false' ) if JSON::PP::is_bool($value);
    return "$value";
}

# RFC 3986 escaping for URL parts, shared with the SigV4 canonical form.
sub urlenc { return Voxgig::Sekreto::Sigv4::uriescape(@_) }

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

# A directory of one-secret-per-file entries, keyed like the environment:
# `api.token` reads `<dir>/API_TOKEN`.
#
# This is the shape of a mounted Kubernetes Secret, a Docker or Swarm
# secret, and a systemd credentials directory, so those all work with no
# further configuration. One trailing newline is stripped - tools that
# write these files disagree about it, and a newline is never part of a
# secret on purpose.
{

    package Voxgig::Sekreto::Providers::File;

    sub new {
        my ( $class, $dir, $prefix ) = @_;
        return bless { dir => $dir, prefix => $prefix }, $class;
    }

    sub lookup {
        my ( $self, $name ) = @_;

        my $file = File::Spec->catfile( $self->{dir},
            Voxgig::Sekreto::Providers::envkey( $name, $self->{prefix} ) );

        my $handle;
        if ( !open( $handle, '<', $file ) ) {

            # An absent file - or an absent directory - means "no secrets
            # here", exactly like a missing .env. Anything else (permission
            # denied, an unreadable mount) is a store that could not answer.
            return undef if $!{ENOENT} || $!{ENOTDIR};

            Voxgig::Sekreto::Providers::fail(
                'sekreto: file provider cannot read ' . $file . ': ' . $! );
        }

        local $/ = undef;
        my $text = <$handle>;
        close($handle);

        $text = '' if !defined $text;
        $text =~ s/\r?\n\z//;

        return $text;
    }

    sub describe {
        my ($self) = @_;
        return 'file:' . $self->{dir};
    }
}

# One JSON round-trip, returning (status, decoded-json-or-undef). A 404 is
# a normal answer here, not a failure: it means the store has no such
# secret. Network failure is always an error - an unreachable store is a
# store that could not answer.
sub fetchjson {
    my ( $method, $url, $headers, $body ) = @_;

    my $options = { headers => $headers || {} };
    $options->{content} = $body if defined $body;

    my $response = HTTP::Tiny->new( timeout => 10 )->request( $method, $url, $options );

    # HTTP::Tiny reports transport failures as a synthetic 599.
    if ( 599 == $response->{status} ) {
        ( my $plain = $url ) =~ s/\?.*//s;
        fail( 'sekreto: cannot reach ' . $plain . ': ' . ( $response->{content} || '' ) );
    }

    my $parsed = eval { JSON::PP->new->decode( $response->{content} ) };

    return ( $response->{status}, $parsed );
}

# Refuse to send a secret-bearing credential in the clear.
#
# A vault API is HTTPS in any real deployment; plaintext is a dev-mode
# convenience. Sending a token over http to anything but the local machine
# puts both the token and the secret it fetches on the wire for anyone on
# the path, so sekreto will not do it. Loopback stays allowed: that is
# `vault server -dev`, `boru vault serve`, and this repo's own test
# harness.
sub checkaddr {
    my ($addr) = @_;

    return if 0 == index( $addr, 'https://' );

    fail( 'sekreto: not an http(s) address: ' . $addr ) if 0 != index( $addr, 'http://' );

    my $host = ( split( /:/, ( split( m{/}, substr( $addr, 7 ) ) )[0] ) )[0];
    $host = '' if !defined $host;

    return if grep { $_ eq $host } ( 'localhost', '127.0.0.1', '::1', '[::1]' );

    fail( 'sekreto: refusing to send a token in plaintext to ' . $addr . ' (use https)' );
}

# HashiCorp Vault.
#
# KV v2 (the default): `api.token` reads `{addr}/v1/{mount}/data/api` and
# takes the `token` field of `data.data`. KV v1 (`kv: 1`) reads
# `{addr}/v1/{mount}/api` and takes the field of `data`. A 404 means "not
# here" - a miss - so a vault can sit in a chain with fallbacks.
#
# A Vault Enterprise namespace rides the X-Vault-Namespace header, on
# logins as well as reads.
#
# Instead of being handed a token, the provider can log in: Kubernetes
# auth (the pod's service-account JWT, from its conventional path) or
# AppRole. A failed login is an error, never a miss - it means this store
# could not answer at all.
{

    package Voxgig::Sekreto::Providers::Hashicorp;

    sub new {
        my ( $class, $addr, $token, $options ) = @_;

        my $opts = $options || {};
        my $usetoken = defined $token ? $token : '';

        return bless {
            addr           => defined $addr ? $addr : '',
            mount          => $opts->{mount} || 'secret',
            kv             => $opts->{kv} || 2,
            vaultnamespace => $opts->{vaultnamespace},
            auth           => $opts->{auth},

            # The working token, resolved once and reused. A configured
            # token wins; otherwise the first lookup logs in.
            livetoken => '' eq $usetoken ? undef : $usetoken,
        }, $class;
    }

    sub baseheaders {
        my ($self) = @_;
        my %headers;
        $headers{'X-Vault-Namespace'} = $self->{vaultnamespace} if $self->{vaultnamespace};
        return \%headers;
    }

    sub login {
        my ($self) = @_;

        my $auth = $self->{auth};
        Voxgig::Sekreto::Providers::fail('sekreto: hashicorp: no token and no auth method')
          if !$auth;

        my $method = defined $auth->{method} ? $auth->{method} : '';
        my $mount = $auth->{mount} || $method;

        ( my $addr = $self->{addr} ) =~ s{/$}{};
        my $url = $addr . '/v1/auth/' . $mount . '/login';

        my $body;
        if ( 'kubernetes' eq $method ) {
            my $jwt = $auth->{jwt};
            if ( !defined $jwt ) {
                my $file = $auth->{jwtfile}
                  || '/var/run/secrets/kubernetes.io/serviceaccount/token';
                my $handle;
                Voxgig::Sekreto::Providers::fail(
                    'sekreto: hashicorp: cannot read jwt file ' . $file )
                  if !open( $handle, '<', $file );
                local $/ = undef;
                $jwt = <$handle>;
                close($handle);
                $jwt = '' if !defined $jwt;
                $jwt =~ s/^\s+|\s+$//g;
            }
            $body = { role => ( defined $auth->{role} ? $auth->{role} : '' ), jwt => $jwt };
        }
        elsif ( 'approle' eq $method ) {
            $body = {
                role_id   => defined $auth->{roleid}   ? $auth->{roleid}   : '',
                secret_id => defined $auth->{secretid} ? $auth->{secretid} : '',
            };
        }
        else {
            Voxgig::Sekreto::Providers::fail(
                'sekreto: hashicorp: unknown auth method: ' . $method );
        }

        my ( $status, $resbody ) = Voxgig::Sekreto::Providers::fetchjson(
            'POST', $url,
            $self->baseheaders(),
            JSON::PP->new->canonical(1)->encode($body)
        );

        my $got =
          ( 'HASH' eq ref( $resbody || '' ) && 'HASH' eq ref( $resbody->{auth} || '' ) )
          ? $resbody->{auth}{client_token}
          : undef;

        Voxgig::Sekreto::Providers::fail(
            'sekreto: hashicorp login failed: ' . $status . ': ' . $url )
          if 200 != $status || !$got;

        return Voxgig::Sekreto::Providers::stringof($got);
    }

    sub lookup {
        my ( $self, $name ) = @_;

        Voxgig::Sekreto::Providers::checkaddr( $self->{addr} );

        $self->{livetoken} = $self->login() if !defined $self->{livetoken};

        my $ref = Voxgig::Sekreto::Providers::vaultref($name);

        ( my $addr = $self->{addr} ) =~ s{/$}{};
        my $base = $addr . '/v1/' . $self->{mount};
        my $url =
          1 == $self->{kv} ? $base . '/' . $ref->{path} : $base . '/data/' . $ref->{path};

        my $headers = $self->baseheaders();
        $headers->{'X-Vault-Token'} = $self->{livetoken};

        my ( $status, $body ) = Voxgig::Sekreto::Providers::fetchjson( 'GET', $url, $headers );

        return undef if 404 == $status;

        Voxgig::Sekreto::Providers::fail(
            'sekreto: hashicorp error: ' . $status . ': ' . $url )
          if 200 != $status;

        my $data;
        if ( 1 == $self->{kv} ) {
            $data = 'HASH' eq ref( $body || '' ) ? $body->{data} : undef;
        }
        else {
            $data =
              ( 'HASH' eq ref( $body || '' ) && 'HASH' eq ref( $body->{data} || '' ) )
              ? $body->{data}{data}
              : undef;
        }

        my $value = 'HASH' eq ref( $data || '' ) ? $data->{ $ref->{field} } : undef;
        return Voxgig::Sekreto::Providers::stringof($value);
    }

    sub describe {
        my ($self) = @_;
        return 'hashicorp:' . $self->{addr} . '/' . $self->{mount};
    }
}

# A boru vault (https://github.com/boru-lang/boru), read through the boru
# CLI: `boru vault get --reveal <alias>` prints the secret on stdout, and
# nothing else.
#
# A sekreto name is already a valid boru alias, so `api.token` crosses over
# unchanged. A `namespace` qualifies it the way boru writes it,
# `<namespace>:<name>`.
#
# The passphrase is read by boru itself from `BORU_VAULT_PASSPHRASE`. sekreto
# never accepts it as config and never puts it on a command line, where it
# would show up in the process table.
#
# boru's `vault proxy` and `vault mcp` remain out of bounds: they are a
# credential *broker*, built precisely so the caller never receives the
# credential. The wire route in is `vault serve` - the provider below.
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

# The same boru vault over its wire protocol: `boru vault serve` publishes
# a read-only, HashiCorp-shaped provision API (boru's
# design/VAULT-WIRE-PROTOCOL.0.md), authenticated by a capability token
# from `boru vault grant`.
#
# A sekreto name is already a valid boru alias, and boru aliases keep
# their dots, so `api.token` is the single path segment `api.token` - not
# the `api`/`token` split a HashiCorp KV gets. The value is the `value`
# field. A 404 is a miss; anything else the server refuses (a revoked
# capability, a sealed vault) is an error.
{

    package Voxgig::Sekreto::Providers::BoruWire;

    sub new {
        my ( $class, $addr, $token, $namespace, $mount ) = @_;

        ( my $useaddr = defined $addr ? $addr : '' ) =~ s{/$}{};

        return bless {
            addr      => $useaddr,
            token     => defined $token ? $token : '',
            namespace => $namespace,
            mount     => $mount || 'secret',
        }, $class;
    }

    sub lookup {
        my ( $self, $name ) = @_;

        Voxgig::Sekreto::checkname($name);
        Voxgig::Sekreto::Providers::checkaddr( $self->{addr} );

        my $alias = $self->{namespace} ? $self->{namespace} . '/' . $name : $name;
        my $url   = $self->{addr} . '/v1/' . $self->{mount} . '/data/' . $alias;

        my ( $status, $body ) = Voxgig::Sekreto::Providers::fetchjson( 'GET', $url,
            { 'X-Vault-Token' => $self->{token} } );

        return undef if 404 == $status;

        Voxgig::Sekreto::Providers::fail(
            'sekreto: boru serve error: ' . $status . ': ' . $url )
          if 200 != $status;

        my $data =
          ( 'HASH' eq ref( $body || '' ) && 'HASH' eq ref( $body->{data} || '' ) )
          ? $body->{data}{data}
          : undef;

        my $value = 'HASH' eq ref( $data || '' ) ? $data->{value} : undef;
        return Voxgig::Sekreto::Providers::stringof($value);
    }

    sub describe {
        my ($self) = @_;
        return 'boru:' . $self->{addr};
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

# The `YYYYMMDDTHHMMSSZ` timestamp SigV4 wants, for now.
sub awsnow {
    my @t = gmtime();
    return sprintf( '%04d%02d%02dT%02d%02d%02dZ',
        $t[5] + 1900, $t[4] + 1, $t[3], $t[2], $t[1], $t[0] );
}

# Region and credentials, from config first and the standard AWS_*
# environment variables second - those are AWS's own convention, and a pod
# or CI job that has them set should just work. Missing either is an
# error: an AWS store with no credentials could not answer.
sub awsauth {
    my ($opts) = @_;

    my $region  = $opts->{region} || $ENV{AWS_REGION} || $ENV{AWS_DEFAULT_REGION} || '';
    my $keyid   = $opts->{keyid} || $ENV{AWS_ACCESS_KEY_ID} || '';
    my $secret  = $opts->{secret} || $ENV{AWS_SECRET_ACCESS_KEY} || '';
    my $session = $opts->{session} || $ENV{AWS_SESSION_TOKEN} || undef;

    fail('sekreto: aws: no region (set region or AWS_REGION)') if '' eq $region;

    fail(   'sekreto: aws: no credentials'
          . ' (set keyid/secret or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY)' )
      if '' eq $keyid || '' eq $secret;

    return { region => $region, keyid => $keyid, secret => $secret, session => $session };
}

# One signed call to an AWS JSON-1.1 API.
sub awscall {
    my ( $opts, $service, $target, $payload ) = @_;

    my $auth = awsauth($opts);
    my $addr = $opts->{addr} || 'https://' . $service . '.' . $auth->{region} . '.amazonaws.com';
    checkaddr($addr);

    ( my $base = $addr ) =~ s{/$}{};
    my $url  = $base . '/';
    my $body = JSON::PP->new->canonical(1)->encode($payload);

    my %headers = (
        'content-type' => 'application/x-amz-json-1.1',
        'x-amz-target' => $target,
    );

    my $signed = Voxgig::Sekreto::Sigv4::sigv4(
        {
            method   => 'POST',
            url      => $url,
            headers  => {%headers},
            body     => $body,
            service  => $service,
            region   => $auth->{region},
            keyid    => $auth->{keyid},
            secret   => $auth->{secret},
            session  => $auth->{session},
            datetime => awsnow(),
        }
    );

    return fetchjson( 'POST', $url, { %headers, %$signed }, $body );
}

# Does this AWS error body name one of the not-found types? Those are a
# miss; every other failure is a store that could not answer.
sub awsmiss {
    my ( $body, $types ) = @_;

    my $errtype =
      ( 'HASH' eq ref( $body || '' ) && defined $body->{__type} && !ref( $body->{__type} ) )
      ? $body->{__type}
      : '';

    for my $name (@$types) {
        return 1 if index( $errtype, $name ) >= 0;
    }

    return 0;
}

# AWS Secrets Manager.
#
# `api.token` reads the secret named `api` (the vaultref path, so
# `db.pass.main` reads `db/pass`) and takes the `token` field of its JSON
# SecretString - the AWS idiom of one JSON map per secret. A SecretString
# that is not JSON is the value itself, under the conventional field
# `value`. Requests are SigV4-signed in-tree; see Sigv4.pm.
{

    package Voxgig::Sekreto::Providers::Awssecrets;

    sub new {
        my ( $class, $opts ) = @_;
        return bless { opts => $opts || {} }, $class;
    }

    sub lookup {
        my ( $self, $name ) = @_;

        my $ref = Voxgig::Sekreto::Providers::vaultref($name);

        my ( $status, $body ) =
          Voxgig::Sekreto::Providers::awscall( $self->{opts}, 'secretsmanager',
            'secretsmanager.GetSecretValue', { SecretId => $ref->{path} } );

        return undef
          if 400 == $status
          && Voxgig::Sekreto::Providers::awsmiss( $body, ['ResourceNotFoundException'] );

        Voxgig::Sekreto::Providers::fail( 'sekreto: aws secretsmanager error: ' . $status )
          if 200 != $status;

        my $text = 'HASH' eq ref( $body || '' ) ? $body->{SecretString} : undef;

        if ( !defined $text || ref($text) ) {

            # A binary secret has no fields to address; only the conventional
            # `value` field can mean "the bytes themselves".
            my $bin = 'HASH' eq ref( $body || '' ) ? $body->{SecretBinary} : undef;
            return MIME::Base64::decode_base64($bin)
              if defined $bin && !ref($bin) && 'value' eq $ref->{field};
            return undef;
        }

        my $parsed = eval { JSON::PP->new->decode($text) };

        if ( 'HASH' eq ref( $parsed || '' ) ) {
            my $value = $parsed->{ $ref->{field} };
            return Voxgig::Sekreto::Providers::stringof($value);
        }

        # A plain-string secret is the whole value; it has no named fields.
        return 'value' eq $ref->{field} ? $text : undef;
    }

    sub describe {
        my ($self) = @_;

        # Config only, never the environment: describe() feeds the spec's
        # sources group, which must answer the same everywhere.
        return 'awssecrets:' . ( $self->{opts}{region} || '' );
    }
}

# AWS SSM Parameter Store.
#
# `db.pass.main` reads the parameter `/db/pass/main` (under an optional
# prefix path), decrypted. Parameter Store carries flat strings, so there
# is no field indirection.
{

    package Voxgig::Sekreto::Providers::Awsparams;

    sub new {
        my ( $class, $opts ) = @_;
        return bless { opts => $opts || {} }, $class;
    }

    sub lookup {
        my ( $self, $name ) = @_;

        my ( $status, $body ) = Voxgig::Sekreto::Providers::awscall(
            $self->{opts}, 'ssm',
            'AmazonSSM.GetParameter',
            {
                Name => Voxgig::Sekreto::Providers::awsparam( $name, $self->{opts}{prefix} ),
                WithDecryption => JSON::PP::true,
            }
        );

        return undef
          if 400 == $status
          && Voxgig::Sekreto::Providers::awsmiss( $body, ['ParameterNotFound'] );

        Voxgig::Sekreto::Providers::fail( 'sekreto: aws ssm error: ' . $status )
          if 200 != $status;

        my $value =
          ( 'HASH' eq ref( $body || '' ) && 'HASH' eq ref( $body->{Parameter} || '' ) )
          ? $body->{Parameter}{Value}
          : undef;

        return Voxgig::Sekreto::Providers::stringof($value);
    }

    sub describe {
        my ($self) = @_;
        return 'awsparams:' . ( $self->{opts}{region} || '' ) . ( $self->{opts}{prefix} || '' );
    }
}

# GCP Secret Manager.
#
# `api.token` reads secret `api_token` (dots flattened to `_`; Secret
# Manager ids have no hierarchy and reject dots), latest version. The
# token comes from config, then `GOOGLE_OAUTH_ACCESS_TOKEN`, then the
# GCE/GKE metadata server - so on Google's own platform no credential
# configuration is needed at all.
#
# The metadata call itself is plain http to a link-local host by platform
# design; no credential rides on it, so `checkaddr` guards the Secret
# Manager address instead.
{

    package Voxgig::Sekreto::Providers::Gcpsecrets;

    sub new {
        my ( $class, $opts ) = @_;
        return bless { opts => $opts || {}, livetoken => undef }, $class;
    }

    sub metadataaddr {
        my ($self) = @_;
        return $self->{opts}{metadataaddr} if $self->{opts}{metadataaddr};
        my $host = $ENV{GCE_METADATA_HOST};
        return $host ? 'http://' . $host : 'http://metadata.google.internal';
    }

    sub login {
        my ($self) = @_;

        my $configured = $self->{opts}{token} || $ENV{GOOGLE_OAUTH_ACCESS_TOKEN};
        return $configured if $configured;

        ( my $base = $self->metadataaddr() ) =~ s{/$}{};
        my $url = $base . '/computeMetadata/v1/instance/service-accounts/default/token';

        my ( $status, $body ) = Voxgig::Sekreto::Providers::fetchjson( 'GET', $url,
            { 'Metadata-Flavor' => 'Google' } );

        my $got = 'HASH' eq ref( $body || '' ) ? $body->{access_token} : undef;

        Voxgig::Sekreto::Providers::fail(
            'sekreto: gcp: no token and metadata server did not answer')
          if 200 != $status || !$got;

        return Voxgig::Sekreto::Providers::stringof($got);
    }

    sub lookup {
        my ( $self, $name ) = @_;

        my $project = $self->{opts}{project} || '';
        Voxgig::Sekreto::Providers::fail('sekreto: gcp: no project') if '' eq $project;

        my $addr = $self->{opts}{addr} || 'https://secretmanager.googleapis.com';
        Voxgig::Sekreto::Providers::checkaddr($addr);

        $self->{livetoken} = $self->login() if !defined $self->{livetoken};

        ( my $base = $addr ) =~ s{/$}{};
        my $url =
            $base
          . '/v1/projects/'
          . $project
          . '/secrets/'
          . Voxgig::Sekreto::Providers::flatname( $name, '_' )
          . '/versions/latest:access';

        my ( $status, $body ) = Voxgig::Sekreto::Providers::fetchjson( 'GET', $url,
            { 'authorization' => 'Bearer ' . $self->{livetoken} } );

        return undef if 404 == $status;

        Voxgig::Sekreto::Providers::fail( 'sekreto: gcp error: ' . $status . ': ' . $url )
          if 200 != $status;

        my $data =
          ( 'HASH' eq ref( $body || '' ) && 'HASH' eq ref( $body->{payload} || '' ) )
          ? $body->{payload}{data}
          : undef;

        return undef if !defined $data || ref($data);

        return MIME::Base64::decode_base64($data);
    }

    sub describe {
        my ($self) = @_;
        return 'gcpsecrets:' . ( $self->{opts}{project} || '' );
    }
}

# Azure Key Vault.
#
# `api.token` reads secret `api-token` (dots flattened to `-`; Key Vault
# names allow nothing else), current version. The token comes from config,
# then a client-credentials login when tenant/clientid/clientsecret are
# given, then the IMDS managed-identity endpoint - so on Azure's own
# platform no credential configuration is needed.
#
# As with GCP, the IMDS call is plain http to a link-local host by
# platform design and carries no credential; the login and vault addresses
# are `checkaddr`-guarded.
{

    package Voxgig::Sekreto::Providers::Azuresecrets;

    my $RESOURCE = 'https://vault.azure.net';

    sub new {
        my ( $class, $opts ) = @_;
        return bless { opts => $opts || {}, livetoken => undef }, $class;
    }

    sub login {
        my ($self) = @_;
        my $opts = $self->{opts};

        return $opts->{token} if $opts->{token};

        if ( $opts->{tenant} && $opts->{clientid} && $opts->{clientsecret} ) {
            my $loginaddr = $opts->{loginaddr} || 'https://login.microsoftonline.com';
            Voxgig::Sekreto::Providers::checkaddr($loginaddr);

            ( my $base = $loginaddr ) =~ s{/$}{};
            my $url = $base . '/' . $opts->{tenant} . '/oauth2/v2.0/token';
            my $form =
                'grant_type=client_credentials&client_id='
              . Voxgig::Sekreto::Providers::urlenc( $opts->{clientid} )
              . '&client_secret='
              . Voxgig::Sekreto::Providers::urlenc( $opts->{clientsecret} )
              . '&scope='
              . Voxgig::Sekreto::Providers::urlenc( $RESOURCE . '/.default' );

            my ( $status, $body ) = Voxgig::Sekreto::Providers::fetchjson( 'POST', $url,
                { 'content-type' => 'application/x-www-form-urlencoded' }, $form );

            my $got = 'HASH' eq ref( $body || '' ) ? $body->{access_token} : undef;

            Voxgig::Sekreto::Providers::fail( 'sekreto: azure login failed: ' . $status )
              if 200 != $status || !$got;

            return Voxgig::Sekreto::Providers::stringof($got);
        }

        ( my $imdsbase = $opts->{imdsaddr} || 'http://169.254.169.254' ) =~ s{/$}{};
        my $imds =
            $imdsbase
          . '/metadata/identity/oauth2/token?api-version=2018-02-01&resource='
          . Voxgig::Sekreto::Providers::urlenc($RESOURCE);

        my ( $status, $body ) =
          Voxgig::Sekreto::Providers::fetchjson( 'GET', $imds, { 'Metadata' => 'true' } );

        my $got = 'HASH' eq ref( $body || '' ) ? $body->{access_token} : undef;

        Voxgig::Sekreto::Providers::fail(
            'sekreto: azure: no token, no client credentials, and IMDS did not answer')
          if 200 != $status || !$got;

        return Voxgig::Sekreto::Providers::stringof($got);
    }

    sub lookup {
        my ( $self, $name ) = @_;
        my $opts = $self->{opts};

        my $vault = $opts->{vault} || '';
        Voxgig::Sekreto::Providers::fail('sekreto: azure: no vault') if '' eq $vault;

        my $vaulturl =
          0 == index( $vault, 'http' ) ? $vault : 'https://' . $vault . '.vault.azure.net';
        Voxgig::Sekreto::Providers::checkaddr($vaulturl);

        $self->{livetoken} = $self->login() if !defined $self->{livetoken};

        ( my $base = $vaulturl ) =~ s{/$}{};
        my $url =
            $base
          . '/secrets/'
          . Voxgig::Sekreto::Providers::flatname( $name, '-' )
          . '?api-version='
          . ( $opts->{apiversion} || '7.4' );

        my ( $status, $body ) = Voxgig::Sekreto::Providers::fetchjson( 'GET', $url,
            { 'authorization' => 'Bearer ' . $self->{livetoken} } );

        return undef if 404 == $status;

        if ( 200 != $status ) {
            ( my $plain = $url ) =~ s/\?.*//s;
            Voxgig::Sekreto::Providers::fail(
                'sekreto: azure error: ' . $status . ': ' . $plain );
        }

        my $value = 'HASH' eq ref( $body || '' ) ? $body->{value} : undef;
        return Voxgig::Sekreto::Providers::stringof($value);
    }

    sub describe {
        my ($self) = @_;
        return 'azuresecrets:' . ( $self->{opts}{vault} || '' );
    }
}

# 1Password, through a Connect server.
#
# The item titled `api.token` (titles keep their dots), in the named
# vault. The value is the field with purpose PASSWORD, or the field
# labelled `value`. A vault that cannot be found is an error - config
# names it, so its absence is a broken store, not a missing secret.
{

    package Voxgig::Sekreto::Providers::Onepassword;

    sub new {
        my ( $class, $opts ) = @_;
        return bless { opts => $opts || {}, vaultid => undef }, $class;
    }

    sub authheaders {
        my ($self) = @_;
        return { 'authorization' => 'Bearer ' . ( $self->{opts}{token} || '' ) };
    }

    sub resolvevault {
        my ( $self, $addr ) = @_;

        my $want = $self->{opts}{vault} || '';
        Voxgig::Sekreto::Providers::fail('sekreto: onepassword: no vault') if '' eq $want;

        my ( $status, $body ) = Voxgig::Sekreto::Providers::fetchjson( 'GET',
            $addr . '/v1/vaults', $self->authheaders() );

        Voxgig::Sekreto::Providers::fail(
            'sekreto: onepassword error: ' . $status . ': listing vaults')
          if 200 != $status || 'ARRAY' ne ref( $body || '' );

        for my $entry (@$body) {
            next if 'HASH' ne ref( $entry || '' );
            return Voxgig::Sekreto::Providers::stringof( $entry->{id} )
              if ( defined $entry->{id} && !ref( $entry->{id} ) && $want eq $entry->{id} )
              || ( defined $entry->{name} && !ref( $entry->{name} ) && $want eq $entry->{name} );
        }

        Voxgig::Sekreto::Providers::fail( 'sekreto: onepassword: no vault named ' . $want );
    }

    sub lookup {
        my ( $self, $name ) = @_;

        Voxgig::Sekreto::checkname($name);

        ( my $addr = $self->{opts}{addr} || '' ) =~ s{/$}{};
        Voxgig::Sekreto::Providers::fail('sekreto: onepassword: no addr') if '' eq $addr;
        Voxgig::Sekreto::Providers::checkaddr($addr);

        $self->{vaultid} = $self->resolvevault($addr) if !defined $self->{vaultid};

        my $filter = Voxgig::Sekreto::Providers::urlenc( 'title eq "' . $name . '"' );
        my ( $status, $found ) = Voxgig::Sekreto::Providers::fetchjson( 'GET',
            $addr . '/v1/vaults/' . $self->{vaultid} . '/items?filter=' . $filter,
            $self->authheaders() );

        Voxgig::Sekreto::Providers::fail(
            'sekreto: onepassword error: ' . $status . ': finding ' . $name )
          if 200 != $status || 'ARRAY' ne ref( $found || '' );

        return undef if 0 == scalar(@$found);

        my ( $itemstatus, $item ) = Voxgig::Sekreto::Providers::fetchjson( 'GET',
            $addr . '/v1/vaults/' . $self->{vaultid} . '/items/' . $found->[0]{id},
            $self->authheaders() );

        Voxgig::Sekreto::Providers::fail(
            'sekreto: onepassword error: ' . $itemstatus . ': reading ' . $name )
          if 200 != $itemstatus;

        my $fields =
          ( 'HASH' eq ref( $item || '' ) && 'ARRAY' eq ref( $item->{fields} || '' ) )
          ? $item->{fields}
          : [];

        for my $field (@$fields) {
            next if 'HASH' ne ref( $field || '' );
            return Voxgig::Sekreto::Providers::stringof( $field->{value} )
              if defined $field->{purpose} && 'PASSWORD' eq $field->{purpose};
        }
        for my $field (@$fields) {
            next if 'HASH' ne ref( $field || '' );
            return Voxgig::Sekreto::Providers::stringof( $field->{value} )
              if defined $field->{label} && 'value' eq $field->{label};
        }

        return undef;
    }

    sub describe {
        my ($self) = @_;
        return 'onepassword:' . ( $self->{opts}{vault} || '' );
    }
}

# Doppler.
#
# The whole config is downloaded once - Doppler's own bulk endpoint - and
# answered from memory, like a remote .env: `api.token` is the `API_TOKEN`
# entry. A service token is config-scoped, so project and config are only
# needed with broader tokens.
{

    package Voxgig::Sekreto::Providers::Doppler;

    sub new {
        my ( $class, $opts ) = @_;
        return bless { opts => $opts || {}, values => undef }, $class;
    }

    sub load {
        my ($self) = @_;

        return $self->{values} if defined $self->{values};

        ( my $addr = $self->{opts}{addr} || 'https://api.doppler.com' ) =~ s{/$}{};
        Voxgig::Sekreto::Providers::checkaddr($addr);

        my $url = $addr . '/v3/configs/config/secrets/download?format=json';
        $url .= '&project=' . Voxgig::Sekreto::Providers::urlenc( $self->{opts}{project} )
          if $self->{opts}{project};
        $url .= '&config=' . Voxgig::Sekreto::Providers::urlenc( $self->{opts}{config} )
          if $self->{opts}{config};

        my ( $status, $body ) = Voxgig::Sekreto::Providers::fetchjson( 'GET', $url,
            { 'authorization' => 'Bearer ' . ( $self->{opts}{token} || '' ) } );

        Voxgig::Sekreto::Providers::fail( 'sekreto: doppler error: ' . $status )
          if 200 != $status || 'HASH' ne ref( $body || '' );

        my %values;
        for my $key ( keys %$body ) {
            $values{$key} = Voxgig::Sekreto::Providers::stringof( $body->{$key} )
              if defined $body->{$key};
        }
        $self->{values} = \%values;

        return $self->{values};
    }

    sub lookup {
        my ( $self, $name ) = @_;
        return $self->load()->{ Voxgig::Sekreto::Providers::envkey($name) };
    }

    sub describe {
        my ($self) = @_;
        my $opts = $self->{opts};
        return 'doppler'
          . ( $opts->{project} ? ':' . $opts->{project} . '/' . ( $opts->{config} || '' ) : '' );
    }
}

# Infisical.
#
# `api.token` reads the secret keyed `API_TOKEN` (Infisical's own
# convention is environment-style keys) at a secret path in one
# environment of a project. Auth is a token, or a universal-auth (machine
# identity) login with clientid/clientsecret.
{

    package Voxgig::Sekreto::Providers::Infisical;

    sub new {
        my ( $class, $opts ) = @_;
        return bless { opts => $opts || {}, livetoken => undef }, $class;
    }

    sub login {
        my ( $self, $addr ) = @_;
        my $opts = $self->{opts};

        return $opts->{token} if $opts->{token};

        Voxgig::Sekreto::Providers::fail(
            'sekreto: infisical: no token and no client credentials')
          if !$opts->{clientid} || !$opts->{clientsecret};

        my ( $status, $body ) = Voxgig::Sekreto::Providers::fetchjson(
            'POST',
            $addr . '/api/v1/auth/universal-auth/login',
            { 'content-type' => 'application/json' },
            JSON::PP->new->canonical(1)->encode(
                { clientId => $opts->{clientid}, clientSecret => $opts->{clientsecret} }
            )
        );

        my $got = 'HASH' eq ref( $body || '' ) ? $body->{accessToken} : undef;

        Voxgig::Sekreto::Providers::fail( 'sekreto: infisical login failed: ' . $status )
          if 200 != $status || !$got;

        return Voxgig::Sekreto::Providers::stringof($got);
    }

    sub lookup {
        my ( $self, $name ) = @_;
        my $opts = $self->{opts};

        ( my $addr = $opts->{addr} || 'https://app.infisical.com' ) =~ s{/$}{};
        Voxgig::Sekreto::Providers::checkaddr($addr);

        my $project     = $opts->{project}     || '';
        my $environment = $opts->{environment} || '';
        Voxgig::Sekreto::Providers::fail('sekreto: infisical: no project/environment')
          if '' eq $project || '' eq $environment;

        $self->{livetoken} = $self->login($addr) if !defined $self->{livetoken};

        my $url =
            $addr
          . '/api/v3/secrets/raw/'
          . Voxgig::Sekreto::Providers::envkey($name)
          . '?workspaceId='
          . Voxgig::Sekreto::Providers::urlenc($project)
          . '&environment='
          . Voxgig::Sekreto::Providers::urlenc($environment)
          . '&secretPath='
          . Voxgig::Sekreto::Providers::urlenc( $opts->{path} || '/' );

        my ( $status, $body ) = Voxgig::Sekreto::Providers::fetchjson( 'GET', $url,
            { 'authorization' => 'Bearer ' . $self->{livetoken} } );

        return undef if 404 == $status;

        Voxgig::Sekreto::Providers::fail( 'sekreto: infisical error: ' . $status )
          if 200 != $status;

        my $value =
          ( 'HASH' eq ref( $body || '' ) && 'HASH' eq ref( $body->{secret} || '' ) )
          ? $body->{secret}{secretValue}
          : undef;

        return Voxgig::Sekreto::Providers::stringof($value);
    }

    sub describe {
        my ($self) = @_;
        return 'infisical:'
          . ( $self->{opts}{project} || '' ) . '/'
          . ( $self->{opts}{environment} || '' );
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

    return Voxgig::Sekreto::Providers::File->new( $spec->{dir} || '', $spec->{prefix} )
      if 'file' eq ( $kind || '' );

    return Voxgig::Sekreto::Providers::Hashicorp->new(
        $spec->{addr}  || '',
        $spec->{token} || '',
        {
            mount          => $spec->{mount},
            kv             => $spec->{kv},
            vaultnamespace => $spec->{vaultnamespace},
            auth           => $spec->{auth},
        }
    ) if 'hashicorp' eq ( $kind || '' );

    if ( 'boru' eq ( $kind || '' ) ) {
        return Voxgig::Sekreto::Providers::BoruWire->new(
            $spec->{addr}, $spec->{token}, $spec->{namespace}, $spec->{mount} )
          if $spec->{addr};

        return Voxgig::Sekreto::Providers::Boru->new(
            $spec->{command}, $spec->{namespace}, $spec->{home} );
    }

    return Voxgig::Sekreto::Providers::Awssecrets->new($spec)
      if 'awssecrets' eq ( $kind || '' );

    return Voxgig::Sekreto::Providers::Awsparams->new($spec)
      if 'awsparams' eq ( $kind || '' );

    return Voxgig::Sekreto::Providers::Gcpsecrets->new($spec)
      if 'gcpsecrets' eq ( $kind || '' );

    return Voxgig::Sekreto::Providers::Azuresecrets->new($spec)
      if 'azuresecrets' eq ( $kind || '' );

    return Voxgig::Sekreto::Providers::Onepassword->new($spec)
      if 'onepassword' eq ( $kind || '' );

    return Voxgig::Sekreto::Providers::Doppler->new($spec)
      if 'doppler' eq ( $kind || '' );

    return Voxgig::Sekreto::Providers::Infisical->new($spec)
      if 'infisical' eq ( $kind || '' );

    fail( 'sekreto: unknown provider kind: ' . ( defined $kind ? $kind : '' ) );
}

# Build a whole provider chain from its declarative form.
sub makechain {
    my ($specs) = @_;
    return [ map { makeprovider($_) } @{ $specs || [] } ];
}

1;
