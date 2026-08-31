package Voxgig::Sekreto;

# sekreto: one interface for secrets, wherever they live.
#
# A Sekreto is an ordered chain of providers. `get` asks each in turn and
# returns the first hit, so an app can be configured from environment
# variables in development and a vault in production without changing a
# line of its own code.
#
# A port of typescript/src/Sekreto.ts, which is canonical.

use strict;
use warnings;

use Exporter 'import';

use Voxgig::Sekreto::Providers qw(makechain makeprovider);
use Voxgig::Sekreto::Sigv4 qw(sigv4);

our @EXPORT_OK = qw(
  awsparam envkey flatname parsedotenv redact sekreto sigv4 validname vaultref
);

our $VERSION = '0.1.0';

# Anything sekreto refuses to do: a bad name, a missing secret, a provider
# that could not be reached.
{

    package Voxgig::Sekreto::SekretoError;

    sub new {
        my ( $class, $message ) = @_;
        return bless { message => $message }, $class;
    }

    sub message { return $_[0]->{message} }

    use overload '""' => sub { $_[0]->{message} }, fallback => 1;
}

sub fail {
    my ($message) = @_;
    die Voxgig::Sekreto::SekretoError->new($message);
}

# Is this a well-formed secret name?
sub validname {
    my ($name) = @_;

    return 0 if !defined $name || ref($name);
    return 0 if '' eq $name;

    for my $part ( split( /\./, $name, -1 ) ) {
        # `\z`-style anchors, not `$`. In Python, PCRE, Perl and .NET `$` also
        # matches BEFORE a final newline, so `api.token\n` was accepted here while the
        # canonical port rejected it - and `envkey` then produced the key
        # `API_TOKEN\n`, sending this port looking for a differently named file and
        # variable than the others.
        return 0 if $part !~ /\A[a-z0-9_]+\z/;
    }

    return 1;
}

sub checkname {
    my ($name) = @_;

    fail( 'sekreto: invalid name: ' . ( defined $name && !ref($name) ? $name : '' ) )
      if !validname($name);

    return $name;
}

# The environment-variable key for a name: `api.token` -> `API_TOKEN`.
sub envkey {
    my ( $name, $prefix ) = @_;

    checkname($name);

    return ( defined $prefix ? $prefix : '' ) . uc( join( '_', split( /\./, $name, -1 ) ) );
}

# Where a name lives in a KV vault: `api.token` -> `api` / `token`.
#
# A single-segment name has no path of its own, so it becomes a secret of
# that name with the conventional field `value`.
sub vaultref {
    my ($name) = @_;

    checkname($name);

    my @parts = split( /\./, $name, -1 );

    return { path => $parts[0], field => 'value' } if 1 == scalar(@parts);

    my $field = pop @parts;

    return { path => join( '/', @parts ), field => $field };
}

# A name flattened to one segment: `api.token` -> `api_token` (GCP Secret
# Manager, `_`) or `api-token` (Azure Key Vault, `-`).
#
# Those stores have no path hierarchy and reject dots in ids, so the dots
# become the store's conventional separator. With `-` as the separator,
# underscores flatten too: Azure Key Vault's alphabet is letters, digits
# and hyphens only, and a valid sekreto name like `with_underscore` must
# still be representable there. (The resulting `.`/`_` collision mirrors
# the documented envkey behaviour, where both already map to `_`.)
sub flatname {
    my ( $name, $sep ) = @_;

    checkname($name);

    my $flat = join( $sep, split( /\./, $name, -1 ) );

    return '-' eq $sep ? join( '-', split( /_/, $flat, -1 ) ) : $flat;
}

# The AWS SSM Parameter Store name for a name: dots become the path
# hierarchy, rooted at `/` (or at a prefix): `db.pass.main` ->
# `/db/pass/main`, or `/app/db/pass/main` under prefix `/app`.
sub awsparam {
    my ( $name, $prefix ) = @_;

    checkname($name);

    my $base = defined $prefix ? $prefix : '';
    $base = '/' . $base if '' ne $base && 0 != index( $base, '/' );
    $base =~ s{/$}{};

    return $base . '/' . join( '/', split( /\./, $name, -1 ) );
}

# Parse `.env` text into a map of raw keys to values.
#
# Deliberately small: `KEY=value`, optional `export`, `#` comments on their
# own line, and single- or double-quoted values (double quotes also unescape
# \n, \r, \t and \\). A line with no `=` is skipped.
sub parsedotenv {
    my ($text) = @_;

    my %out;

    return \%out if !defined $text || ref($text);

    for my $rawline ( split( /\n/, $text, -1 ) ) {
        my $line = $rawline;
        $line =~ s/\r$//;
        $line =~ s/^\s+|\s+$//g;

        next if '' eq $line || 0 == index( $line, '#' );

        my $body = $line;
        if ( 0 == index( $line, 'export ' ) ) {
            $body = substr( $line, 7 );
            $body =~ s/^\s+|\s+$//g;
        }

        my $eq = index( $body, '=' );
        next if 0 >= $eq;

        my $key = substr( $body, 0, $eq );
        $key =~ s/^\s+|\s+$//g;

        my $value = substr( $body, $eq + 1 );
        $value =~ s/^\s+|\s+$//g;

        if ( 2 <= length($value) && '"' eq substr( $value, 0, 1 ) && '"' eq substr( $value, -1 ) ) {
            $value = unescape( substr( $value, 1, -1 ) );
        }
        elsif ( 2 <= length($value)
            && "'" eq substr( $value, 0, 1 )
            && "'" eq substr( $value, -1 ) )
        {
            $value = substr( $value, 1, -1 );
        }

        $out{$key} = $value;
    }

    return \%out;
}

sub unescape {
    my ($text) = @_;

    my $out   = '';
    my $index = 0;
    my $len   = length($text);

    while ( $index < $len ) {
        my $head = substr( $text, $index, 1 );

        if ( '\\' eq $head && $index + 1 < $len ) {
            my $next = substr( $text, $index + 1, 1 );
            $index += 2;

            if    ( 'n' eq $next )    { $out .= "\n" }
            elsif ( 'r' eq $next )    { $out .= "\r" }
            elsif ( 't' eq $next )    { $out .= "\t" }
            elsif ( '\\' eq $next )   { $out .= '\\' }
            elsif ( '"' eq $next )    { $out .= '"' }
            else                      { $out .= '\\' . $next }
        }
        else {
            $out .= $head;
            $index++;
        }
    }

    return $out;
}

# Replace known secret values in text with `[redacted]`.
#
# Only values of four characters or more are replaced: shorter ones are too
# likely to appear in ordinary text, and redacting them would make logs
# unreadable without making them safer.
sub redact {
    my ( $text, $values ) = @_;

    my $out = defined $text && !ref($text) ? $text : '';

    my @usable = grep { defined $_ && !ref($_) && 4 <= length($_) } @{ $values || [] };

    # Longest first: a shorter secret that prefixes a longer one used to eat
    # the prefix and leave the rest in the log. @usable is our own list, so
    # sorting it does not reorder the caller's.
    for my $value ( sort { length($b) <=> length($a) } @usable ) {
        $out = join( '[redacted]', split( /\Q$value\E/, $out, -1 ) );
    }

    return $out;
}

# The store name a provider answers to when its spec does not say.
#
# `describe` opens with the provider's kind - `hashicorp:...`, `dotenv:...`,
# plain `env` - so the kind is the natural default, and a custom provider
# gets a sensible name without implementing anything extra.
sub storename {
    my ( $provider, $spec ) = @_;

    return $spec->{name} if $spec && $spec->{name};

    return ( split( /:/, $provider->describe(), 2 ) )[0];
}

# The secrets facade: a chain of providers plus a cache.
#
# Two ways to read. `get` is transparent - it walks the chain and takes the
# first hit, and the caller never learns which store answered. `getfrom` is
# directed - it names the store, and only that store is asked.
sub new {
    my ( $class, $options ) = @_;

    my $opts = $options || {};

    my @entries;
    for my $entry ( @{ $opts->{providers} || [] } ) {
        if ( ref($entry) && 'HASH' eq ref($entry) ) {
            my $provider = makeprovider($entry);
            push @entries, [ storename( $provider, $entry ), $provider ];
        }
        else {
            push @entries, [ storename($entry), $entry ];
        }
    }

    my $self = {
        entries => \@entries,
        docache => ( exists $opts->{cache} && !$opts->{cache} ) ? 0 : 1,

        # A list, not a hash: the store a value came from stays attached,
        # and redaction order does not vary between runs.
        cache => [],

        # Every value ever resolved, for redactall. Kept independently of
        # the read cache so that redaction still works when cache is off -
        # otherwise `cache => 0` would silently disable redactall and leak
        # secrets to logs.
        seen => [],
    };

    return bless $self, $class;
}

# The secret, or a SekretoError if no provider has it.
sub get {
    my ( $self, $name ) = @_;

    my $found = $self->try($name);

    fail( 'sekreto: unknown secret: ' . $name ) if !defined $found;

    return $found;
}

# The secret, or undef if no provider has it.
sub try {
    my ( $self, $name ) = @_;
    return $self->_resolve( '', $name, $self->{entries} );
}

# The secret from one named store, or a SekretoError if that store does not
# have it.
sub getfrom {
    my ( $self, $store, $name ) = @_;

    my $found = $self->tryfrom( $store, $name );

    fail( 'sekreto: unknown secret: ' . $store . ':' . $name ) if !defined $found;

    return $found;
}

# The secret from one named store, or undef if that store does not have it.
#
# Naming a store that is not in the chain is an error, not a miss: `try`
# already means "this store may not have it", so it cannot also mean "this
# store may not exist" without hiding a typo.
sub tryfrom {
    my ( $self, $store, $name ) = @_;

    my @matching = grep { $_->[0] eq $store } @{ $self->{entries} };

    fail( 'sekreto: unknown store: ' . $store ) if 0 == scalar(@matching);

    return $self->_resolve( $store, $name, \@matching );
}

sub _resolve {
    my ( $self, $store, $name, $entries ) = @_;

    checkname($name);

    if ( $self->{docache} ) {
        for my $cached ( @{ $self->{cache} } ) {
            return $cached->[2] if $cached->[0] eq $store && $cached->[1] eq $name;
        }
    }

    for my $entry ( @{$entries} ) {
        my $found = $entry->[1]->lookup($name);

        if ( defined $found ) {
            push @{ $self->{cache} }, [ $store, $name, $found ] if $self->{docache};
            push @{ $self->{seen} }, $found;
            return $found;
        }
    }

    return undef;
}

# Does any provider have this secret?
sub has {
    my ( $self, $name ) = @_;
    return defined $self->try($name) ? 1 : 0;
}

# Does this named store have this secret?
sub hasin {
    my ( $self, $store, $name ) = @_;
    return defined $self->tryfrom( $store, $name ) ? 1 : 0;
}

# Every named secret at once. Missing ones are an error.
sub all {
    my ( $self, $names ) = @_;

    my %out;
    $out{$_} = $self->get($_) for @{$names};

    return \%out;
}

# A description of each provider, in resolution order.
sub sources {
    my ($self) = @_;
    return [ map { $_->[1]->describe() } @{ $self->{entries} } ];
}

# The name of each store that can be named by `getfrom`, in resolution order
# and without repeats.
sub stores {
    my ($self) = @_;

    my ( @out, %seen );
    for my $entry ( @{ $self->{entries} } ) {
        push @out, $entry->[0] if !$seen{ $entry->[0] }++;
    }

    return \@out;
}

# Replace every value this Sekreto has resolved with `[redacted]`.
#
# Works whether or not caching is enabled: the redaction list is kept
# independently of the read cache.
sub redactall {
    my ( $self, $text ) = @_;
    return redact( $text, $self->{seen} );
}

# Drop cached values, so the next `get` asks the providers again.
sub refresh {
    my ($self) = @_;
    $self->{cache} = [];
    return;
}

# Make a Sekreto from options.
sub sekreto {
    my ($options) = @_;
    return Voxgig::Sekreto->new($options);
}

1;
