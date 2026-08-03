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

our @EXPORT_OK = qw(
  envkey parsedotenv redact sekreto validname vaultref
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
        return 0 if $part !~ /^[a-z0-9_]+$/;
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

    for my $value ( @{ $values || [] } ) {
        next if !defined $value || ref($value);
        next if 4 > length($value);

        $out = join( '[redacted]', split( /\Q$value\E/, $out, -1 ) );
    }

    return $out;
}

# The secrets facade: a chain of providers plus a cache.
sub new {
    my ( $class, $options ) = @_;

    my $opts = $options || {};

    my @providers =
      map { ref($_) && 'HASH' eq ref($_) ? makeprovider($_) : $_ } @{ $opts->{providers} || [] };

    my $self = {
        providers => \@providers,
        docache => ( exists $opts->{cache} && !$opts->{cache} ) ? 0 : 1,
        cache => {},
        order => [],
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

    checkname($name);

    return $self->{cache}{$name} if $self->{docache} && exists $self->{cache}{$name};

    for my $provider ( @{ $self->{providers} } ) {
        my $found = $provider->lookup($name);

        if ( defined $found ) {
            if ( $self->{docache} ) {
                push @{ $self->{order} }, $name if !exists $self->{cache}{$name};
                $self->{cache}{$name} = $found;
            }
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
    return [ map { $_->describe() } @{ $self->{providers} } ];
}

# Replace every value this Sekreto has resolved with `[redacted]`.
sub redactall {
    my ( $self, $text ) = @_;
    return redact( $text, [ map { $self->{cache}{$_} } @{ $self->{order} } ] );
}

# Drop cached values, so the next `get` asks the providers again.
sub refresh {
    my ($self) = @_;
    $self->{cache} = {};
    $self->{order} = [];
    return;
}

# Make a Sekreto from options.
sub sekreto {
    my ($options) = @_;
    return Voxgig::Sekreto->new($options);
}

1;
