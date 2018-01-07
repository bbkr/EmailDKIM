use v6;

use lib 'lib';

use Test;
use Email::DKIM::Body;

plan 4;

my $body;

$body = Email::DKIM::Body.new(
    lines => [ ],
);

is $body.canonicalize( 'simple' ), "\r\n", 'empty body canonicalized using simple algorithm';
is $body.canonicalize( 'simple' ), "\r\n", 'canonicalization cache';

$body = Email::DKIM::Body.new(
    lines => [ 'Foo' ],
);

is $body.canonicalize( 'simple' ), "Foo\r\n", 'body without CRLF at the end canonicalized using simple algorithm';

$body = Email::DKIM::Body.new(
    lines => [ 'Foo', '', '' ],
);

is $body.canonicalize( 'simple' ), "Foo\r\n", 'body with empty lines at the end canonicalized using simple algorithm';
