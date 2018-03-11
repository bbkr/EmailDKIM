use v6;

use lib 'lib';

use Test;
use Email::DKIM::Body;

plan 2;

subtest 'canonicalization simple' => sub {

    plan 4;
    
    my $body = Email::DKIM::Body.new(
        lines => [ ],
    );

    is $body.canonicalize( 'simple' ), "\r\n", 'empty';
    is $body.canonicalize( 'simple' ), "\r\n", 'canonicalization cache';

    $body = Email::DKIM::Body.new(
        lines => [ 'Foo' ],
    );

    is $body.canonicalize( 'simple' ), "Foo\r\n", 'without CRLF at the end';

    $body = Email::DKIM::Body.new(
        lines => [ 'Foo', '', '' ],
    );

    is $body.canonicalize( 'simple' ), "Foo\r\n", 'with empty lines at the end';

};

subtest 'canonicalization relaxed' => sub {

    todo 'NYI';
    
};
