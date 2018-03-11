use v6;

use lib 'lib';

use Test;
use Email::DKIM::Header;

plan 2;

subtest 'canonicalization simple' => sub {

    plan 3;

    my $header = Email::DKIM::Header.new(
        name => 'Foo',
        separator => ':',
        body => [ 'Bar' ]
    );

    is $header.canonicalize( 'simple' ), "Foo:Bar\r\n", 'with letters only';
    is $header.canonicalize( 'simple' ), "Foo:Bar\r\n", 'canonicalization cache';

    $header = Email::DKIM::Header.new(
        name => '!"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~',
        separator => " \t:\t ",
        body => [ 'Bar ', '  B az' ]
    );

    is $header.canonicalize( 'simple' ),
        "!\"#\$\%\&'()*+,-./0123456789:;<=>?\@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz\{|\}~ \t:\t Bar \r\n  B az\r\n",
        'with all allowed characters';

};

subtest 'canonicalization relaxed' => sub {

    todo 'NYI';
    
};
