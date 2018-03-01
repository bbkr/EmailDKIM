use v6;

use lib 'lib';

use Test;
use Email::DKIM::Parser::Grammar;
use Email::DKIM::Parser::Actions;

my $actions = Email::DKIM::Parser::Actions.new;

my $message = "Foo: Bar\r\n\r\n";
my ( $headers, $body ) = Email::DKIM::Parser::Grammar.parse( $message, :$actions ).made;
is-deeply $headers{ 'foo' }[ 0 ].body, [ 'Bar' ], 'simple header parsed';
is-deeply $body.lines, [ ], 'empty body parsed';

# my $message = "Foo: Bar\r\n\r\n";
# my ( $headers, $body ) = Email::DKIM::Parser::Grammar.parse( $message, :$actions ).made;
# is-deeply $headers{ 'foo' }[ 0 ].body, [ 'Bar' ], 'simple header parsed';
# is-deeply $body.lines, [ ], 'empty body parsed';

