use v6;

use lib 'lib';

use Test;
use Email::DKIM::Parser::Grammar;
use Email::DKIM::Parser::Actions;

my $actions = Email::DKIM::Parser::Actions.new;
my $printable_ascii = "!" .. "~";

my $message = "Foo: Bar\r\n\r\n";
my ( $headers, $body ) = Email::DKIM::Parser::Grammar.parse( $message, :$actions ).made;
is-deeply $headers{ 'foo' }[ 0 ].body, [ 'Bar' ], 'simple header parsed';
is-deeply $body.lines, [ ], 'empty body parsed';


# header name from all allowed characters
$message = ($printable_ascii (-) ":").keys.sort.join;

# header separator
# note that DKIM canonicalization allows trailing whitespaces while MIME does not
$message ~= "\t : \t";

# header body from all allowed characters
$message ~= $printable_ascii.sort.join ~ "\t ";

# header continuation
# note that DKIM normalization allows bare CR or LF line breaks while MIME does not
$message ~= "\r foo ";

# header continuation
# note that DKIM normalization allows bare CR or LF line breaks while MIME does not
$message ~= "\n\tbar\t";

# header continuation
$message ~= "\r\n baz\r\n";

# headers and body separator
$message ~= "\r\n";

# body with all ACII characters allowed
# bare CR and LF will be normalized as newlines
$message ~= ( "\x[00]" .. "\x[7F]" ).join;

# body empty line
$message ~= "\r\n\r\n";

( $headers, $body ) = Email::DKIM::Parser::Grammar.parse( $message, :$actions ).made;
is-deeply $headers{ '!"#$%&\'()*+,-./0123456789;<=>?@abcdefghijklmnopqrstuvwxyz[\]^_`abcdefghijklmnopqrstuvwxyz{|}~' }[ 0 ].body,
    [ "!\"#\$\%\&'()*+,-./0123456789:;<=>?\@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz\{|}~\t ", "foo ", "bar\t", "baz" ],
    'complex header parsed';
is-deeply $body.lines, [
    "\0\x[1]\x[2]\x[3]\x[4]\x[5]\x[6]\x[7]\b\t",
    "\x[b]\x[c]",
    "\x[e]\x[f]\x[10]\x[11]\x[12]\x[13]\x[14]\x[15]\x[16]\x[17]\x[18]\x[19]\x[1a]\x[1b]\x[1c]\x[1d]\x[1e]\x[1f] " ~ $printable_ascii.sort.join ~ "\x[7f]",
    ""
], 'complex body parsed';
