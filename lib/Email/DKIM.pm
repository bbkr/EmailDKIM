unit class Email::DKIM;

use Email::DKIM::Parser::Grammar;
use Email::DKIM::Parser::Actions;

submethod BUILD ( Str:D :$message! ) {
    my $parsed =  MIME.parse( $message );
    say $parsed;
}
