unit class Email::DKIM;

use Email::DKIM::Header;
use Email::DKIM::Body;
use Email::DKIM::Signature;

has %.headers;
has Email::DKIM::Body $.body;

submethod BUILD ( Str:D :$message! ) {
    
    require Email::DKIM::Parser::Grammar;
    require Email::DKIM::Parser::Actions;
    
    my $parsed = Email::DKIM::Parser::Grammar.parse(
        $message,
        actions => Email::DKIM::Parser::Actions.new
    );
    
    unless $parsed {
        !!!        
    }
    
    with $parsed.made {
        %!headers = .head;
        $!body = .tail;
    }
}
