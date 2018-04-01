use v6;

use lib 'lib';

use Test;
use Email::DKIM;
use OpenSSL::RSATools;

my $private-pem = slurp 't/rsa/private.pem';

my $message = "Foo: Bar\r\n\r\nBaz";

my $dkim = Email::DKIM.new( :$message );
isa-ok $dkim, Email::DKIM, 'constructed from message string';

say $dkim.sign(
    header-canonicalization => 'simple',
    domain => 'example.com',
    selector => 's1',
    key => OpenSSL::RSAKey.new( :$private-pem ),
    
);