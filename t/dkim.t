use lib 'lib';

use Test;
use Email::MIME;
use MIME::Base64;
use OpenSSL::RSATools;

use Email::DKIM;
use Email::DKIM::Signer;

plan 4;

# Integration test to confirm that we can go full circle:
# sign text data, transport signatures in text form and verify text data.
subtest 'RSA and Base64 toolchain' => sub {

    plan 2;

    my $data = 'Zażółć gęślą jaźń';

    my $private-pem = slurp 't/rsa/private.pem';
    my $public-pem = slurp 't/rsa/public.pem';

    my $rsa-private = OpenSSL::RSAKey.new( :$private-pem );
    my $signature-sha1      = $rsa-private.sign( $data.encode, :sha1 );
    my $signature-sha256    = $rsa-private.sign( $data.encode, :sha256 );

    my $base64-signature-sha1   = MIME::Base64.encode( $signature-sha1,     :oneline);
    my $base64-signature-sha256 = MIME::Base64.encode( $signature-sha256,   :oneline);

    my $rsa-public = OpenSSL::RSAKey.new( :$public-pem );
    my $verification-sha1   = $rsa-public.verify( $data.encode, MIME::Base64.decode( $base64-signature-sha1 ),      :sha1 );
    my $verification-sha256 = $rsa-public.verify( $data.encode, MIME::Base64.decode( $base64-signature-sha256 ),    :sha256 );

    ok $verification-sha1,      'RSA-SHA1 signed and verified';
    ok $verification-sha256,    'RSA-SHA256 signed and verified';

    bail-out unless $verification-sha1 and $verification-sha256;

};

# https://tools.ietf.org/html/rfc6376#section-5.3
subtest 'network normalization' => sub {
    
    plan 4;
    
    is Email::DKIM.normalize("\x0D"), "\x0D\x0A", 'bare CR normalized';
    is Email::DKIM.normalize("\x0A"), "\x0D\x0A", 'bare LF normalized';
    is Email::DKIM.normalize("\x0D\x0A"), "\x0D\x0A", 'sequence CRLF left intact';
    is Email::DKIM.normalize("\x0A\x0D"), "\x0D\x0A\x0D\x0A", 'sequence LFCR normalized';
    
};

# https://tools.ietf.org/html/rfc6376#section-3.4.1
subtest 'canonicalization header simple' => sub {
    
    plan 1;
    
    is Email::DKIM.canonicalize_header_simple("SubjEct: foo \x0D\x0A bar \x0D\x0A"),
        "SubjEct: foo \x0D\x0A bar \x0D\x0A", 'header is not altered';
    
};

# https://tools.ietf.org/html/rfc6376#section-3.4.3
subtest 'canonicalization body simple' => sub {
    
    plan 3;
    
    is Email::DKIM.canonicalize_body_simple(""), "\x0D\x0A", 'empty normalized';
    is Email::DKIM.canonicalize_body_simple("\x0D\x0A"), "\x0D\x0A", 'single sequence CRLF at the end left intact';
    is Email::DKIM.canonicalize_body_simple("\x0D\x0A\x0D\x0A"), "\x0D\x0A", 'multiple sequence CRLF at the end normalized';
    
};
