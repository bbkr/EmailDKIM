use v6;

# Integration test to confirm that we can go full circle:
# sign text data, transport signatures in text form and verify text data.

use Test;
use MIME::Base64;
use OpenSSL::RSATools;

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

bail-out 'RSA and Base64 toolchain failed' unless $verification-sha1 and $verification-sha256;
