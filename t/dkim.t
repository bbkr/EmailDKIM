use lib 'lib';

use MIME::Base64;
use OpenSSL::RSATools;

my $private-pem = slurp 't/rsa/private.pem';
my $public-pem = slurp 't/rsa/public.pem';
my $rsa = OpenSSL::RSAKey.new(:$private-pem);
my $data = 'foo';

my $signature = $rsa.sign($data.encode, :sha256);
my $base64 = MIME::Base64.encode($signature, :oneline);
say $base64;

my $rsa2 = OpenSSL::RSAKey.new(:$public-pem);
say $rsa2.verify($data.encode, MIME::Base64.decode($base64), :sha256);
