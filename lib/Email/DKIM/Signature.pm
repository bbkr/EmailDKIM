unit class Email::DKIM::Signature;

use OpenSSL::RSATools;

=begin pod

=head1 NAME

Email::DKIM::Signature

=head1 DESCRIPTION

Represents single DKIM-Signature header.

=head1 ATTRIBUTES

=head3 version

Defines the version of specification that applies to the signature record.
It MUST be C<v1> for RFC 6376.

=end pod

has Version $.version = v1 is required;

=begin pod

=head3 algorithm

The algorithm used to generate the signature.
Allowed values are C<rsa-sha1> and C<rsa-sha256>.
Only C<rsa-sha256> SHOULD be used for signing.

=end pod

subset Algorithm of Str where 'rsa-sha1' | 'rsa-sha256';
has Algorithm $.algorithm is required;

=begin pod

=head3 key

RSA key used to sign or verify signature.
Verification will create it automatically based on DNS.

=end pod

has OpenSSL::RSAKey $.key;

=begin pod

=head3 header-canonicalization / body-canonicalization

Informs of the type of canonicalization
used to prepare the message for signing. 
Allowed values are C<simple> and C<relaxed>.

=end pod

subset Canonicalization of Str where 'simple' | 'relaxed';
has Canonicalization $.header-canonicalization is required;
has Canonicalization $.body-canonicalization is required;

=begin pod

=head3 domain



=end pod

has Str $.domain is required;

