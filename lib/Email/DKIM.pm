unit class Email::DKIM;

=begin pod

=head1 NAME

Email::DKIM

=head1 DESCRIPTION

Common RFC 6376 algorithms used by L<Email::DKIM::Signer> and L<Email::DKIM::Verifier>.

=head1 METHODS

=head3 normalize

Normalize the Message to Prevent Transport Conversions,
see L<https://tools.ietf.org/html/rfc6376#section-5.3>.

=end pod

method normalize ( Str:D $chunk is copy --> Str:D ) {
    
    # SPEC: In particular, bare CR or LF characters
    #       (used by some systems as a local line separator convention)
    #       MUST be converted to the SMTP-standard CRLF sequence
    #       before the message is signed.
    
    $chunk ~~ s:g/
        \x0D <!before \x0A>     # CR not followed by LF
        | <!after \x0D> \x0A    # or LF not preceded by CR
    /\x0D\x0A/;
    
    return $chunk;
}

