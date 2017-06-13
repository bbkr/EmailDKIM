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

method normalize ( Str:D $text is copy --> Str:D ) {
    
    # SPEC: In particular, bare CR or LF characters
    #       (used by some systems as a local line separator convention)
    #       MUST be converted to the SMTP-standard CRLF sequence
    #       before the message is signed.
    
    $text ~~ s:g/
        \x0D <!before \x0A>     # CR not followed by LF
        | <!after \x0D> \x0A    # or LF not preceded by CR
    /\x0D\x0A/;
    
    return $text;
}

=begin pod

=head3 canonicalize_header_simple

Canonicalize header using simple algorithm,
see L<https://tools.ietf.org/html/rfc6376#section-3.4.1>.

=end pod

method canonicalize_header_simple ( Str:D $text is copy --> Str:D ) {
    
    # SPEC: The "simple" header canonicalization algorithm does not change header
    #       fields in any way.  Header fields MUST be presented to the signing or
    #       verification algorithm exactly as they are in the message being
    #       signed or verified.  In particular, header field names MUST NOT be
    #       case folded and whitespace MUST NOT be changed.
    
    return $text;
}

