unit class Email::DKIM;

submethod BUILD ( Str:D :$message! ) {
    my $parsed =  MIME.parse( $message );
    say $parsed;
}


=finish


has %!headers;
has @!body;

class Header {
    has Str $.name is required;
    has @.lines;
}

submethod BUILD ( Str:D :$message! ) {
    
    # track what next line can contain
    my $expected = 'header_start';
    
    # track last header in case of continuation
    my $last_header;
    
    # SPEC: Normalize the Message to Prevent Transport Conversions
    #       https://tools.ietf.org/html/rfc6376#section-5.3
    #       
    #       In particular, bare CR or LF characters
    #       (used by some systems as a local line separator convention)
    #       MUST be converted to the SMTP-standard CRLF sequence
    #       before the message is signed.
    #
    # 
    for split / \x0D\x0A | \x0D | \x0A /, $message -> $line {
        
        
        
        if $expected eq 'header_start' {
            
            # check if line starts with header name as described in
            # https://tools.ietf.org/html/rfc5322#section-2.2
            
            state $header_regexp = rx/
                
                # SPEC: Header fields are lines beginning with a field name
                #       followed by a colon, followed by a field body...
                ^
                
                # SPEC: A field name MUST be composed of
                #       printable US-ASCII characters except colon.
                $<name> = [ <+ [ \x21 .. \x7E ] - [:] >+ ]
                
                # note that RFC 5322 does not allow WSP between header name and colon
                # but RFC 6376 tells how to canonicalize it
                # so it is also allowed while parsing
                $<separator> = [ [ \x09 | \x20 ]* ':' [ \x09 | \x20 ]* ]
                
                # SPEC: A field body may be composed of printable US-ASCII characters
                #       as well as the space and horizontal tab characters
                $<body> = [ <+ [ \x21 .. \x7E \x20 \x09 ] >* ]
            
                # end of line
                $
            /;
            
            if $line ~~ $header_regexp {
                
                push %headers
                $expected = 'header_start' | 'header_continuation' | 'headers_end';
            }
            else {
                die "parsing failed";
            
            }
        
        }
    }

}


=finish

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

=begin pod

=head3 canonicalize_body_simple

Canonicalize body using simple algorithm,
see L<https://tools.ietf.org/html/rfc6376#section-3.4.3>.

=end pod

method canonicalize_body_simple ( Str:D $text is copy --> Str:D ) {
    
    # SPEC: The "simple" body canonicalization algorithm ignores all empty lines
    #       at the end of the message body. An empty line is a line of zero
    #       length after removal of the line terminator.
    #       If there is no body or no trailing CRLF on the message body, a CRLF is added.
    
    # TODO: a bit naive method, should be optimized later
    $text ~~ s/ [\x0D\x0A]* $/\x0D\x0A/;
    
    return $text;
}
