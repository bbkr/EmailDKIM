unit grammar Email::DKIM::Parser::Grammar;

=begin pod

=head1 NAME

Email::DKIM::Parser::Grammar

=head1 DESCRIPTION

Parses MIME messages according to L<https://tools.ietf.org/html/rfc5322>
with few simplifications mentioned below that are irrelevant
for signing/verification but greatly speed up parsing process

=head1 METHODS

=end pod

=begin pod

=head2 message

Matches message as defined in L<https://tools.ietf.org/html/rfc5322#section-2>.
Maximum line length of 998 characters requirement is ignored.

=end pod

token TOP {
    
    ^
    <header>+
    <.newline>
    <body>?
    $
    
}

=begin pod

=head2 header

Matches header as defined in L<https://tools.ietf.org/html/rfc5322#section-2.2>.
Structured headers are not analyzed.

=end pod

token header {
    
    # SPEC: Header fields are lines beginning with a field name
    #       followed by a colon, followed by a field body.
    #       A field name MUST be composed of
    #       printable US-ASCII characters except colon.
    $<name> = [ <+ [ \x21 .. \x7E ] - [:] >+ ]
    
    # note that RFC 5322 does not allow WSP between header name and colon
    # but RFC 6376 tells how to canonicalize it so it is also allowed while parsing
    $<separator> = [ [ \x09 | \x20 ]* ':' [ \x09 | \x20 ]* ]
    
    # SPEC: A field body may be composed of printable US-ASCII characters
    #       as well as the space and horizontal tab characters
    $<body> = [ <+ [ \x21 .. \x7E \x20 \x09 ] >* ]
    
    # SPEC: For convenience however,
    #       and to deal with the 998/78 character limitations per line,
    #       the field body portion of a header field can be split into
    #       a multiple-line representation; this is called "folding".
    #       The general rule is that wherever this specification
    #       allows for folding white space (not simply WSP characters),
    #       a CRLF may be inserted before any WSP.
    [
        <.newline> [ \x09 | \x20 ]+
        $<body> = [ <+ [ \x21 .. \x7E \x20 \x09 ] >* ]
    ]*
    
    <.newline>

}

=begin pod

=head2 body

Matches body as defined in L<https://tools.ietf.org/html/rfc5322#section-2.3>.

=end pod

token body {
    
    # SPEC: The body of a message is simply lines of US-ASCII characters.
    [ $<line> = [ <+ [\x00 .. \x7F ] >*? ] <.newline> ]*
    [ $<line> = [ <+ [\x00 .. \x7F ]>+ ] ]?
    
}

=begin pod

=head2 newline

Matches line delimiter in message.
To speed up canonicalization normalized newlines are used.

=end pod

token newline {
    
    # SPEC: Normalize the Message to Prevent Transport Conversions
    #       https://tools.ietf.org/html/rfc6376#section-5.3
    #       
    #       In particular, bare CR or LF characters
    #       (used by some systems as a local line separator convention)
    #       MUST be converted to the SMTP-standard CRLF sequence
    #       before the message is signed.
    \x0D\x0A | \x0D | \x0A
    
}
