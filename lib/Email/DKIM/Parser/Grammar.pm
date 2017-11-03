# grammar to parse MIME messages
# according to https://tools.ietf.org/html/rfc5322#section-2.2
# with few simplifications mentioned below that are irrelevant
# for signing/verification but greatly speed up parsing process
unit grammar MIME;
    
token TOP {
    
    ^ <message> $
    
}

# line delimiter in message,
# grammar already uses normalized form to speed up canonicalization later
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

# https://tools.ietf.org/html/rfc5322#section-2.1
# 998 character maximum line length is ignored
token message {
    
    <header>+
    <.newline>
    <body>?
    
}

# https://tools.ietf.org/html/rfc5322#section-2.2
# structured headers are not analyzed
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

# https://tools.ietf.org/html/rfc5322#section-2.3
token body {
    
    # SPEC: The body of a message is simply lines of US-ASCII characters.
    [ $<line> = [ <+ [\x00 .. \x7F ] >*? ] <.newline> ]*
    [ $<line> = [ <+ [\x00 .. \x7F ]>+ ] ]?
}
