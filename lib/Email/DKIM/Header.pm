unit class Email::DKIM::Header;

=begin pod

=head1 NAME

Email::DKIM::Header

=head1 DESCRIPTION

Represents single message header and provides canonicalization algorithms.

=head1 ATTRIBUTES

=end pod

=begin pod

=head2 name

Name, exactly as it appears in message.

=end pod

has Str $.name is required;

=begin pod

=head2 separator

Name and body separator, exactly as it appears in message.
Must include leading and trailing whitespaces, if any.

=end pod

has Str $.separator is required;

=begin pod

=head2 body

Lines of body, exactly as they appear in message.
Must be splited by normalized newlines
and leading whitespaces must be preserved.

=end pod

has @.body is required;

# cache for canonicalized versions
has $!canonicalized_simple;
has $!canonicalized_relaxed;

# newline defined in DKIM spec
constant CRLF = "\x0D\x0A";

=begin pod

=head3 canonicalize( 'simple' )

Return header canonicalized using simple algorithm
described in L<https://tools.ietf.org/html/rfc6376#section-3.4.1>.

=end pod

multi method canonicalize ( 'simple' ) {
    
    # SPEC: The "simple" header canonicalization algorithm does not change header
    #       fields in any way.  Header fields MUST be presented to the signing or
    #       verification algorithm exactly as they are in the message being
    #       signed or verified.  In particular, header field names MUST NOT be
    #       case folded and whitespace MUST NOT be changed.
    
    return $!canonicalized_simple //= do {
        $.name ~ $.separator ~ map( { $_ ~ CRLF }, @.body ).join;
    };
}

=begin pod

=head3 canonicalize( 'relaxed' )

Return header canonicalized using relaxed algorithm
described in L<https://tools.ietf.org/html/rfc6376#section-3.4.2>.

=end pod

multi method canonicalize ( 'relaxed' ) {
    !!!
}
