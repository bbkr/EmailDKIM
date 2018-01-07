unit class Email::DKIM::Body;

=begin pod

=head1 NAME

Email::DKIM::Body

=head1 DESCRIPTION

Represents message body and provides canonicalization algorithms.

=head1 ATTRIBUTES

=end pod

=begin pod

=head2 lines

Lines of body, exactly as they appear in message.
Must be splited by normalized newlines
and all whitespaces must be preserved.

=end pod

has @.lines is required;

# cache for canonicalized versions
has $!canonicalized_simple;
has $!canonicalized_relaxed;

# newline defined in DKIM spec
constant CRLF = "\x0D\x0A";

=begin pod

=head3 canonicalize( 'simple' )

Return body canonicalized using simple algorithm
described in L<https://tools.ietf.org/html/rfc6376#section-3.4.3>.

=end pod

multi method canonicalize ( 'simple' ) {
    
    # SPEC: The "simple" body canonicalization algorithm ignores all empty lines
    #       at the end of the message body.
    #       If there is no body or no trailing CRLF on the message body,
    #       a CRLF is added.
    
    return $!canonicalized_simple //= do {
        
        my $tail_index = @.lines.end;
        
        $tail_index-- while $tail_index >= 0 and !@.lines[ $tail_index ].chars;
        
        $tail_index >= 0 ?? @.lines[ 0 .. $tail_index ].map( { $_ ~ CRLF } ).join !! CRLF;
    };
}

=begin pod

=head3 canonicalize( 'relaxed' )

Return body canonicalized using relaxed algorithm
described in L<https://tools.ietf.org/html/rfc6376#section-3.4.4>.

=end pod

multi method canonicalize ( 'relaxed' ) {
    !!!
}
