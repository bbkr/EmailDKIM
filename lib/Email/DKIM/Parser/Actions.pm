unit grammar Email::DKIM::Parser::Actions;

use Email::DKIM::Header;

=begin pod

=head1 NAME

Email::DKIM::Parser::Actions

=head1 DESCRIPTION

Convert parsed tokens into L<Email::DKIM::Header>s and L<Email::DKIM::Body>.

=head1 METHODS

=end pod

=begin pod

=head2 TOP

Return Array of Headers and single Body objects.

=end pod

method TOP ( $/ ) {
    
    return;
    
}

method header ( $/ ) {
    say $/;

}
