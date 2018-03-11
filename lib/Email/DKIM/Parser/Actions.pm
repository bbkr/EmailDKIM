unit grammar Email::DKIM::Parser::Actions;

use Email::DKIM::Header;
use Email::DKIM::Body;

=begin pod

=head1 NAME

Email::DKIM::Parser::Actions

=head1 DESCRIPTION

Convert parsed tokens into L<Email::DKIM::Header>s and L<Email::DKIM::Body>.

=head1 METHODS

=end pod

=begin pod

=head2 TOP

Return Hash of Array of Header instances and single Body instance.

=end pod

method TOP ( $/ ) {
    
    make ( $/{ 'header' }.classify( *.made.name.lc, as => *.made ).item, $/{ 'body' }.made );
}

method header ( $/ ) {
    
    make Email::DKIM::Header.new(
        name => $/{ 'name' }.Str,
        separator => $/{ 'separator' }.Str,
        body => $/{ 'body' }.map: *.Str
    );
}

method body ( $/ ) {
    
    make Email::DKIM::Body.new(
        lines => $/{ 'line' }.map: *.Str
    );
}
