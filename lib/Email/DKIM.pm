unit class Email::DKIM;

use MIME::Base64;
use OpenSSL::Digest;
use OpenSSL::RSATools;
use Email::DKIM::Header;
use Email::DKIM::Body;
use Email::DKIM::Signature;

has %.headers;
has Email::DKIM::Body $.body;

submethod BUILD ( Str:D :$message! ) {
    
    require Email::DKIM::Parser::Grammar;
    require Email::DKIM::Parser::Actions;
    
    my $parsed = Email::DKIM::Parser::Grammar.parse(
        $message,
        actions => Email::DKIM::Parser::Actions.new
    );
    
    unless $parsed {
        !!!        
    }
    
    with $parsed.made {
        %!headers = .head;
        $!body = .tail;
    }
}

# SPEC: Recommended Signature Content
#       L<https://tools.ietf.org/html/rfc6376#section-5.4.1> 

method sign (

    # SPEC: The algorithm used to generate the signature.
    #       Signers SHOULD sign using "rsa-sha256".
    Algorithm :$algorithm = 'rsa-sha256',
    
    # SPEC: Message canonicalization.
    Canonicalization :$header-canonicalization = 'simple',
    Canonicalization :$body-canonicalization = 'simple',

    # SPEC: The SDID claiming responsibility
    #       for an introduction of a message into the mail stream.
    Str:D :$domain!,

    # SPEC: Signed header fields.
    #       The basic rule for choosing fields to include is
    #       to select those fields that constitute the "core" of the message content.
    :@headers = (
        'From', 'Reply-To', 'Subject', 'Date', 'To', 'Cc',
        'Resent-Date', 'Resent-From', 'Resent-To', 'Resent-Cc', 'In-Reply-To', 'References',
        'List-Id', 'List-Help', 'List-Unsubscribe', 'List-Subscribe', 'List-Post', 'List-Owner', 'List-Archive'
    ),

    # SPEC: The selector subdividing the namespace.
    Str:D :$selector!,

    # RSA private key.
    OpenSSL::RSAKey :$key! where .private

) {

    # DKIM header tags
    my %header = (
        'v'  => 1,
        'a'  => $algorithm,
        'b'  => '', # empty signature should be used for first stage
        'd'  => $domain,
        's'  => $selector,
    );
    
    # SPEC: The Signer/Verifier MUST compute two hashes: one over the body of the
    #       message and one over the selected header fields of the message.
    #       Signers MUST compute them in the order shown.
    # 
    #       In hash step 1, the Signer/Verifier MUST hash the message body,
    #       canonicalized using the body canonicalization algorithm specified in
    #       the "c=" tag
    %header{ 'c' } = $header-canonicalization;
    %header{ 'c' } ~= '/' ~ $_ with $body-canonicalization;
    
    # SPEC: If only one algorithm is named, that algorithm is used for the header
    #       and "simple" is used for the body.
    %header{ 'bh' } = $.body.canonicalize( $body-canonicalization // 'simple' );
    
    # convert to Buf and perform SHA hashing
    %header{ 'bh' } .= encode( );
    %header{ 'bh' } = do given $algorithm {
        when 'rsa-sha1' { sha1( %header{ 'bh' } ) }
        when 'rsa-sha256' { sha256( %header{ 'bh' } ) }
    };
    
    # convert SHA to Base64 for email transport
    %header{ 'bh' } = MIME::Base64.encode( %header{ 'bh' }, :oneline);
    
    return %header;
}

