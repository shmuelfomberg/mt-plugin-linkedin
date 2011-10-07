package LinkedIn::Auth;
use strict;
use warnings;

sub condition {
    my ($blog, $reason) = @_;
    my %required = (
        'Digest::HMAC_SHA1' => '1.01',
        'URI::Escape' => '3.28',
        'Class::Accessor' => '0.31',
        'Class::Data::Inheritable' => '0.06',
        'Digest::SHA1' => '2.12',
        'Encode' => '2.35',
    );
    my @not_found;
    while (my ($mod, $ver) = each %required) {
        eval "use $mod $ver;";
        if ($@) {
            push @not_found, "$mod version $ver";
        }
    }
    return 1 unless @not_found;
    $$reason = "Please install these Perl modules: ".join(", ", @not_found);
    return 0;
}

sub login {
    require Net::OAuth;
    require HTTP::Request::Common;
    my $ua = MT->new_ua( { paranoid => 1 } );

    my $request = Net::OAuth->request("request token")->new(
        consumer_key => 'h7rnj3ecjbs9',
        consumer_secret => 'N1Pie5VHq8yeZQjL',
        request_url => 'https://www.linkedin.com/uas/oauth/authenticate',
        request_method => 'POST',
        signature_method => 'HMAC-SHA1',
        timestamp => time(),
        nonce => 'hsu94j3884jdopsl',
        callback => 'http://printer.example.com/request_token_ready',
        protocol_version => $Net::OAuth::PROTOCOL_VERSION_1_0A,
        extra_params => {
            __mode => 'bar'
        },
    );

    $request->sign;

    my $res = $ua->request(POST $request->to_url); # Post message to the Service Provider

    if ($res->is_success) {
        my $response = Net::OAuth->response('request token')->from_post_body($res->content);
        print "Got Request Token ", $response->token, "\n";
        print "Got Request Token Secret ", $response->token_secret, "\n";
    }
    else {
        die "Something went wrong";
    }
}

1;
