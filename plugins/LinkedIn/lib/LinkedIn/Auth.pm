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
use Data::Dumper;

sub login {
    my $class    = shift;
    my ($app)    = @_;
    my $q        = $app->param;

    require Net::OAuth;
    require HTTP::Request::Common;
    my $ua = $app->new_ua( { paranoid => 1 } );

    my $request = Net::OAuth->request("request token")->new(
        consumer_key => 'h7rnj3ecjbs9',
        consumer_secret => 'N1Pie5VHq8yeZQjL',
        request_url => 'https://api.linkedin.com/uas/oauth/requestToken',
        request_method => 'POST',
        signature_method => 'HMAC-SHA1',
        timestamp => time(),
        nonce => 'hsu94j3884jdopsl',
        callback => __create_return_url($app),
        protocol_version => $Net::OAuth::PROTOCOL_VERSION_1_0A,
    );

    $request->sign;

    my $res = $ua->request(HTTP::Request::Common::POST($request->to_url)); # Post message to the Service Provider

    if ($res->is_success) {
        print STDERR "Request is success\n";
        print STDERR Dumper($res);
        my $response = Net::OAuth->response('request token')->from_post_body($res->content);
        print STDERR "Got Request Token ", $response->token, "\n";
        print STDERR "Got Request Token Secret ", $response->token_secret, "\n";
    }
    else {
        print STDERR "Something went wrong\n";
        print STDERR Dumper($res);
    }
    # redurect to https://api.linkedin.com/uas/oauth/authorize? oauth_token=f7868c3a-7336-4662-a6d1-3219fb4650d1
}

sub commenter_auth_params {
    my ($key, $blog_id, $entry_id, $static) = @_;
    require MT::Util;
    if ($static =~ m/^http%3A%2F%2F/) {
        # the URL was encoded before, but we want the normal version
        $static = MT::Util::decode_url($static);
    }
    my $params = {
        blog_id => $blog_id,
        static  => $static,
    };
    $params->{entry_id} = $entry_id if defined $entry_id;
    return $params;
}

sub __create_return_url {
    my $app = shift;
    my $q        = $app->param;
    my $cfg = $app->config;

    my $cgi_path = $app->config('CGIPath');
    $cgi_path .= '/' unless $cgi_path =~ m!/$!;

    my $blog_id = $q->param("blog_id");
    $blog_id =~ s/\D//g;
    my $static = $q->param("static");
    
    my @params = (
        "__mode=handle_sign_in",
        "key=LinkedIn",
        "blog_id=$blog_id",
        "static=".MT::Util::encode_url($q->param("static")),
    );

    if (my $entry_id = $q->param("entry_id")) {
        $entry_id =~ s/\D//g;
        push @params, "entry_id=$entry_id";
    }
    
    return $cgi_path . $cfg->CommentScript ."?". join('&', @params);
}

1;
