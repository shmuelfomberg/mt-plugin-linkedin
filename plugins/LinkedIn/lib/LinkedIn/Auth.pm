package LinkedIn::Auth;
use strict;
use warnings;

my $Session_Name = "LinkedInOauthPlugin";

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

    my $session_key = $app->make_magic_token;
    require MT::Session;
    my $sess = MT::Session->new;
    $sess->id($session_key);
    $sess->kind('CR');    # CR == Commenter Registration
    $sess->name($Session_Name);
    $sess->start(time);
    $sess->duration( time + 60 * 60 );

    require WWW::LinkedIn;
    my $li = WWW::LinkedIn->new(
        consumer_key    => 'h7rnj3ecjbs9',
        consumer_secret => 'N1Pie5VHq8yeZQjL',
    );
    my $token;
    eval {
        $token = $li->get_request_token(
            callback  => __create_return_url($app, $session_key)
        );
    };
    if ($@) {
        return $app->errtrans("Failed to verify LinkedIn user");
    }

    print STDERR "Got tokens: |", $token->{token}, "|",  $token->{secret}, "|\n";
    $sess->set("LinkedInToken", $token->{token});
    $sess->set("LinkedInSecret", $token->{secret});
    $sess->save;

    return $app->redirect($token->{url});
}

sub handle_sign_in {
    my $class = shift;
    my ( $app, $auth_type ) = @_;
    my $q = $app->param;

    require WWW::LinkedIn;
    my $li = WWW::LinkedIn->new(
        consumer_key    => 'h7rnj3ecjbs9',
        consumer_secret => 'N1Pie5VHq8yeZQjL',
    );

    my $session = $app->model('session')->load({
        id => scalar($q->param('sesskey')),
        kind => 'CR',
        name => $Session_Name,
    });
    return $app->errtrans("Failed to verify LinkedIn user") 
        unless $session and ($session->duration() > time);

    my $access_token = $li->get_access_token(
        verifier              => $q->param('oauth_verifier'), # <--- This is passed to us in the querystring:
        request_token         => $session->get("LinkedInToken"), # <--- From step 1.
        request_token_secret  => $session->get("LinkedInSecret"), # <--- From step 1.
    );
    $session->remove();
    $session = undef;

    print STDERR "Access token: ", Dumper($access_token);
    return $app->errtrans("Failed to verify LinkedIn user") 
        unless $access_token->{token};

    # Get the user's own profile:
    my $profile_xml = $li->request(
        request_url         => 'https://api.linkedin.com/v1/people/~:(id,first-name,last-name,picture-url,public-profile-url,site-standard-profile-request)',
        access_token        => $access_token->{token},
        access_token_secret => $access_token->{secret},
    );
    my ($li_id) = $profile_xml =~ m!<id>(\w+)</id>!;
    my ($li_first_name) = $profile_xml =~ m!<first-name>(\w+)</first-name>!;
    my ($li_last_name ) = $profile_xml =~ m!<last-name>(\w+)</last-name>!;
    my ($li_picture   ) = $profile_xml =~ m!<picture-url>([^<>]*)</picture-url>!;
    my ($li_url       ) = $profile_xml =~ m!<public-profile-url>([^<>]*)</public-profile-url>!;
    print STDERR "Got user id: |$li_id|\n";
    print STDERR "Got user XML: ", Dumper($profile_xml), "\n";

    my $author_class = $app->model('author');
    my $cmntr = $author_class->load(
        {   name      => $li_id,
            type      => $author_class->COMMENTER(),
            auth_type => $auth_type,
        }
    );
    
    my $nickname = "$li_last_name $li_first_name";
    print STDERR "Got user nickname: |$nickname|\n";
    if (not $cmntr) {
        $cmntr = $app->make_commenter(
            name        => $li_id,
            nickname    => $nickname,
            auth_type   => $auth_type,
            external_id => $li_id,
#            url => "http://www.facebook.com/profile.php?id=$fb_id",
        );
    }
    
    print STDERR "Got commenter? ", ($cmntr? "YES":"NO"), "\n";
    return $app->error("Failed to created commenter")
        unless $cmntr;

    __get_userpic($cmntr, $li_picture);

    $app->make_commenter_session($cmntr) 
        or return $app->error("Failed to create a session");
    
    print STDERR "Done!\n";
    return $cmntr;
}

sub __get_userpic {
    my ($cmntr, $picture_url) = @_;
    
    return unless $picture_url;

    if ( my $userpic = $cmntr->userpic ) {
        require MT::FileMgr;
        my $fmgr  = MT::FileMgr->new('Local');
        my $mtime = $fmgr->file_mod_time( $userpic->file_path() );
        my $INTERVAL = 60 * 60 * 24 * 7;
        if ( $mtime > time - $INTERVAL ) {
            # newer than 7 days ago, don't download the userpic
            return;
        }
    }

    require MT::Auth::OpenID;

    if ( my $userpic = MT::Auth::OpenID::_asset_from_url($picture_url) ) {
        $userpic->tags('@userpic');
        $userpic->created_by( $cmntr->id );
        $userpic->save;
        if ( my $userpic = $cmntr->userpic ) {
            # Remove the old userpic thumb so the new userpic's will be generated
            # in its place.
            my $thumb_file = $cmntr->userpic_file();
            my $fmgr       = MT::FileMgr->new('Local');
            if ( $fmgr->exists($thumb_file) ) {
                $fmgr->delete($thumb_file);
            }
            $userpic->remove;
        }
        $cmntr->userpic_asset_id( $userpic->id );
        $cmntr->save;
    }
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
    my ($app, $session_key) = @_;
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
        "sesskey=$session_key",
    );

    if (my $entry_id = $q->param("entry_id")) {
        $entry_id =~ s/\D//g;
        push @params, "entry_id=$entry_id";
    }
    
    return $cgi_path . $cfg->CommentScript ."?". join('&', @params);
}

1;
