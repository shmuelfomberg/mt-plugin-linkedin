package LinkedIn;
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

1;