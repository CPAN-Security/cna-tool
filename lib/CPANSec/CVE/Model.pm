package CPANSec::CVE::Model;

use v5.42;
use feature qw(class);
no warnings qw(experimental::class);

class CPANSec::CVE::Model {
  field $cpansec :param;
  field $source_file :param = undef;

  ADJUST {
    die "cpansec model data must be a hash\n" unless ref($cpansec) eq 'HASH';
  }

  method cpansec () {
    return $cpansec;
  }

  method source_file () {
    return $source_file;
  }

  method cve_id () {
    return $cpansec->{cve};
  }

  # Normalized view of the affected distributions, so callers never have to care
  # which spelling the YAML used. Entries carry: distribution, versions, and
  # optionally author, repo, files, routines.
  method distributions () {
    my $affected = $cpansec->{affected};
    die "cpansec.affected must be a non-empty array\n"
      unless ref($affected) eq 'ARRAY' && @$affected;

    my $objects = grep { ref($_) eq 'HASH' } @$affected;
    die "cpansec.affected must not mix version-range strings with distribution objects\n"
      if $objects && $objects != @$affected;

    unless ($objects) {
      die "cpansec.distribution is required when cpansec.affected lists version ranges\n"
        unless defined $cpansec->{distribution} && length $cpansec->{distribution};
      return [ _entry($cpansec, $cpansec->{distribution}, $affected) ];
    }

    die "cpansec.distribution must not be set when cpansec.affected lists distributions\n"
      if defined $cpansec->{distribution};

    return [ map { _entry({ %$cpansec, %$_ }, $_->{distribution}, $_->{versions}) } @$affected ];
  }
}

# Record-level author/repo/files/routines act as defaults for every entry, so a
# multi-distribution record only repeats what actually differs.
sub _entry ($src, $distribution, $versions) {
  return {
    distribution => $distribution,
    versions     => $versions,
    map { defined $src->{$_} ? ($_ => $src->{$_}) : () } qw(author repo files routines),
  };
}

1;
