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
}

1;
