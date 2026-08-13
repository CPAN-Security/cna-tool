package CPANSec::CNA;

use v5.42;

our $VERSION = '0.1';

# Records name the tool that produced them. Derived from $VERSION rather than
# written out, so bumping the version is enough to change what records say.
sub generator () {
  return "cpansec-cna-tool $VERSION";
}

1;
