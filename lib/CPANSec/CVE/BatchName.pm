package CPANSec::CVE::BatchName;

use v5.42;

use Exporter 'import';
our @EXPORT_OK = qw(sort_cve_ids batch_filename parse_batch_filename);

my $CVE_ID = qr/CVE-(\d{4})-(\d{4,19})/;

# Numeric by year, then by sequence number. A sequence number can be longer
# than a double holds exactly, so it is compared as a digit string with
# leading zeros stripped: shorter is smaller, equal lengths compare lexically.
sub sort_cve_ids (@ids) {
  return map { $_->[0] }
    sort { $a->[1] <=> $b->[1] || length($a->[2]) <=> length($b->[2]) || $a->[2] cmp $b->[2] }
    map {
      my ($year, $number) = /^$CVE_ID\z/ or die "Invalid CVE ID '$_'\n";
      [$_, $year, $number =~ s/^0+(?=\d)//r]
    } @ids;
}

# Every ID appears, sorted and joined with '+'. The year is written out for
# the first ID of each year; later IDs of that year are just the number.
sub batch_filename ($distribution, @ids) {
  my $year = '';
  my @parts;
  for my $id (sort_cve_ids(@ids)) {
    my ($y, $number) = $id =~ /^$CVE_ID\z/;
    push @parts, $y eq $year ? $number : $id;
    $year = $y;
  }
  return "$distribution--" . join('+', @parts) . '.txt';
}

# Inverse of batch_filename: a bare number takes the year of the nearest full
# ID before it. Returns an empty list when the name does not parse.
sub parse_batch_filename ($name) {
  my ($distribution, $list) = $name =~ m{^([^/]+?)--(CVE-[^/]+)\.txt\z} or return;
  my ($year, @ids);
  for my $part (split /\+/, $list, -1) {
    if ($part =~ /^$CVE_ID\z/) {
      $year = $1;
      push @ids, $part;
      next;
    }
    return unless defined $year && $part =~ /^\d{4,19}\z/;
    push @ids, "CVE-$year-$part";
  }
  return ($distribution, @ids);
}

1;
