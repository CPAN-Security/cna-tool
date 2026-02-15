package CPANSec::CVE::VersionPhrase;

use v5.42;

use Exporter 'import';
our @EXPORT_OK = qw(
  phrase_from_affected_expr
  phrases_from_affected
  template_version_range_from_affected
  phrase_from_cve_version
  phrases_from_cve_versions
);

sub phrase_from_affected_expr ($expr) {
  return '' unless defined $expr && !ref($expr) && $expr =~ /\S/;
  my $s = $expr;
  $s =~ s/^\s+|\s+$//g;

  if ($s =~ /^(\S+)\s*<=\s*(\S+)$/) {
    return "from $1" if $2 eq '*';
    return "from $1 through $2";
  }
  if ($s =~ /^(\S+)\s*<\s*(\S+)$/) {
    return "from $1" if $2 eq '*';
    return "from $1 before $2";
  }
  if ($s =~ /^<=\s*(\S+)$/) {
    return "through $1";
  }
  if ($s =~ /^<\s*(\S+)$/) {
    return "before $1";
  }
  return $s;
}

sub phrases_from_affected ($affected) {
  return () unless ref($affected) eq 'ARRAY' && @$affected;
  my @phrases = map { phrase_from_affected_expr($_) } @$affected;
  return grep { length $_ } @phrases;
}

sub template_version_range_from_affected ($affected) {
  my @phrases = phrases_from_affected($affected);
  return '' unless @phrases;
  return 'versions ' . join(', ', @phrases);
}

sub phrase_from_cve_version ($v) {
  return '' unless ref($v) eq 'HASH' && (($v->{versionType} // '') eq 'custom');
  my $from = $v->{version} // '';

  if (defined $v->{lessThanOrEqual}) {
    return "from $from" if ($from && $v->{lessThanOrEqual} eq '*');
    return ($from && $from ne '0')
      ? "from $from through $v->{lessThanOrEqual}"
      : "through $v->{lessThanOrEqual}";
  }
  if (defined $v->{lessThan}) {
    return "from $from" if ($from && $v->{lessThan} eq '*');
    return ($from && $from ne '0')
      ? "from $from before $v->{lessThan}"
      : "before $v->{lessThan}";
  }

  return $from;
}

sub phrases_from_cve_versions ($versions) {
  return () unless ref($versions) eq 'ARRAY' && @$versions;
  my @phrases = map { phrase_from_cve_version($_) } @$versions;
  return grep { length $_ } @phrases;
}

1;
