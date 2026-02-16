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
    my ($from, $to) = ($1, $2);
    return '' if _is_zero_start($from) && $to eq '*';
    return "from $from" if $to eq '*';
    return _is_zero_start($from) ? "through $to" : "from $from through $to";
  }
  if ($s =~ /^(\S+)\s*<\s*(\S+)$/) {
    my ($from, $to) = ($1, $2);
    return '' if _is_zero_start($from) && $to eq '*';
    return "from $from" if $to eq '*';
    return _is_zero_start($from) ? "before $to" : "from $from before $to";
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
    return '' if ($from && _is_zero_start($from) && $v->{lessThanOrEqual} eq '*');
    return "from $from" if ($from && $v->{lessThanOrEqual} eq '*');
    return ($from && !_is_zero_start($from))
      ? "from $from through $v->{lessThanOrEqual}"
      : "through $v->{lessThanOrEqual}";
  }
  if (defined $v->{lessThan}) {
    return '' if ($from && _is_zero_start($from) && $v->{lessThan} eq '*');
    return "from $from" if ($from && $v->{lessThan} eq '*');
    return ($from && !_is_zero_start($from))
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

sub _is_zero_start ($v) {
  return defined($v) && $v eq '0' ? 1 : 0;
}

1;
