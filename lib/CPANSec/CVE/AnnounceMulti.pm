package CPANSec::CVE::AnnounceMulti;

use v5.42;
use feature qw(class);
no warnings qw(experimental::class);

use CPANSec::CVE::Announce ();
use CPANSec::CVE::BatchName qw(sort_cve_ids);
use CPANSec::CVE::VersionPhrase qw(phrase_from_cve_version phrases_from_cve_versions);
use Text::Wrap ();

class CPANSec::CVE::AnnounceMulti {
  field $announcer :param = CPANSec::CVE::Announce->new;
  field $wrap_columns :param = 72;

  # The first affected entry is the primary distribution, as in the single
  # announcement. A batch is keyed on it, so dual-life records can join.
  method primary_distribution ($cve) {
    return $cve->{containers}{cna}{affected}[0]{packageName} // '';
  }

  # A Subject line and an index of CVE IDs with their full titles, then each
  # CVE's single announcement unchanged, minus its Subject line.
  method render (@cves) {
    die "A multi-CVE announcement needs at least 2 CVEs\n" unless @cves >= 2;

    my %by_id = map { ($_->{cveMetadata}{cveId} => $_) } @cves;
    die "Duplicate CVE IDs in multi-CVE announcement\n" if keys %by_id != @cves;
    my @sorted = @by_id{ sort_cve_ids(keys %by_id) };

    my ($nameless) = grep { !length $self->primary_distribution($_) } @sorted;
    die "Cannot determine the primary distribution of $nameless->{cveMetadata}{cveId} (no affected[0].packageName)\n"
      if $nameless;

    my $distribution = $self->primary_distribution($sorted[0]);
    my @others = map { $_->{cveMetadata}{cveId} }
      grep { $self->primary_distribution($_) ne $distribution } @sorted;
    die "All CVEs must share the primary distribution $distribution; differs for @others\n" if @others;

    my $primary = $sorted[0]{containers}{cna}{affected}[0];
    my $module = $primary->{modules}[0] // $distribution;
    my $range = _shared_range(map { $_->{containers}{cna}{affected}[0]{versions} } @sorted);
    my $title = join(' ', $module, (length $range ? $range : ()), sprintf('for Perl (%d CVEs)', scalar @sorted));

    local $Text::Wrap::columns = $wrap_columns;
    my @index;
    for my $cve (@sorted) {
      push @index, '' if @index;
      push @index, $cve->{cveMetadata}{cveId}, Text::Wrap::wrap('  ', '  ', $cve->{containers}{cna}{title});
    }

    my $header = join("\n", "Subject: $title", '', '', @index, '', '') . "\n";
    return $header . join('', map { $announcer->render_cve5_body($_) } @sorted);
  }
}

# A version range covering every CVE of the batch, or '' when none can be
# stated without comparing versions: the phrase they all share (a single
# version reads "version 1.05"), else "before" or "through" their common upper
# bound when one of them starts at 0.
sub _shared_range (@versions) {
  my %phrases = map { (join(', ', phrases_from_cve_versions($_)) => 1) } @versions;
  my ($phrase) = keys %phrases;
  if (keys %phrases == 1 && length $phrase) {
    return $phrase =~ /^(?:from|before|through) |, / ? "versions $phrase" : "version $phrase";
  }

  return '' if grep { ref($_) ne 'ARRAY' || @$_ != 1 } @versions;
  my @ranges = map { $_->[0] } @versions;
  my %bounds = map {
    my $key = defined $_->{lessThan} ? 'lessThan' : 'lessThanOrEqual';
    ("$key " . ($_->{$key} // '*') => { $key => $_->{$key} });
  } @ranges;
  return '' unless keys %bounds == 1;
  my ($bound) = values %bounds;
  return '' if grep { !defined || $_ eq '*' } values %$bound;
  return '' unless grep { ($_->{version} // '') eq '0' } @ranges;
  return 'versions ' . phrase_from_cve_version({ versionType => 'custom', version => '0', %$bound });
}

1;
