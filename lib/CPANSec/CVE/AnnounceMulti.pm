package CPANSec::CVE::AnnounceMulti;

use v5.42;
use feature qw(class);
no warnings qw(experimental::class);

use CPANSec::CVE::Announce ();
use CPANSec::CVE::BatchName qw(sort_cve_ids);
use Text::Wrap ();

class CPANSec::CVE::AnnounceMulti {
  field $announcer :param = CPANSec::CVE::Announce->new;
  field $wrap_columns :param = 72;

  # The first affected entry is the primary distribution, as in the single
  # announcement. A batch is keyed on it, so dual-life records can join.
  method primary_distribution ($cve) {
    return $cve->{containers}{cna}{affected}[0]{packageName} // '';
  }

  # A short header (title plus an index of CVE IDs and their full titles),
  # then each CVE's single announcement unchanged, minus its Subject line.
  method render (@cves) {
    die "A multi-CVE announcement needs at least 2 CVEs\n" unless @cves >= 2;

    my %by_id = map { ($_->{cveMetadata}{cveId} => $_) } @cves;
    die "Duplicate CVE IDs in multi-CVE announcement\n" if keys %by_id != @cves;
    my @sorted = @by_id{ sort_cve_ids(keys %by_id) };

    my $distribution = $self->primary_distribution($sorted[0]);
    my @others = map { $_->{cveMetadata}{cveId} }
      grep { $self->primary_distribution($_) ne $distribution } @sorted;
    die "All CVEs must share the primary distribution $distribution; differs for @others\n" if @others;

    my $title = sprintf('%s for Perl: %d CVEs', $distribution, scalar @sorted);

    local $Text::Wrap::columns = $wrap_columns;
    my @index;
    for my $cve (@sorted) {
      push @index, '' if @index;
      push @index, $cve->{cveMetadata}{cveId}, Text::Wrap::wrap('  ', '  ', $cve->{containers}{cna}{title});
    }

    my $header = join("\n", "Subject: $title", '', '', $title, '', @index, '', '') . "\n";
    return $header . join('', map { $announcer->render_cve5_body($_) } @sorted);
  }
}

1;
