package CPANSec::CVE::Announce;

use v5.42;
use feature qw(class);
no warnings qw(experimental::class);

use JSON::PP qw(decode_json);
use CPANSec::CVE::VersionPhrase qw(phrases_from_cve_versions);
use Text::Wrap ();

class CPANSec::CVE::Announce {
  field $wrap_columns :param = 72;

  method render_cve5_file ($path) {
    open(my $fh, '<', $path) or die $!;
    local $/;
    my $cve = decode_json(<$fh>);
    close($fh);
    return $self->render_cve5_hash($cve);
  }

  method render_cve5_hash ($cve) {
    my $cna = $cve->{containers}->{cna};
    die "Expected CVE JSON record with containers.cna\n" unless ref($cna) eq 'HASH';

    local $Text::Wrap::columns = $wrap_columns;

    my $aff0 = $cna->{affected}->[0] // {};
    my $printed_version_header;

    my @lines = (
      "Subject: $cve->{cveMetadata}->{cveId}: $cna->{title}",
      "",
      "",
      _header([$cve->{cveMetadata}->{cveId}, "CPAN Security Group"], "="),
      "",
      _dt("CVE ID", $cve->{cveMetadata}->{cveId}),
      _dt("Distribution", $aff0->{packageName}),
      (map { _dt($printed_version_header++ ? "" : "Versions", $_) } phrases_from_cve_versions($aff0->{versions})),
      "",
      _dt("MetaCPAN", "https://metacpan.org/dist/" . ($aff0->{packageName} // '')),
      ($aff0->{repo} ? _dt("VCS Repo", $aff0->{repo}) : ()),
      "",
      "",
      Text::Wrap::wrap('', '', $cna->{title}),
      "",
      _header("Description"),
      _wrap_description(_descriptions_text($cna)),
      "",
      ($cna->{problemTypes} ? _section(
        "Problem types", map { Text::Wrap::wrap('- ', '  ', $_->{descriptions}->[0]->{description}) } $cna->{problemTypes}->@*
      ) : ()),
      ($cna->{impacts} ? _section(
        "Impacts", map { Text::Wrap::wrap('- ', '  ', $_->{descriptions}->[0]->{description}) } $cna->{impacts}->@*
      ) : ()),
      ($cna->{workarounds} ? _section(
        "Workarounds", map { Text::Wrap::wrap('', '', $_->{value}) . ("\n") x !!$cna->{workarounds}->@* } $cna->{workarounds}->@*
      ) : ()),
      ($cna->{solutions} ? _section(
        "Solutions", map { Text::Wrap::wrap('', '', $_->{value}) . ("\n") x !!$cna->{solutions}->@* } $cna->{solutions}->@*
      ) : ()),
      ($cna->{references} ? _section(
        "References", map { "$_->{url}" } $cna->{references}->@*
      ) : ()),
      ($cna->{timeline} ? _section(
        "Timeline", map { Text::Wrap::wrap('- ', '  ', _timeline_entry($_)) } $cna->{timeline}->@*
      ) : ()),
      ($cna->{credits} ? _section(
        "Credits", map { "$_->{value}, $_->{type}" } $cna->{credits}->@*
      ) : ()),
      "",
      "",
    );

    return join("\n", @lines);
  }
}

sub _header ($t, $l = "-") {
  return ref($t) eq 'ARRAY'
    ? (($l x 72), sprintf("%-24s %47s", $t->@*), ($l x 72))
    : ($t, ($l x length($t)));
}

sub _dt ($k, $v) {
  $v //= '';
  return sprintf("%15s  %s", ($k ? "$k:" : ""), $v);
}

sub _section ($t, @items) {
  return @items && $items[0] ? (_header($t), @items, "") : ();
}

sub _descriptions_text ($j) {
  my @ret = map { $_->{value} || $_->{description} } grep { $_->{lang} eq 'en' } $j->{descriptions}->@*;
  s/[\N{NBSP}]/ /g foreach @ret;
  return join("\n\n", grep { defined $_ && length $_ } @ret);
}

sub _wrap_description ($text) {
  return () unless defined $text && length $text;

  my @chunks = split /\n{2,}/, $text;
  my @out;
  for my $chunk (@chunks) {
    next unless defined $chunk;
    if ($chunk =~ /^\s/m) {
      push @out, split(/\n/, $chunk);
    } else {
      my $para = $chunk;
      $para =~ s/\n/ /g;
      push @out, Text::Wrap::wrap('', '', $para);
    }
    push @out, '';
  }
  pop @out if @out && $out[-1] eq '';
  return @out;
}

sub _timeline_entry ($entry) {
  my $time = $entry->{time} // '';
  my ($date) = $time =~ /^(\d{4}-\d{2}-\d{2})/;
  $date //= $time;
  return "$date: " . ($entry->{value} // '');
}

1;
