use strict;
use v5.42;

use JSON::PP qw(decode_json);
use Test::More;

use lib 'lib';
use CPANSec::CVE::Announce ();

my $announce = CPANSec::CVE::Announce->new;

for my $fixture (qw(CVE-2025-40906 CVE-2025-40916 CVE-2025-40933)) {
  my $cve = _read_json("t/var/$fixture.source.json");
  my $id = $cve->{cveMetadata}{cveId};
  my $body = $announce->render_cve5_body($cve);

  is($announce->subject_line($cve), "Subject: $id: $cve->{containers}{cna}{title}", "$fixture subject line");
  like($body, qr/\A={72}\n\Q$id\E +CPAN Security Group\n={72}\n/, "$fixture body starts at the banner");
  unlike($body, qr/^Subject:/m, "$fixture body has no subject line");
  is(
    $announce->render_cve5_hash($cve),
    $announce->subject_line($cve) . "\n\n\n" . $body,
    "$fixture full announcement is subject line + body",
  );
}

eval { $announce->render_cve5_body({}) };
like($@, qr/Expected CVE JSON record with containers\.cna/, 'body rejects records without a CNA container');

done_testing();

sub _read_json ($path) {
  open(my $fh, '<:raw', $path) or die "Cannot read $path: $!";
  local $/;
  return decode_json(<$fh>);
}
