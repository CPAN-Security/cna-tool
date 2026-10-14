use strict;
use v5.42;

use Storable qw(dclone);
use Test::More;

use lib 'lib';
use CPANSec::CVE::Announce ();
use CPANSec::CVE::AnnounceMulti ();
use CPANSec::CVE::YAML2CVE ();

my $converter = CPANSec::CVE::YAML2CVE->new;
my $announce = CPANSec::CVE::Announce->new;
my $multi = CPANSec::CVE::AnnounceMulti->new;

my $first = _record('t/var/CVE-2025-40916.yaml', 'CVE-1900-9901');
my $second = _record('t/var/CVE-2025-40916.yaml', 'CVE-1900-9902');

subtest 'header, index and unchanged bodies' => sub {
  my $header = <<'EOT';
Subject: Mojolicious-Plugin-CaptchaPNG for Perl: 2 CVEs


Mojolicious-Plugin-CaptchaPNG for Perl: 2 CVEs

CVE-1900-9901
  Mojolicious::Plugin::CaptchaPNG version 1.05 for Perl uses a weak
  random number source for generating the captcha text

CVE-1900-9902
  Mojolicious::Plugin::CaptchaPNG version 1.05 for Perl uses a weak
  random number source for generating the captcha text


EOT
  is(
    $multi->render($second, $first),
    $header . $announce->render_cve5_body($first) . $announce->render_cve5_body($second),
    'sorted by CVE ID regardless of argument order; bodies are the single announcements',
  );
};

subtest 'primary distribution' => sub {
  is($multi->primary_distribution($first), 'Mojolicious-Plugin-CaptchaPNG', 'single-distribution record');
  is($multi->primary_distribution(_record('t/var/CVE-1900-9997.yaml', 'CVE-1900-9997')),
    'Encode', 'dual-life record: the first affected entry');
};

subtest 'dual-life records batch on their primary distribution' => sub {
  my $text = $multi->render(
    _record('t/var/CVE-1900-9997.yaml', 'CVE-1900-9997'),
    _record('t/var/CVE-1900-9989.yaml', 'CVE-1900-9989'),
  );
  like($text, qr/\ASubject: Encode for Perl: 2 CVEs\n/, 'titled by the primary distribution');
  like($text, qr/^\s*Distribution:\s+perl$/m, 'the perl core block of the dual-life record is kept');
};

subtest 'rejections' => sub {
  eval { $multi->render($first) };
  like($@, qr/at least 2 CVEs/, 'a single CVE');
  eval { $multi->render($first, dclone($first)) };
  like($@, qr/Duplicate CVE IDs/, 'the same CVE twice');
  eval { $multi->render($first, _record('t/var/CVE-2025-40906.yaml', 'CVE-1900-9903')) };
  like($@, qr/share the primary distribution Mojolicious-Plugin-CaptchaPNG; differs for CVE-1900-9903/,
    'different primary distributions');
  my $nameless = dclone($first);
  delete $nameless->{containers}{cna}{affected}[0]{packageName};
  eval { $multi->render($nameless, $second) };
  like($@, qr/Cannot determine the primary distribution of CVE-1900-9901/, 'no primary distribution');
};

done_testing();

sub _record ($path, $id) {
  my $record = dclone($converter->convert_yaml_file($path));
  $record->{cveMetadata}{cveId} = $id;
  return $record;
}
