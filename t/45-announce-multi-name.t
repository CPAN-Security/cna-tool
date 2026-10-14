use strict;
use v5.42;

use Test::More;

use lib 'lib';
use CPANSec::CVE::BatchName qw(sort_cve_ids batch_filename parse_batch_filename);

subtest 'sort_cve_ids' => sub {
  is_deeply(
    [sort_cve_ids(qw(CVE-2026-10001 CVE-2025-40906 CVE-2026-9999 CVE-2026-0042))],
    [qw(CVE-2025-40906 CVE-2026-0042 CVE-2026-9999 CVE-2026-10001)],
    'by year, then numerically by sequence number',
  );
  is_deeply(
    [sort_cve_ids(qw(CVE-2026-1234567890123456789 CVE-2026-1234567890123456788))],
    [qw(CVE-2026-1234567890123456788 CVE-2026-1234567890123456789)],
    '19-digit sequence numbers sort numerically',
  );
  eval { sort_cve_ids('CVE-26-1') };
  like($@, qr/Invalid CVE ID 'CVE-26-1'/, 'rejects malformed IDs');
};

subtest 'batch_filename' => sub {
  is(batch_filename('Foo-Bar', qw(CVE-2026-1003 CVE-2026-1001 CVE-2026-1002)),
    'Foo-Bar--CVE-2026-1001+1002+1003.txt', 'one year, sorted, year written once');
  is(batch_filename('Foo-Bar', qw(CVE-2026-1002 CVE-2025-40906 CVE-2026-1001)),
    'Foo-Bar--CVE-2025-40906+CVE-2026-1001+1002.txt', 'year written again when it changes');
  is(batch_filename('Foo-Bar', qw(CVE-2026-1001 CVE-2026-0042)),
    'Foo-Bar--CVE-2026-0042+1001.txt', 'leading zeros kept verbatim');
};

subtest 'parse_batch_filename' => sub {
  is_deeply(
    [parse_batch_filename('Foo-Bar--CVE-2025-40906+CVE-2026-1001+1002.txt')],
    ['Foo-Bar', qw(CVE-2025-40906 CVE-2026-1001 CVE-2026-1002)],
    'bare numbers take the year of the nearest full ID before them',
  );
  for my $name (
    'Foo-Bar--CVE-2026-1001+1002+1003.txt',
    'Foo-Bar--CVE-2025-40906+CVE-2026-1001+1002.txt',
    'Foo-Bar--CVE-2026-0042+1001.txt',
  ) {
    my ($dist, @ids) = parse_batch_filename($name);
    is(batch_filename($dist, @ids), $name, "$name round-trips");
  }
  for my $bad (
    'Foo-Bar.txt',
    'Foo-Bar--1001+1002.txt',
    'Foo-Bar--CVE-2026-1001+.txt',
    'Foo-Bar--CVE-2026-1001+12.txt',
    'Foo-Bar--CVE-2026-1001+1002.yaml',
    '--CVE-2026-1001+1002.txt',
  ) {
    is_deeply([parse_batch_filename($bad)], [], "$bad does not parse");
  }
};

done_testing();
