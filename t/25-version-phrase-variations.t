use strict;
use v5.42;

use Test::More;

use lib 'lib';
use CPANSec::CVE::VersionPhrase qw(
  phrase_from_affected_expr
  phrases_from_affected
  template_version_range_from_affected
  phrase_from_cve_version
  phrases_from_cve_versions
);

is(phrase_from_affected_expr('<= 1.5'), 'through 1.5', 'upper-bound <= becomes through');
is(phrase_from_affected_expr('< 1.5'), 'before 1.5', 'upper-bound < becomes before');
is(phrase_from_affected_expr('1.2 <= 1.3'), 'from 1.2 through 1.3', 'closed range <= phrasing');
is(phrase_from_affected_expr('1.2 < 1.3'), 'from 1.2 before 1.3', 'open range < phrasing');
is(phrase_from_affected_expr('0 <= 1.3'), 'through 1.3', 'zero-start <= range maps to through phrasing');
is(phrase_from_affected_expr('0 < 1.3'), 'before 1.3', 'zero-start < range maps to before phrasing');
is(phrase_from_affected_expr('0.0.0 < 1.3'), 'from 0.0.0 before 1.3', 'only literal zero is treated as open start');
is(phrase_from_affected_expr('1.5 < *'), 'from 1.5', 'open-ended < * phrasing');
is(phrase_from_affected_expr('1.5 <= *'), 'from 1.5', 'open-ended <= * phrasing');
is(phrase_from_affected_expr('0 < *'), '', 'zero-start open-ended range is omitted');
is(phrase_from_affected_expr('1.5'), '1.5', 'exact version phrasing');

is_deeply(
  [ phrases_from_affected(['<= 1.5', '1.2 <= 1.3', '1.5 < *']) ],
  [ 'through 1.5', 'from 1.2 through 1.3', 'from 1.5' ],
  'affected list produces ordered phrase list',
);

is(
  template_version_range_from_affected(['<= 1.5', '1.2 <= 1.3', '1.5 < *']),
  'versions through 1.5, from 1.2 through 1.3, from 1.5',
  'template range phrase joins multiple ranges',
);

is(
  phrase_from_cve_version({
    versionType => 'custom',
    status => 'affected',
    version => '0',
    lessThanOrEqual => '1.5',
  }),
  'through 1.5',
  'CVE version object upper-bound through phrasing',
);

is(
  phrase_from_cve_version({
    versionType => 'custom',
    status => 'affected',
    version => '0.0.0',
    lessThan => '1.5',
  }),
  'from 0.0.0 before 1.5',
  'CVE version object treats only literal zero as open start',
);

is_deeply(
  [ phrases_from_cve_versions([
    {
      versionType => 'custom',
      status => 'affected',
      version => '0',
      lessThanOrEqual => '1.5',
    },
    {
      versionType => 'custom',
      status => 'affected',
      version => '1.2',
      lessThanOrEqual => '1.3',
    },
    {
      versionType => 'custom',
      status => 'affected',
      version => '1.5',
      lessThan => '*',
    },
  ]) ],
  [ 'through 1.5', 'from 1.2 through 1.3', 'from 1.5' ],
  'CVE versions list phrases are consistent',
);

done_testing();
