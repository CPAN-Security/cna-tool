use strict;
use v5.42;

use File::Copy qw(copy);
use File::Temp qw(tempdir);
use Test::More;

use lib 'lib';
use CPANSec::CVE::CVE2YAML ();

my $conv = CPANSec::CVE::CVE2YAML->new;
my $yaml = $conv->convert_json_file_to_yaml('t/var/CVE-2025-40916.source.json', guard => 1);

like($yaml, qr/^cpansec:\n/m, 'converter outputs cpansec yaml document');
like($yaml, qr/^\s+cve:\s+CVE-2025-40916\s*$/m, 'converter preserves cve id');

my $tmpdir = tempdir(CLEANUP => 1);
my $json_in = "$tmpdir/CVE-2025-40916.json";
copy('t/var/CVE-2025-40916.source.json', $json_in) or die "copy failed: $!";

my $out = qx(scripts/cna --cpansec-cna-root '$tmpdir' import $json_in --force 2>&1);
my $rc = $? >> 8;

is($rc, 0, 'cna import succeeds');
like($out, qr/Round-trip guard: enabled/, 'import reports guard status');
ok(-f "$tmpdir/CVE-2025-40916.yaml", 'import writes YAML next to source JSON');

done_testing();
