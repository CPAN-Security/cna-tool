use strict;
use v5.42;

use File::Temp qw(tempdir);
use JSON::PP qw(decode_json encode_json);
use Test::More;

use lib 'lib';
use CPANSec::CVE::CVE2YAML ();

my $tmp = tempdir(CLEANUP => 1);
my $json_path = "$tmp/CVE-1900-9997.json";

my $source_json = do {
  open(my $fh, '<', 't/var/CVE-2025-40906.source.json') or die "Cannot read fixture: $!";
  local $/;
  my $text = <$fh>;
  close($fh);
  decode_json($text);
};

$source_json->{cveMetadata}{cveId} = 'CVE-1900-9997';
$source_json->{containers}{cna}{affected}[0]{versions}[0]{versionType} = 'semver';

open(my $out, '>', $json_path) or die "Cannot write test json: $!";
print {$out} encode_json($source_json);
close($out);

my $conv = CPANSec::CVE::CVE2YAML->new;
my $ok = eval { $conv->convert_json_file_to_yaml($json_path, guard => 1); 1 };
my $err = $@ // '';

ok(!$ok, 'guard fails when source projection cannot round-trip exactly');
like($err, qr/source\/rebuilt projections differ/, 'error explains guard mismatch');
like($err, qr/Projection diff \(source vs rebuilt\):/, 'error includes projection diff heading');
like($err, qr/affected\[0\]\.versionType/, 'error includes differing field path');

done_testing();
