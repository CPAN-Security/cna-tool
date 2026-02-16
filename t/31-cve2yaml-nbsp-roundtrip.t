use strict;
use v5.42;

use File::Temp qw(tempdir);
use JSON::PP qw(decode_json encode_json);
use Test::More;

use lib 'lib';
use CPANSec::CVE::CVE2YAML ();

my $tmp = tempdir(CLEANUP => 1);
my $json_path = "$tmp/CVE-1900-9996.json";

my $source_json = do {
  open(my $fh, '<', 't/var/CVE-2025-40906.source.json') or die "Cannot read fixture: $!";
  local $/;
  my $text = <$fh>;
  close($fh);
  decode_json($text);
};

$source_json->{cveMetadata}{cveId} = 'CVE-1900-9996';
$source_json->{containers}{cna}{descriptions}[0]{value}
  = "A heap overflow\x{A0}in this function can happen.";
$source_json->{containers}{cna}{title}
  = "Example\x{A0}title";

open(my $out, '>', $json_path) or die "Cannot write test json: $!";
print {$out} encode_json($source_json);
close($out);

my $conv = CPANSec::CVE::CVE2YAML->new;
my $yaml = eval { $conv->convert_json_file_to_yaml($json_path, guard => 1) };
my $err = $@ // '';

ok(!$err, 'guard passes for JSON containing non-breaking spaces');
like($yaml, qr/A heap overflow in this function can happen\./, 'description normalizes NBSP to space');
like($yaml, qr/Example title/, 'title normalizes NBSP to space');
unlike($yaml, qr/\\_in/, 'YAML does not emit backslash-underscore escape for NBSP');

done_testing();
