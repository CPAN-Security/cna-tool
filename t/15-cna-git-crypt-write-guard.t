use strict;
use v5.42;

use File::Copy qw(copy);
use File::Path qw(make_path);
use File::Temp qw(tempdir);
use Test::More;

my $branch = _current_branch();
if (defined $branch && $branch eq 'main') {
  plan skip_all => "encrypted CVE operations are disallowed on main";
}

my $source_cve = 'CVE-2025-40906';
my $cve = 'CVE-1900-9915';
my $fixture_yaml = "t/var/$source_cve.yaml";
my $root = tempdir(CLEANUP => 1);
my $enc = "$root/encrypted";
make_path($enc);
my $yaml = "$enc/$cve.yaml";
my $json = "$enc/$cve.json";

ok(-f $fixture_yaml, 'fixture yaml exists in t/var');
copy($fixture_yaml, $yaml) or die "Cannot copy $fixture_yaml -> $yaml: $!";
_rewrite_cve_in_yaml($yaml, $cve);

my $out_locked = qx(CPANSEC_CNA_GIT_CRYPT_SHIM=locked scripts/cna --cpansec-cna-root '$root' build $cve 2>&1);
my $rc_locked = $? >> 8;
is($rc_locked, 2, 'build fails when git-crypt shim reports locked');
like($out_locked, qr/Refusing encrypted write: git-crypt appears locked/i, 'locked refusal is explicit');

my $out_unprotected = qx(CPANSEC_CNA_GIT_CRYPT_SHIM=unprotected scripts/cna --cpansec-cna-root '$root' build $cve 2>&1);
my $rc_unprotected = $? >> 8;
is($rc_unprotected, 2, 'build fails when git-crypt shim reports unprotected');
like($out_unprotected, qr/not protected by attributes/i, 'unprotected refusal is explicit');

my $out_ok = qx(CPANSEC_CNA_GIT_CRYPT_SHIM=ok scripts/cna --cpansec-cna-root '$root' build $cve --force 2>&1);
my $rc_ok = $? >> 8;
is($rc_ok, 0, 'build succeeds when git-crypt shim reports ok');
like($out_ok, qr/^Wrote \Q$json\E/m, 'build writes encrypted json with ok shim');
ok(-f $json, 'encrypted json was written');

done_testing();

sub _rewrite_cve_in_yaml ($path, $cve) {
  open(my $fh, '<', $path) or die "Cannot read $path: $!";
  local $/;
  my $content = <$fh>;
  close($fh);
  $content =~ s/^  cve:\s+\S+/  cve: $cve/m
    or die "Cannot rewrite cve in $path";
  open(my $wh, '>', $path) or die "Cannot write $path: $!";
  print {$wh} $content;
  close($wh);
}

sub _current_branch () {
  my $b = qx(git branch --show-current 2>/dev/null);
  chomp $b;
  return length($b) ? $b : undef;
}
