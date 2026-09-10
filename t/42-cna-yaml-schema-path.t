use strict;
use v5.42;

use Cwd qw(abs_path);
use File::Path qw(make_path);
use File::Spec ();
use File::Temp qw(tempdir);
use Test::More;

use lib 'lib';
use CPANSec::CVE::YAML2CVE ();

# The command needs no data repo, so the ambient root must not get in the way.
delete $ENV{CPANSEC_CNA_ROOT};

my $bundled = abs_path('schema/cpansec-cna-schema-01.yaml');

is(CPANSec::CVE::YAML2CVE::bundled_schema_path(), $bundled, 'bundled_schema_path names the checkout copy');

my $out = qx(scripts/cna yaml-schema-path 2>&1);
is($? >> 8, 0, 'yaml-schema-path succeeds');
is($out, "$bundled\n", 'prints the bundled schema path on one line');

# A data repo carrying its own diverging copy must not change the answer: the
# point of the command is to find out what the tool bundles.
my $root = tempdir(CLEANUP => 1);
make_path("$root/schema");
open(my $fh, '>', "$root/schema/cpansec-cna-schema-01.yaml") or die $!;
print {$fh} "type: object\n";
close($fh);

my $from_root = qx(scripts/cna --cpansec-cna-root '$root' yaml-schema-path 2>&1);
is($? >> 8, 0, 'yaml-schema-path succeeds under --cpansec-cna-root');
is($from_root, "$bundled\n", 'still reports the bundled copy, not the data repo copy');
ok(File::Spec->file_name_is_absolute((split /\n/, $from_root)[0]), 'path is absolute');

done_testing();
