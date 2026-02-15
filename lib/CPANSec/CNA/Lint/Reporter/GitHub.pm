package CPANSec::CNA::Lint::Reporter::GitHub;

use v5.42;
use feature qw(class);
no warnings qw(experimental::class);

class CPANSec::CNA::Lint::Reporter::GitHub {
  method render ($findings_by_file) {
    my @out;
    for my $path (sort keys %$findings_by_file) {
      my $list = $findings_by_file->{$path} // [];
      for my $f (@$list) {
        my $lvl = ($f->{severity} // 'warning') eq 'error' ? 'error' : 'warning';
        my $line = $f->{line} // 1;
        my $msg = $f->{message} // '';
        my $id = $f->{id} // 'unknown';
        $msg =~ s/%/%25/g;
        $msg =~ s/\r/%0D/g;
        $msg =~ s/\n/%0A/g;
        push @out, sprintf('::%s file=%s,line=%d,title=%s::%s', $lvl, $path, $line, $id, $msg);
      }
    }
    return join("\n", @out);
  }
}

1;
