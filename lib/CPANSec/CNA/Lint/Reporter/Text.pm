package CPANSec::CNA::Lint::Reporter::Text;

use v5.42;
use feature qw(class);
no warnings qw(experimental::class);

class CPANSec::CNA::Lint::Reporter::Text {
  method render ($findings_by_file) {
    my @out;
    for my $path (sort keys %$findings_by_file) {
      my $list = $findings_by_file->{$path} // [];
      next unless @$list;
      push @out, "$path:";
      for my $f (@$list) {
        push @out, sprintf(
          '  [%s] %s (line %d, %s)',
          uc($f->{severity} // 'warning'),
          $f->{message} // '',
          $f->{line} // 1,
          $f->{id} // 'unknown',
        );
      }
      push @out, '';
    }

    return @out ? join("\n", @out) : "No lint findings.";
  }
}

1;
