package CPANSec::CVE;

use v5.42;
use feature qw(class);
no warnings qw(experimental::class);

use CPANSec::CVE::Announce ();
use CPANSec::CVE::Model ();
use CPANSec::CVE::YAML2CVE ();

class CPANSec::CVE {
  field $model :param;
  field $converter :param = CPANSec::CVE::YAML2CVE->new;
  field $announcer :param = CPANSec::CVE::Announce->new;

  ADJUST {
    die "model must be CPANSec::CVE::Model\n" unless eval { $model->isa('CPANSec::CVE::Model') };
  }

  method model () {
    return $model;
  }

  method converter () {
    return $converter;
  }

  method announcer () {
    return $announcer;
  }

  method cve_id () {
    return $model->cve_id;
  }

  method validate () {
    # Reuse CVE schema validation on a canonical projection.
    $converter->convert_model($model, cna_only => 1);
    return;
  }

  method to_cve5_hash () {
    return $converter->convert_model($model, cna_only => 0);
  }

  method to_cve5_json () {
    return $converter->encode_json($self->to_cve5_hash);
  }

  method to_cna_container_hash () {
    return $converter->convert_model($model, cna_only => 1);
  }

  method to_cna_container_json () {
    return $converter->encode_json($self->to_cna_container_hash);
  }

  method to_announce_text () {
    return $announcer->render_cve5_hash($self->to_cve5_hash);
  }
}

sub from_yaml_file ($class, $infile, %opts) {
  my $converter = CPANSec::CVE::YAML2CVE->new(%opts);
  my $model = $converter->load_yaml_model($infile);
  return $class->new(model => $model, converter => $converter);
}

sub from_model ($class, $model, %opts) {
  my $converter = CPANSec::CVE::YAML2CVE->new(%opts);
  return $class->new(model => $model, converter => $converter);
}

1;
