package CPANSec::CNA::App;

use v5.42;
use feature qw(class);
no warnings qw(experimental::class);

use CPANSec::CNA::Lint ();
use CPANSec::CNA::Lint::Reporter::GitHub ();
use CPANSec::CNA::Lint::Reporter::Text ();
use CPANSec::CVE ();
use CPANSec::CVE::Announce ();
use CPANSec::CVE::CVE2YAML ();
use CPANSec::CVE::YAML2CVE ();
use File::Basename qw(dirname basename);
use File::Path qw(make_path);
use File::Spec ();
use File::Temp qw(tempfile);
use HTTP::Tiny ();
use JSON::PP qw(decode_json);
use Storable qw(dclone);

class CPANSec::CNA::App {
  field $lint :param = CPANSec::CNA::Lint->new;
  field $root_dir :reader = '.';
  field $encrypted_context = 0;
  field $encrypted_notice_shown = 0;

  method run (@argv) {
    @argv = $self->_extract_global_options(@argv);

    my $cmd = shift(@argv) // '';
    return $self->_usage(0) if $cmd eq '' || $cmd eq 'help' || $cmd eq '--help';

    if ($cmd eq 'init') {
      return $self->_cmd_init(@argv);
    }
    if ($cmd eq 'check') {
      return $self->_cmd_check(@argv);
    }
    if ($cmd eq 'build') {
      return $self->_cmd_build(@argv);
    }
    if ($cmd eq 'emit') {
      return $self->_cmd_emit(@argv);
    }
    if ($cmd eq 'announce') {
      return $self->_cmd_announce(@argv);
    }
    if ($cmd eq 'import') {
      return $self->_cmd_import(@argv);
    }
    if ($cmd eq 'reconcile') {
      return $self->_cmd_reconcile(@argv);
    }

    die "Unknown command '$cmd'.\n" . $self->_usage_text;
  }

  method _usage ($exit) {
    print $self->_usage_text;
    return $exit;
  }

  method _usage_text () {
    return <<'USAGE';
Usage: cna [--cpansec-cna-root PATH] <command> [options]

Commands:
  init [--force] [--encrypted] <CVE-ID> <Module::Name>
                                    Create/initialize cves/<CVE-ID>.yaml (or encrypted/)
  check [CVE-ID] [--changed] [--format text|github] [--strict]
                                    Validate YAML + lint findings (and JSON drift if present)
  build [CVE-ID] [--strict] [--force]
                                    Validate/lint and write <CVE-ID>.json next to source YAML
  emit [CVE-ID] [--strict] [--cna-container-only]
                                    Validate/lint and print generated JSON to stdout
  announce [CVE-ID] [--write|--output path] [--force]
                                    Render announcement text to stdout or file
  import <CVE-ID|path.json> [--force] [--no-guard]
                                    Convert CVE JSON to YAML macro with round-trip guard
  reconcile [CVE-ID] [--api-base URL]
                                    Compare local CNA container with published CVE JSON

Global options:
  --cpansec-cna-root PATH           Path to CVE data repository root
                                    (default: CPANSEC_CNA_ROOT or current directory)
USAGE
  }

  method _extract_global_options (@argv) {
    my @rest;
    my $root = $ENV{CPANSEC_CNA_ROOT};
    my $saw_cmd = 0;

    while (@argv) {
      my $a = shift @argv;

      if (!$saw_cmd && $a =~ /^--cpansec-cna-root=(.+)$/) {
        $root = $1;
        next;
      }
      if (!$saw_cmd && $a eq '--cpansec-cna-root') {
        $root = shift(@argv) // die "--cpansec-cna-root requires value\n";
        next;
      }
      $saw_cmd = 1 if !@rest;
      push @rest, $a;
    }

    $self->_apply_root($root) if defined $root && length $root;
    return @rest;
  }

  method _apply_root ($root) {
    die "CPANSec CNA root is not a directory: $root\n" unless -d $root;
    chdir $root or die "Cannot chdir to CPANSec CNA root $root: $!\n";
    $root_dir = $root;
  }

  method _cmd_init (@args) {
    my %opt = (force => 0, encrypted => 0);
    my @positionals;

    while (@args) {
      my $a = shift @args;
      if ($a eq '--force') { $opt{force} = 1; next; }
      if ($a eq '--encrypted') { $opt{encrypted} = 1; next; }
      push @positionals, $a;
    }

    my ($cve, $module) = @positionals;
    die "Usage: cna init [--force] [--encrypted] <CVE-ID> <Module::Name>\n"
      unless defined $cve && defined $module && @positionals == 2;
    die "CVE must match CVE-YYYY-NNNN format\n" unless $cve =~ /^CVE-\d{4}-\d{4,19}$/;
    die "Module name looks invalid\n" unless $module =~ /^[A-Za-z0-9_:]+$/;

    my $base = $opt{encrypted} ? 'encrypted' : 'cves';
    if ($base eq 'encrypted') {
      $self->_mark_encrypted_context($cve, File::Spec->catfile('encrypted', "$cve.yaml"));
    }

    my $reserved = File::Spec->catfile('reserved', $cve);
    if (!-f $reserved) {
      if ($opt{force}) {
        print "WARNING: --force set, skipping reserved check ($reserved not found)\n";
      } else {
        die "Cannot initialize $cve: missing reserved record at $reserved\n";
      }
    }

    my $current_branch = $self->_git_current_branch;
    my $target_branch = $cve . '--' . $self->_slugify_module($module);
    my $can_offer_switch = $current_branch eq 'main' && $self->_git_worktree_clean;

    if ($current_branch ne $target_branch && $can_offer_switch) {
      print "Current branch: $current_branch\n";
      print "Recommended branch: $target_branch\n";
      if ($self->_confirm("Switch to '$target_branch'?", 0)) {
        if ($self->_git_branch_exists($target_branch)) {
          $self->_run_cmd('git', 'switch', $target_branch);
        } elsif ($self->_confirm("Create branch '$target_branch' from '$current_branch'?", 0)) {
          $self->_run_cmd('git', 'switch', '-c', $target_branch);
        } else {
          print "Continuing on current branch '$current_branch'.\n";
        }
      } else {
        print "Continuing on current branch '$current_branch'.\n";
      }
    } elsif ($current_branch ne $target_branch) {
      if ($current_branch ne 'main') {
        print "Skipping branch switch prompt: current branch is '$current_branch' (only offered from 'main').\n";
      } else {
        print "Skipping branch switch prompt: working tree has uncommitted changes.\n";
        die "Aborted.\n" unless $self->_confirm("Continue on current branch without switching?", 0);
      }
    }

    my %prefill;
    if ($self->_confirm("Fetch metadata from MetaCPAN for '$module'?", 1)) {
      %prefill = $self->_prefill_from_metacpan($module);
    }
    my $distribution = $prefill{distribution} // do {
      my $d = $module;
      $d =~ s/::/-/g;
      $d;
    };
    my $author = $prefill{author} // 'TODO';
    my $repo = $prefill{repo};

    my $yaml_file = File::Spec->catfile($base, "$cve.yaml");
    make_path($base) unless -d $base;
    if (-f $yaml_file) {
      die "Aborted.\n" unless $self->_confirm("$yaml_file exists. Overwrite?", 0);
    }
    $self->_assert_encrypted_write_safe($yaml_file);

    my $stub = $self->_yaml_stub(
      cve => $cve,
      module => $module,
      distribution => $distribution,
      author => $author,
      repo => $repo,
    );

    open(my $fh, '>', $yaml_file) or die "Cannot write $yaml_file: $!\n";
    print {$fh} $stub;
    close($fh);

    print "Initialized $yaml_file\n";
    return 0;
  }

  method _cmd_check (@args) {
    my %opt = (format => 'text', strict => 0, changed => 0);
    my @positionals;

    while (@args) {
      my $a = shift @args;
      if ($a eq '--changed') { $opt{changed} = 1; next; }
      if ($a eq '--strict') { $opt{strict} = 1; next; }
      if ($a =~ /^--format=(.+)$/) { $opt{format} = $1; next; }
      if ($a eq '--format') { $opt{format} = shift(@args) // die "--format requires value\n"; next; }
      push @positionals, $a;
    }

    die "--format must be 'text' or 'github'\n" unless $opt{format} eq 'text' || $opt{format} eq 'github';
    die "Usage: cna check [CVE-ID] [--changed] [--format text|github] [--strict]\n"
      if @positionals > 1;

    my $default_cve = (!$opt{changed} && !@positionals) ? $self->_default_cve_from_context : undef;

    my @yaml_files = $self->_resolve_check_targets($positionals[0] // $default_cve, $opt{changed});
    if (!@yaml_files) {
      print "No CVE YAML files to check.\n";
      return 0;
    }

    my ($findings_by_file, $errors, $warnings) = $self->_lint_and_validate_files(@yaml_files);
    my $schema_errors = $self->_count_schema_errors($findings_by_file);
    my $report = $self->_render_findings($findings_by_file, $opt{format});
    print $report, "\n" if length $report;

    if ($schema_errors > 0) {
      print "Summary: $errors error(s), $warnings warning(s), $schema_errors schema error(s).\n";
      return 1;
    }
    if ($opt{strict} && ($errors > 0 || $warnings > 0)) {
      print "Summary: $errors error(s), $warnings warning(s), $schema_errors schema error(s) [strict mode].\n";
      return 1;
    }

    print "Summary: $errors error(s), $warnings warning(s), $schema_errors schema error(s).\n";
    return 0;
  }

  method _cmd_build (@args) {
    my %opt = (strict => 0, force => 0);
    my @positionals;

    while (@args) {
      my $a = shift @args;
      if ($a eq '--strict') { $opt{strict} = 1; next; }
      if ($a eq '--force') { $opt{force} = 1; next; }
      push @positionals, $a;
    }

    die "Usage: cna build [CVE-ID] [--strict] [--force]\n" unless @positionals <= 1;
    my $cve = $positionals[0] // $self->_default_cve_from_context
      // die "No CVE provided and no default found (set CPANSEC_CNA_CVE or use a CVE-prefixed branch name).\n";
    my $yaml = $self->_find_yaml_for_cve($cve);

    my ($findings_by_file, $errors, $warnings) = $self->_lint_and_validate_files($yaml);
    my $schema_errors = $self->_count_schema_errors($findings_by_file);
    my $report = $self->_render_findings($findings_by_file, 'text');
    print $report, "\n" if length $report;

    if ($schema_errors > 0 || ($opt{strict} && ($errors > 0 || $warnings > 0))) {
      print "Build blocked by findings.\n";
      return 1;
    }

    my $cve_obj = CPANSec::CVE->from_yaml_file($yaml);
    my $json = $cve_obj->to_cve5_json;

    (my $json_file = $yaml) =~ s/\.yaml$/.json/i;
    if (-f $json_file && !$opt{force}) {
      die "Aborted.\n" unless $self->_confirm("$json_file exists. Overwrite?", 0);
    }
    $self->_assert_encrypted_write_safe($json_file);

    open(my $fh, '>', $json_file) or die "Cannot write $json_file: $!\n";
    print {$fh} $json;
    close($fh);

    print "Wrote $json_file\n";
    return 0;
  }

  method _cmd_emit (@args) {
    my %opt = (strict => 0, cna_container_only => 0);
    my @positionals;

    while (@args) {
      my $a = shift @args;
      if ($a eq '--strict') { $opt{strict} = 1; next; }
      if ($a eq '--cna-container-only') { $opt{cna_container_only} = 1; next; }
      push @positionals, $a;
    }

    die "Usage: cna emit [CVE-ID] [--strict] [--cna-container-only]\n" unless @positionals <= 1;
    my $cve = $positionals[0] // $self->_default_cve_from_context
      // die "No CVE provided and no default found (set CPANSEC_CNA_CVE or use a CVE-prefixed branch name).\n";
    my $yaml = $self->_find_yaml_for_cve($cve);

    my ($findings_by_file, $errors, $warnings) = $self->_lint_and_validate_files($yaml);
    my $schema_errors = $self->_count_schema_errors($findings_by_file);
    my $report = $self->_render_findings($findings_by_file, 'text');
    print STDERR $report, "\n" if length $report && ($errors > 0 || $warnings > 0);

    if ($schema_errors > 0 || ($opt{strict} && ($errors > 0 || $warnings > 0))) {
      print STDERR "Emit blocked by findings.\n";
      return 1;
    }

    my $cve_obj = CPANSec::CVE->from_yaml_file($yaml);
    my $json = $opt{cna_container_only} ? $cve_obj->to_cna_container_json : $cve_obj->to_cve5_json;
    print $json;
    return 0;
  }

  method _cmd_announce (@args) {
    my %opt = (write => 0, force => 0);
    my @positionals;

    while (@args) {
      my $a = shift @args;
      if ($a eq '--write') { $opt{write} = 1; next; }
      if ($a eq '--force') { $opt{force} = 1; next; }
      if ($a =~ /^--output=(.+)$/) { $opt{output} = $1; next; }
      if ($a eq '--output') { $opt{output} = shift(@args) // die "--output requires value\n"; next; }
      push @positionals, $a;
    }

    die "Usage: cna announce [CVE-ID] [--write|--output path] [--force]\n"
      unless @positionals <= 1;
    die "--write and --output cannot be combined\n" if $opt{write} && defined $opt{output};

    my $cve = $positionals[0] // $self->_default_cve_from_context
      // die "No CVE provided and no default found (set CPANSEC_CNA_CVE or use a CVE-prefixed branch name).\n";

    my ($text, $source_yaml) = $self->_render_announce_text($cve);
    if (defined $source_yaml && $source_yaml =~ m{^encrypted/}) {
      die "Refusing to generate announcement from encrypted CVE source ($source_yaml). Publish it to cves/ first.\n";
    }

    if (defined $opt{output} || $opt{write}) {
      my $default_dir = 'announce';
      my $default_file = "$cve.txt";
      my $out = defined($opt{output}) ? $opt{output} : File::Spec->catfile($default_dir, $default_file);
      if (-f $out && !$opt{force}) {
        die "Aborted.\n" unless $self->_confirm("$out exists. Overwrite?", 0);
      }
      $self->_assert_encrypted_write_safe($out);
      my $dir = dirname($out);
      make_path($dir) unless -d $dir;
      open(my $fh, '>', $out) or die "Cannot write $out: $!\n";
      print {$fh} $text;
      close($fh);
      print "Wrote $out\n";
      return 0;
    }

    print $text;
    return 0;
  }

  method _cmd_import (@args) {
    my %opt = (force => 0, guard => 1);
    my @positionals;

    while (@args) {
      my $a = shift @args;
      if ($a eq '--force') { $opt{force} = 1; next; }
      if ($a eq '--no-guard') { $opt{guard} = 0; next; }
      push @positionals, $a;
    }

    die "Usage: cna import <CVE-ID|path.json> [--force] [--no-guard]\n"
      unless @positionals == 1;

    my ($json_path, $yaml_path) = $self->_resolve_import_paths($positionals[0]);
    die "Cannot read JSON input $json_path\n" unless -f $json_path;

    if (-f $yaml_path && !$opt{force}) {
      die "Aborted.\n" unless $self->_confirm("$yaml_path exists. Overwrite?", 0);
    }
    $self->_assert_encrypted_write_safe($yaml_path);

    my $conv = CPANSec::CVE::CVE2YAML->new;
    my $yaml = $conv->convert_json_file_to_yaml($json_path, guard => $opt{guard});

    open(my $fh, '>', $yaml_path) or die "Cannot write $yaml_path: $!\n";
    print {$fh} $yaml;
    close($fh);

    print "Wrote $yaml_path\n";
    print "Round-trip guard: ", ($opt{guard} ? "enabled" : "disabled"), "\n";
    return 0;
  }

  method _cmd_reconcile (@args) {
    my $api_base = 'https://cveawg.mitre.org/api/cve';
    my $verbose = 0;
    my @positionals;

    while (@args) {
      my $a = shift @args;
      if ($a =~ /^--api-base=(.+)$/) { $api_base = $1; next; }
      if ($a eq '--api-base') { $api_base = shift(@args) // die "--api-base requires value\n"; next; }
      if ($a eq '--verbose') { $verbose = 1; next; }
      push @positionals, $a;
    }
    die "Usage: cna reconcile [CVE-ID] [--api-base URL] [--verbose]\n" if @positionals > 1;

    my @ids;
    if (@positionals == 1) {
      my $cve = $positionals[0];
      die "CVE must match CVE-YYYY-NNNN format\n" unless $cve =~ /^CVE-\d{4}-\d{4,19}$/;
      push @ids, $cve;
    } else {
      @ids = $self->_local_cve_ids;
    }

    if (!@ids) {
      print "No local CVE records found under cves/*.{yaml,json}\n";
      return 0;
    }

    my $single = @ids == 1 ? 1 : 0;
    my ($same, $diff, $missing, $errors) = (0, 0, 0, 0);
    for my $cve (@ids) {
      my ($ok, $message);
      my $eval_ok = eval {
        ($ok, $message) = $self->_reconcile_one($cve, $api_base);
        1;
      };
      if (!$eval_ok) {
        my $err = $@ || 'unknown error';
        chomp $err;
        if ($err =~ s/^NOT_FOUND:\s*//) {
          print "MISSING $cve: $err\n";
          $missing++;
          next;
        }
        print "ERROR $cve: $err\n";
        $errors++;
        next;
      }
      if ($message eq 'same') {
        print "OK $cve: containers.cna matches\n" if $single || $verbose;
        $same++;
      } else {
        print "DIFF $cve: containers.cna differs\n";
        print $message;
        print "\n" unless $message =~ /\n\z/;
        $diff++;
      }
    }

    if (!$single && !$verbose && $same > 0) {
      print "OK: $same CVE(s) match.\n";
    }
    print "Summary: $same match, $diff differ, $missing missing, $errors error.\n";
    return ($diff > 0 || $missing > 0 || $errors > 0) ? 1 : 0;
  }

  method _lint_and_validate_files (@yaml_files) {
    my %findings_by_file;
    my ($errors, $warnings) = (0, 0);

    for my $yaml (@yaml_files) {
      my @findings;
      my $cve_obj;
      my $ok = eval {
        $cve_obj = CPANSec::CVE->from_yaml_file($yaml);
        1;
      };

      if (!$ok) {
        my $msg = $@ || 'YAML/schema validation failed';
        chomp $msg;
        push @findings, {
          severity => 'error',
          id => 'schema_validation',
          message => $msg,
          path => $yaml,
          line => 1,
        };
      } else {
        my $lint_findings = $lint->run_model($cve_obj->model, path => $yaml);
        push @findings, @$lint_findings;
        if (my $json_sync = $self->_check_yaml_json_sync($yaml, $cve_obj)) {
          push @findings, $json_sync;
        }
      }

      for my $f (@findings) {
        if (($f->{severity} // '') eq 'error') { $errors++; }
        else { $warnings++; }
      }
      $findings_by_file{$yaml} = \@findings;
    }

    return (\%findings_by_file, $errors, $warnings);
  }

  method _render_findings ($findings_by_file, $format) {
    if ($format eq 'github') {
      my $r = CPANSec::CNA::Lint::Reporter::GitHub->new;
      return $r->render($findings_by_file);
    }
    my $r = CPANSec::CNA::Lint::Reporter::Text->new;
    return $r->render($findings_by_file);
  }

  method _count_schema_errors ($findings_by_file) {
    my $count = 0;
    for my $path (keys %$findings_by_file) {
      for my $f (@{$findings_by_file->{$path} // []}) {
        $count++ if ($f->{id} // '') eq 'schema_validation';
      }
    }
    return $count;
  }

  method _resolve_check_targets ($cve, $changed) {
    if (defined $cve && length $cve) {
      return ($self->_find_yaml_for_cve($cve));
    }

    if ($changed) {
      return $self->_changed_yaml_files;
    }

    my @files = glob('cves/*.yaml');
    push @files, glob('encrypted/*.yaml');
    @files = sort grep { -f $_ } @files;
    for my $f (@files) {
      if ($f =~ m{^encrypted/([^/]+)\.yaml$}i) {
        $self->_mark_encrypted_context($1, $f);
      }
    }
    return @files;
  }

  method _changed_yaml_files () {
    my @cand = $self->_run_cmd_capture('git', 'diff', '--name-only', 'origin/main...HEAD');
    if (!@cand) {
      @cand = $self->_run_cmd_capture('git', 'diff', '--name-only', 'HEAD~1...HEAD');
    }

    my %seen;
    my @files;
    for my $f (@cand) {
      chomp $f;
      next unless $f =~ m{^(cves|encrypted)/.+\.yaml$}i;
      next unless -f $f;
      next if $seen{$f}++;
      if ($f =~ m{^encrypted/([^/]+)\.yaml$}i) {
        $self->_mark_encrypted_context($1, $f);
      }
      push @files, $f;
    }
    return sort @files;
  }

  method _find_yaml_for_cve ($cve) {
    die "CVE must match CVE-YYYY-NNNN format\n" unless $cve =~ /^CVE-\d{4}-\d{4,19}$/;
    my $path = $self->_resolve_cve_path($cve, qw(yaml));
    die "Cannot find YAML for $cve under cves/ or encrypted/\n" unless defined $path;
    return $path;
  }

  method _default_cve_from_context () {
    if (defined $ENV{CPANSEC_CNA_CVE} && length $ENV{CPANSEC_CNA_CVE}) {
      my $cve = $ENV{CPANSEC_CNA_CVE};
      die "Invalid CPANSEC_CNA_CVE value '$cve' (expected CVE-YYYY-NNNN)\n"
        unless $cve =~ /^CVE-\d{4}-\d{4,19}$/;
      return $cve;
    }

    my $branch = $self->_git_current_branch;
    return undef unless defined $branch && length $branch;
    return $1 if $branch =~ /^(CVE-\d{4}-\d{4,19})(?:--|-|$)/;
    return undef;
  }

  method _resolve_import_paths ($arg) {
    if ($arg =~ /^CVE-\d{4}-\d{4,19}$/) {
      my $json = $self->_resolve_cve_path($arg, qw(json));
      if (!defined $json) {
        my $yaml_existing = $self->_resolve_cve_path($arg, qw(yaml));
        if (defined $yaml_existing && $yaml_existing =~ m{^encrypted/}) {
          $json = File::Spec->catfile('encrypted', "$arg.json");
        } else {
          $json = File::Spec->catfile('cves', "$arg.json");
        }
      }
      my $yaml = $json;
      $yaml =~ s/\.json$/.yaml/i;
      return ($json, $yaml);
    }

    my $json = $arg;
    die "Import expects a .json path or CVE ID\n" unless $json =~ /\.json$/i;
    if ($json =~ m{(^|/)encrypted/}i) {
      my ($cve) = $json =~ m{(CVE-\d{4}-\d{4,19})}i;
      $self->_mark_encrypted_context($cve // 'unknown', $json);
    }
    (my $yaml = $json) =~ s/\.json$/.yaml/i;
    return ($json, $yaml);
  }

  method _render_announce_text ($cve) {
    die "CVE must match CVE-YYYY-NNNN format\n" unless $cve =~ /^CVE-\d{4}-\d{4,19}$/;
    my $yaml = $self->_find_yaml_for_cve($cve);
    my $cve_obj = CPANSec::CVE->from_yaml_file($yaml);
    return ($cve_obj->to_announce_text, $yaml);
  }

  method _local_cve_ids () {
    my @files = glob('cves/*.yaml');
    push @files, glob('cves/*.json');
    @files = sort grep { -f $_ } @files;
    my %seen;
    my @ids;
    for my $f (@files) {
      my ($id) = $f =~ m{/(CVE-\d{4}-\d{4,19})\.(?:json|yaml)$}i;
      next unless $id =~ /^CVE-\d{4}-\d{4,19}$/;
      if (exists $seen{$id} && $seen{$id} ne $f) {
        # multiple representations for same CVE in one base are acceptable
        # (e.g. yaml + json); reconcile will resolve preferred source.
      } else {
        $seen{$id} = $f;
        push @ids, $id;
      }
    }
    return @ids;
  }

  method _reconcile_one ($cve, $api_base) {
    my ($local, $local_path) = $self->_load_local_cve_for_reconcile($cve);
    my $remote = $self->_fetch_remote_cve($cve, $api_base);

    my $local_cna = $local->{containers}{cna}
      or die "Local record missing containers.cna in $local_path\n";
    my $remote_cna = $remote->{containers}{cna}
      or die "Remote record missing containers.cna for $cve\n";

    my $local_norm = _normalize_cna_for_reconcile($local_cna);
    my $remote_norm = _normalize_cna_for_reconcile($remote_cna);

    my ($eq, $diff_text) = $self->_diff_json_structures($local_norm, $remote_norm, "$cve local", "$cve remote");
    return ($eq ? 1 : 0, $eq ? 'same' : $diff_text);
  }

  method _load_local_cve_for_reconcile ($cve) {
    my @cves_yaml = grep { -f $_ } (File::Spec->catfile('cves', "$cve.yaml"));
    my @cves_json = grep { -f $_ } (File::Spec->catfile('cves', "$cve.json"));

    if (@cves_yaml) {
      my $obj = CPANSec::CVE->from_yaml_file($cves_yaml[0]);
      my $doc = decode_json($obj->to_cve5_json);
      return ($doc, $cves_yaml[0]);
    }

    if (@cves_json) {
      return (_read_json_file($cves_json[0]), $cves_json[0]);
    }

    die "Missing local CVE source for $cve under cves/ (yaml/json)\n";
  }

  method _fetch_remote_cve ($cve, $api_base) {
    if ($api_base =~ m{^file://(.+)$}) {
      my $base = $1;
      my $path;
      if ($base =~ /%s/) {
        $path = sprintf($base, $cve);
      } else {
        $base =~ s{/+$}{};
        $path = "$base/$cve.json";
      }
      die "NOT_FOUND: no remote CVE record at $path\n" unless -f $path;
      return _read_json_file($path);
    }

    die "Network access is disabled (encrypted context or CPANSEC_CNA_NO_NETWORK/HARNESS_ACTIVE)\n"
      unless $self->_network_allowed;

    my $url = $api_base;
    $url =~ s{/+$}{};
    $url .= "/$cve";

    my $http = HTTP::Tiny->new(
      timeout => 30,
      agent => "cpansec-cna/0.1",
      verify_SSL => 1,
    );
    my $res = $http->get($url, { headers => { Accept => 'application/json' } });
    if (($res->{status} // 0) == 404) {
      die "NOT_FOUND: API returned 404 for $url\n";
    }
    die "HTTP $res->{status} from $url: $res->{reason}\n" unless $res->{success};

    my $doc = eval { decode_json($res->{content} // '') };
    die "Failed to parse JSON from $url: $@\n" if !$doc;
    return $doc;
  }

  method _diff_json_structures ($left, $right, $left_name, $right_name) {
    my $json = JSON::PP->new->canonical->pretty;
    my $l = $json->encode($left);
    my $r = $json->encode($right);
    return (1, '') if $l eq $r;

    my ($lfh, $lfile) = tempfile('cna-left-XXXX', TMPDIR => 1, UNLINK => 1);
    my ($rfh, $rfile) = tempfile('cna-right-XXXX', TMPDIR => 1, UNLINK => 1);
    print {$lfh} $l;
    print {$rfh} $r;
    close($lfh);
    close($rfh);

    my @diff = $self->_run_cmd_capture_any('diff', '-u', '--label', $left_name, '--label', $right_name, $lfile, $rfile);
    my $txt = join('', @diff);
    return (0, $txt);
  }

  method _check_yaml_json_sync ($yaml, $cve_obj) {
    return undef unless $yaml =~ m{^cves/.+\.yaml$}i;
    (my $json_file = $yaml) =~ s/\.yaml$/.json/i;
    return undef unless -f $json_file;

    my $local_json = eval { _read_json_file($json_file) };
    if (!$local_json) {
      my $err = $@ || 'unknown JSON parse error';
      chomp $err;
      return {
        severity => 'warning',
        id => 'json_unreadable',
        message => "Cannot parse existing JSON file $json_file: $err",
        path => $json_file,
        line => 1,
      };
    }

    my $generated_json = decode_json($cve_obj->to_cve5_json);
    my $json = JSON::PP->new->canonical;

    my $local_projection = eval { CPANSec::CVE::CVE2YAML::_project_roundtrip_view($local_json) };
    if (!$local_projection) {
      my $err = $@ || 'unknown projection error';
      chomp $err;
      return {
        severity => 'warning',
        id => 'json_unreadable',
        message => "Cannot project existing JSON file $json_file into round-trip view: $err",
        path => $json_file,
        line => 1,
      };
    }
    my $generated_projection = CPANSec::CVE::CVE2YAML::_project_roundtrip_view($generated_json);
    return undef if $json->encode($local_projection) eq $json->encode($generated_projection);

    my ($cve) = basename($yaml) =~ /^(CVE-\d{4}-\d{4,19})\.yaml$/i;
    my $hint = defined($cve) ? "run `cna build $cve`" : "run `cna build`";
    return {
      severity => 'warning',
      id => 'json_out_of_date',
      message => "JSON file $json_file is not in sync with $yaml; $hint to refresh it.",
      path => $yaml,
      line => 1,
    };
  }

  method _yaml_stub (%in) {
    my $repo = defined($in{repo}) && length($in{repo}) ? $in{repo} : 'https://example.invalid/TODO-repo';
    return sprintf <<'YAML', $in{cve}, $in{distribution}, $in{module}, $in{author}, $repo, $in{module}, $in{module};
# yaml-language-server: $schema=../schema/cpansec-cna-schema-01.yaml
cpansec:
  cve: %s
  distribution: %s
  module: %s
  author: %s
  repo: %s

  affected:
    - "<= TODO"

  title: %s {{VERSION_RANGE}} for Perl TODO

  description: |-
    %s {{VERSION_RANGE}} for Perl TODO.
    TODO description.

  # cwes:
  #   - CWE-XXX Name

  # impacts:
  #   - CAPEC-XXX Name

  # solution: |-
  #   ...

  # mitigation: |-
  #   ...

  # files:
  #   - lib/Path/To/File.pm

  # routines:
  #   - Package::routine_name

  # timeline:
  #   - time: YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ
  #     value: Event summary

  # credits:
  #   - type: finder
  #     value: Name

  references:
    - link: https://example.invalid/TODO
      tags: [advisory]

YAML
  }

  method _slugify_module ($module) {
    my $slug;
    my $ok = eval {
      require Mojo::Util;
      $slug = Mojo::Util::slugify($module);
      1;
    };

    if (!$ok || !defined $slug || $slug eq '') {
      $slug = $module;
      $slug =~ s/::/-/g;
      $slug =~ s/[^A-Za-z0-9-]+/-/g;
      $slug =~ s/-+/-/g;
      $slug =~ s/^-|-$//g;
    }
    return $slug;
  }

  method _prefill_from_metacpan ($module) {
    my %ret;
    return %ret unless $self->_network_allowed;

    my $ok = eval {
      require MetaCPAN::Client;
      my $mc = MetaCPAN::Client->new;
      my $mod = eval { $mc->module($module) };

      my $dist;
      if ($mod) {
        $dist = _obj_get($mod, 'distribution');
        $dist //= _obj_get($mod, 'dist');
      }
      $ret{distribution} = $dist if defined $dist && length $dist;

      if (defined $dist && length $dist) {
        my $rel = eval { $mc->release($dist) };
        if ($rel) {
          my $author = _obj_get($rel, 'author');
          $ret{author} = $author if defined $author && length $author;

          my $res = _obj_get($rel, 'resources');
          if (ref($res) eq 'HASH') {
            my $repo = $res->{repository};
            if (ref($repo) eq 'HASH') {
              my $url = $repo->{url};
              if (defined $url && !ref($url) && length $url) {
                $ret{repo} = $self->_normalize_prefill_repo_url($url);
              }
            }
          }
        }
      }
      1;
    };

    return %ret;
  }

  method _network_allowed () {
    return 0 if $encrypted_context;
    return 0 if defined $ENV{CPANSEC_CNA_NO_NETWORK} && $ENV{CPANSEC_CNA_NO_NETWORK};
    return 0 if defined $ENV{HARNESS_ACTIVE} && $ENV{HARNESS_ACTIVE};
    return 1;
  }

  method _normalize_prefill_repo_url ($url) {
    my $out = $url;
    if ($out =~ m{^git://github\.com/(.+)$}i) {
      $out = "https://github.com/$1";
    }
    if ($out =~ m{^https://github\.com/}i) {
      $out =~ s{^https://github\.com/}{https://github.com/}i;
      $out =~ s{\.git$}{};
    }
    return $out;
  }

  method _assert_encrypted_branch_policy () {
    my $branch = $self->_git_current_branch;
    if ($branch eq 'main') {
      die "Refusing to operate on encrypted CVE data from 'main'; use a PR branch.\n";
    }
    return;
  }

  method _resolve_cve_path ($cve, @exts) {
    my @hits;
    for my $base ('cves', 'encrypted') {
      for my $ext (@exts) {
        my $p = File::Spec->catfile($base, "$cve.$ext");
        push @hits, [$base, $p] if -f $p;
      }
    }

    return undef if !@hits;

    my %by_base;
    for my $h (@hits) {
      $by_base{$h->[0]} ||= [];
      push @{$by_base{$h->[0]}}, $h->[1];
    }

    if ($by_base{cves} && $by_base{encrypted}) {
      my $c = join(', ', @{$by_base{cves}});
      my $e = join(', ', @{$by_base{encrypted}});
      die "Ambiguous source for $cve: found in both cves/ ($c) and encrypted/ ($e)\n";
    }

    my ($base) = keys %by_base;
    my $chosen = $by_base{$base}[0];
    if ($base eq 'encrypted') {
      $self->_mark_encrypted_context($cve, $chosen);
    }
    return $chosen;
  }

  method _mark_encrypted_context ($cve, $path) {
    $encrypted_context = 1;
    $self->_assert_encrypted_branch_policy;
    return if $encrypted_notice_shown;
    $encrypted_notice_shown = 1;
    print STDERR "!!! SENSITIVE CVE CONTEXT DETECTED !!!\n";
    print STDERR "Using encrypted data path: $path\n";
    print STDERR "Network access is disabled for this run.\n";
  }

  method _assert_encrypted_write_safe ($path) {
    return unless $self->_is_encrypted_path($path);
    $self->_mark_encrypted_context('unknown', $path);

    if (defined $ENV{CPANSEC_CNA_GIT_CRYPT_SHIM} && length $ENV{CPANSEC_CNA_GIT_CRYPT_SHIM}) {
      my $mode = $ENV{CPANSEC_CNA_GIT_CRYPT_SHIM};
      return if $mode eq 'ok';
      die "Refusing encrypted write: git-crypt path is not protected by attributes ($path)\n"
        if $mode eq 'unprotected';
      die "Refusing encrypted write: git-crypt appears locked ($path)\n"
        if $mode eq 'locked';
      die "Refusing encrypted write: git-crypt unavailable ($path)\n"
        if $mode eq 'missing';
      die "Invalid CPANSEC_CNA_GIT_CRYPT_SHIM value '$mode' (expected ok|unprotected|locked|missing)\n";
    }

    my @attr = $self->_run_cmd_capture_any('git', 'check-attr', 'filter', '--', $path);
    my $has_filter = grep { /:\s*filter:\s*git-crypt\s*$/ } @attr;
    die "Refusing encrypted write: git-crypt filter not configured for $path\n" unless $has_filter;

    my ($rc, @enc) = $self->_run_cmd_capture_with_rc('git-crypt', 'status', '-e', 'encrypted');
    if (!defined $rc) {
      die "Refusing encrypted write: git-crypt command unavailable\n";
    }
    if ($rc != 0) {
      my $detail = join('', @enc);
      chomp $detail;
      $detail = "git-crypt status failed with exit $rc" if !length $detail;
      die "Refusing encrypted write: $detail\n";
    }

    my $locked = grep { /^\s*encrypted:\s+/ } @enc;
    if ($locked) {
      die "Refusing encrypted write: git-crypt appears locked (encrypted files are still ciphertext in working tree)\n";
    }
    return;
  }

  method _is_encrypted_path ($path) {
    return 1 if $path =~ m{(?:^|/)encrypted/};
    return 0;
  }

  method _git_current_branch () {
    my @out = $self->_run_cmd_capture('git', 'branch', '--show-current');
    my $b = $out[0] // '';
    chomp $b;
    die "Cannot determine current git branch\n" unless length $b;
    return $b;
  }

  method _git_branch_exists ($branch) {
    system('git', 'show-ref', '--verify', '--quiet', "refs/heads/$branch");
    return ($? >> 8) == 0;
  }

  method _git_worktree_clean () {
    my ($rc, @out) = $self->_run_cmd_capture_with_rc('git', 'status', '--porcelain');
    return 0 if !defined $rc || $rc != 0;
    return @out ? 0 : 1;
  }

  method _confirm ($question, $default_yes) {
    my $hint = $default_yes ? 'Y/n' : 'y/N';
    print "$question [$hint] ";
    my $ans = <STDIN>;
    return $default_yes unless defined $ans;
    chomp $ans;
    $ans =~ s/^\s+|\s+$//g;
    return $default_yes if $ans eq '';
    return 1 if $ans =~ /^(y|yes)$/i;
    return 0 if $ans =~ /^(n|no)$/i;
    return 0;
  }

  method _run_cmd (@cmd) {
    system(@cmd);
    my $rc = $? >> 8;
    die "Command failed ($rc): @cmd\n" if $rc != 0;
    return;
  }

  method _run_cmd_capture (@cmd) {
    open my $fh, '-|', @cmd or return ();
    my @lines = <$fh>;
    close $fh;
    return @lines if ($? >> 8) == 0;
    return ();
  }

  method _run_cmd_capture_any (@cmd) {
    open my $fh, '-|', @cmd or return ();
    my @lines = <$fh>;
    close $fh;
    return @lines;
  }

  method _run_cmd_capture_with_rc (@cmd) {
    open my $fh, '-|', @cmd or return (undef);
    my @lines = <$fh>;
    close $fh;
    my $rc = $? >> 8;
    return ($rc, @lines);
  }
}

sub _obj_get ($obj, $key) {
  return undef unless defined $obj;
  if (ref($obj) eq 'HASH') {
    return $obj->{$key};
  }
  if (eval { $obj->can($key) }) {
    return eval { $obj->$key };
  }
  return undef;
}

sub _read_json_file ($path) {
  open(my $fh, '<', $path) or die "Cannot read $path: $!\n";
  local $/;
  my $json = <$fh>;
  close($fh);
  return decode_json($json);
}

sub _normalize_cna_for_reconcile ($cna) {
  my $copy = dclone($cna);

  # Reconciliation should focus on published vulnerability content, not
  # provider metadata maintained by CVE Services.
  delete $copy->{providerMetadata};

  return $copy;
}

1;
