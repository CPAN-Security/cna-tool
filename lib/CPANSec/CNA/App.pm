package CPANSec::CNA::App;

use v5.42;
use feature qw(class);
no warnings qw(experimental::class);

use CPANSec::CNA::Lint ();
use CPANSec::CNA::Lint::Reporter::GitHub ();
use CPANSec::CNA::Lint::Reporter::Text ();
use CPANSec::CVE ();
use CPANSec::CVE::Announce ();
use CPANSec::CVE::AnnounceMulti ();
use CPANSec::CVE::BatchName qw(batch_filename parse_batch_filename sort_cve_ids);
use CPANSec::CVE::CVE2YAML ();
use CPANSec::CVE::YAML2CVE ();
use File::Basename qw(dirname basename);
use File::Path qw(make_path);
use File::Spec ();
use File::Temp qw(tempfile);
use Encode qw(decode);
use HTTP::Tiny ();
use JSON::PP qw(decode_json);
use List::Util qw(max uniq);
use Storable qw(dclone);
use Text::ParseWords qw(shellwords);

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
    if ($cmd eq 'announce-multi') {
      return $self->_cmd_announce_multi(@argv);
    }
    if ($cmd eq 'list-cves') {
      return $self->_cmd_list_cves(@argv);
    }
    if ($cmd eq 'edit') {
      return $self->_cmd_edit(@argv);
    }
    if ($cmd eq 'import') {
      return $self->_cmd_import(@argv);
    }
    if ($cmd eq 'reconcile') {
      return $self->_cmd_reconcile(@argv);
    }
    if ($cmd eq 'yaml-schema-path') {
      return $self->_cmd_yaml_schema_path(@argv);
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
                                    Use --pr-policy --base-sha <sha> to enforce announce PR rules
  build [CVE-ID] [--strict]
                                    Validate/lint and write <CVE-ID>.json next to source YAML
  emit [CVE-ID] [--strict] [--cna-container-only]
                                    Validate/lint and print generated JSON to stdout
  announce [CVE-ID] [--write|--output path]
                                    Render announcement text to stdout or file
  announce-multi <CVE-ID> <CVE-ID>... [--write|--output path] [--force]
                                    Render one announcement covering several CVEs
                                    of the same distribution (--write: announce-multi/)
  announce-multi [--create|--sync] [CVE-ID...] [--dry-run]
                                    --create: start batches for this branch's new CVEs;
                                    --sync: update the branch's batches (writes; --dry-run previews)
  list-cves --branch [--ids]
                                    List CVEs this branch touches (committed, staged,
                                    unstaged or untracked) with their changed files
  edit [CVE-ID]
                                    Open CVE YAML in $VISUAL/$EDITOR (or vi)
  import [CVE-ID|path.json] [--force] [--no-guard]
                                    Convert CVE JSON to YAML macro with round-trip guard
  reconcile [CVE-ID] [--api-base URL]
                                    Compare local CNA container with published CVE JSON
  yaml-schema-path
                                    Print the path of the YAML schema bundled with the tool

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
    # The distribution becomes the Package URL, so an unchecked guess publishes
    # an identifier that resolves to nothing.
    my $distribution = $prefill{distribution};
    if (defined $distribution && length $distribution) {
      print "Distribution '$distribution' confirmed via MetaCPAN.\n";
    } else {
      $distribution = $module =~ s/::/-/gr;
      print <<"UNVERIFIED";
WARNING: distribution '$distribution' was derived from the module name and is
         NOT confirmed against MetaCPAN, so pkg:cpan/$distribution may not
         resolve (LWP::UserAgent, for instance, ships in libwww-perl).
         Check it before publishing.
UNVERIFIED
    }
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
      repo => $repo,
    );

    open(my $fh, '>', $yaml_file) or die "Cannot write $yaml_file: $!\n";
    print {$fh} $stub;
    close($fh);

    print "Initialized $yaml_file\n";
    $self->_retire_reserved($cve, $reserved);
    $self->_hint_multi_after_init($cve);
    return 0;
  }

  # Issuing the CVE is what retires its reservation, so the removal is staged
  # here rather than left as a step to remember. It belongs to the PR that
  # issues the CVE: on main the reservation is the record that the ID is held,
  # so it is left alone there rather than staged for deletion.
  method _retire_reserved ($cve, $reserved) {
    return unless -f $reserved;

    if ($self->_git_current_branch eq 'main') {
      print "Left $reserved in place: reservations are retired in the PR that issues the CVE.\n";
      return;
    }

    my ($rc) = $self->_run_cmd_capture_with_rc('git', 'rm', '--quiet', '--', $reserved);
    if (!defined $rc || $rc != 0) {
      print "WARNING: could not 'git rm $reserved'; remove the reservation by hand.\n";
      return;
    }

    print "Staged removal of $reserved\n";
    return;
  }

  method _cmd_check (@args) {
    my %opt = (format => 'text', strict => 0, changed => 0, pr_policy => 0);
    my @positionals;

    while (@args) {
      my $a = shift @args;
      if ($a eq '--changed') { $opt{changed} = 1; next; }
      if ($a eq '--strict') { $opt{strict} = 1; next; }
      if ($a eq '--pr-policy') { $opt{pr_policy} = 1; next; }
      if ($a =~ /^--base-sha=(.+)$/) { $opt{base_sha} = $1; next; }
      if ($a eq '--base-sha') { $opt{base_sha} = shift(@args) // die "--base-sha requires value\n"; next; }
      if ($a =~ /^--format=(.+)$/) { $opt{format} = $1; next; }
      if ($a eq '--format') { $opt{format} = shift(@args) // die "--format requires value\n"; next; }
      push @positionals, $a;
    }

    die "--format must be 'text' or 'github'\n" unless $opt{format} eq 'text' || $opt{format} eq 'github';
    die "Usage: cna check [CVE-ID] [--changed] [--format text|github] [--strict] [--pr-policy --base-sha <sha>]\n"
      if @positionals > 1;
    if ($opt{pr_policy}) {
      die "--pr-policy requires --base-sha <sha>\n"
        unless defined $opt{base_sha} && length $opt{base_sha};
    } elsif (defined $opt{base_sha}) {
      die "--base-sha requires --pr-policy\n";
    }

    my $default_cve = (!$opt{changed} && !@positionals) ? $self->_default_cve_from_context : undef;

    my $target_cve = $positionals[0] // $default_cve;
    my @yaml_files = $self->_resolve_check_targets($target_cve, $opt{changed});
    my @multi_files = $self->_resolve_multi_check_targets($target_cve, $opt{changed}, \@yaml_files);
    if (!@yaml_files && !@multi_files && !$opt{pr_policy}) {
      print "No CVE YAML files to check.\n";
      return 0;
    }

    $self->_warn_if_no_merged_ref if @multi_files && !$opt{pr_policy};

    my ($findings_by_file, $errors, $warnings) = $self->_lint_and_validate_files(@yaml_files);
    my ($multi_findings, $multi_errors)
      = $self->_announce_multi_findings(\@multi_files, $opt{pr_policy} ? $opt{base_sha} : $self->_merged_ref);
    $self->_merge_findings($findings_by_file, $multi_findings);
    $errors += $multi_errors;
    my $incomplete_ref = $opt{pr_policy} ? $opt{base_sha} : $self->_existing_merged_ref;
    if (@multi_files && defined $incomplete_ref) {
      my ($incomplete, $incomplete_warnings) = $self->_multi_incomplete_findings(\@multi_files, $incomplete_ref);
      $self->_merge_findings($findings_by_file, $incomplete);
      $warnings += $incomplete_warnings;
    }
    my $pr_policy_errors = 0;
    if ($opt{pr_policy}) {
      my ($extra_findings, $extra_errors, $extra_warnings)
        = $self->_pr_policy_announce_findings(\@yaml_files, $opt{base_sha});
      $self->_merge_findings($findings_by_file, $extra_findings);
      $errors += $extra_errors;
      $warnings += $extra_warnings;
      $pr_policy_errors += $extra_errors;
      my $scope = defined $target_cve && length $target_cve ? { $target_cve => 1 } : undef;
      my ($multi_policy, $multi_policy_errors)
        = $self->_pr_policy_announce_multi_findings($opt{base_sha}, $scope);
      $self->_merge_findings($findings_by_file, $multi_policy);
      $errors += $multi_policy_errors;
      $pr_policy_errors += $multi_policy_errors;
    }
    my $schema_errors = $self->_count_schema_errors($findings_by_file);
    my $report = $self->_render_findings($findings_by_file, $opt{format});
    print $report, "\n" if length $report;
    $self->_print_batch_results(\@multi_files, $findings_by_file);

    if ($schema_errors > 0) {
      print "Summary: $errors error(s), $warnings warning(s), $schema_errors schema error(s).\n";
      return 1;
    }
    if ($pr_policy_errors > 0 || $multi_errors > 0) {
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

    die "Usage: cna build [CVE-ID] [--strict]\n" unless @positionals <= 1;
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

    # No overwrite prompt: writing this file is what the command does, the
    # content is regenerated from the YAML, and it is tracked in git.
    (my $json_file = $yaml) =~ s/\.yaml$/.json/i;
    $self->_assert_encrypted_write_safe($json_file);

    open(my $fh, '>', $json_file) or die "Cannot write $json_file: $!\n";
    print {$fh} $json;
    close($fh);

    print "Wrote $json_file\n";
    $self->_hint_multi_out_of_date;
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

    die "Usage: cna announce [CVE-ID] [--write|--output path]\n"
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
      # No overwrite prompt: --write/--output asked for the file to be written,
      # and the text is regenerated from the YAML.
      my $out = defined($opt{output}) ? $opt{output} : File::Spec->catfile($default_dir, $default_file);
      $self->_assert_encrypted_write_safe($out);
      my $dir = dirname($out);
      make_path($dir) unless -d $dir;
      open(my $fh, '>:encoding(UTF-8)', $out) or die "Cannot write $out: $!\n";
      print {$fh} $text;
      close($fh);
      print "Wrote $out\n";
      $self->_hint_multi_out_of_date;
      return 0;
    }

    binmode(STDOUT, ':encoding(UTF-8)');
    print $text;
    return 0;
  }

  method _cmd_announce_multi (@args) {
    my %opt = (write => 0, force => 0, sync => 0, create => 0, dry_run => 0);
    my @ids;

    while (@args) {
      my $a = shift @args;
      if ($a eq '--sync') { $opt{sync} = 1; next; }
      if ($a eq '--create') { $opt{create} = 1; next; }
      if ($a eq '--dry-run') { $opt{dry_run} = 1; next; }
      if ($a eq '--write') { $opt{write} = 1; next; }
      if ($a eq '--force') { $opt{force} = 1; next; }
      if ($a =~ /^--output=(.+)$/) { $opt{output} = $1; next; }
      if ($a eq '--output') { $opt{output} = shift(@args) // die "--output requires value\n"; next; }
      die "Unknown option '$a'\n" if $a =~ /^-/;
      push @ids, $a;
    }

    return $self->_announce_multi_sync(\%opt, @ids) if $opt{sync} || $opt{create};
    die "--dry-run only applies to --sync and --create\n" if $opt{dry_run};
    return $self->_announce_multi_status
      if !@ids && !$opt{write} && !$opt{force} && !defined $opt{output};

    die "announce-multi needs at least 2 CVEs; use 'announce $ids[0]' for a single CVE.\n" if @ids == 1;
    die "Usage: cna announce-multi <CVE-ID> <CVE-ID>... [--write|--output path] [--force]\n"
      . "       cna announce-multi [--create|--sync] [CVE-ID...] [--dry-run]\n" unless @ids >= 2;
    die "--write and --output cannot be combined\n" if $opt{write} && defined $opt{output};

    my ($text, $filename) = $self->_render_announce_multi(@ids);

    if (!$opt{write} && !defined $opt{output}) {
      binmode(STDOUT, ':encoding(UTF-8)');
      print $text;
      return 0;
    }

    my $out = $opt{output} // File::Spec->catfile('announce-multi', $filename);
    die "Refusing to overwrite $out: it is merged and records what was sent. Write a new batch instead, or pass --force.\n"
      if !$opt{force} && -e $out && $self->_git_path_exists_at_ref($self->_merged_ref, $out);
    if ($opt{write}) {
      # Merged batches are frozen, so an overlap can be legitimate: report it
      # and leave any cleanup to the operator.
      my @overlap = $self->_overlapping_batches($out, @ids);
      print STDERR "Note: other batch files also cover some of these CVEs (left untouched):\n",
        map("  $_\n", @overlap)
        if @overlap;
    }
    $self->_write_text_file($out, $text);
    print "Wrote $out\n";
    return 0;
  }

  method _write_text_file ($out, $text) {
    $self->_assert_encrypted_write_safe($out);
    my $dir = dirname($out);
    make_path($dir) unless -d $dir;
    open(my $fh, '>:encoding(UTF-8)', $out) or die "Cannot write $out: $!\n";
    print {$fh} $text;
    close($fh);
    return;
  }

  method _render_announce_multi (@ids) {
    my %seen;
    for my $id (@ids) {
      die "CVE must match CVE-YYYY-NNNN format\n" unless $id =~ /^CVE-\d{4}-\d{4,19}$/;
      die "Duplicate CVE ID $id\n" if $seen{$id}++;
    }
    my $multi = CPANSec::CVE::AnnounceMulti->new;
    my @cves = map { $self->_load_multi_cve5($_) } @ids;
    my $text = $multi->render(@cves);
    return ($text, batch_filename($multi->primary_distribution($cves[0]), @ids));
  }

  # Batches are public-only, like announce: they read cves/ and never touch
  # encrypted/, so no encrypted context is ever entered here.
  method _load_multi_cve5 ($cve) {
    die "Refusing multi-announcement: $cve is under encrypted/. Publish it to cves/ first.\n"
      if -f File::Spec->catfile('encrypted', "$cve.yaml");
    my $yaml = File::Spec->catfile('cves', "$cve.yaml");
    die "Cannot find YAML for $cve under cves/\n" unless -f $yaml;
    return CPANSec::CVE->from_yaml_file($yaml)->to_cve5_hash;
  }

  method _overlapping_batches ($path, @ids) {
    my %want = map { $_ => 1 } @ids;
    my @hits;
    for my $other (sort glob('announce-multi/*.txt')) {
      next if $other eq $path;
      my (undef, @covered) = parse_batch_filename(basename($other));
      my @shared = grep { $want{$_} } @covered;
      push @hits, "$other (" . join(', ', @shared) . ')' if @shared;
    }
    return @hits;
  }

  # CVEs new on this branch: $base_dir/<id>.yaml is in the working tree
  # (committed or not) but not on $ref.
  method _new_on_branch ($ref, $base_dir) {
    return sort_cve_ids(
      grep { !$self->_git_path_exists_at_ref($ref, "$base_dir/$_.yaml") }
      map { m{^\Q$base_dir\E/(CVE-\d{4}-\d{4,19})\.yaml$} ? $1 : () } glob("$base_dir/*.yaml")
    );
  }

  # The branch's own batches: unmerged batch files that name a CVE new on the branch.
  method _branch_batches ($ref) {
    my %branch = map { $_ => 1 } $self->_new_on_branch($ref, 'cves');
    return grep {
      my (undef, @covered) = parse_batch_filename(basename($_));
      !$self->_git_path_exists_at_ref($ref, $_) && grep { $branch{$_} } @covered;
    } sort glob('announce-multi/*.txt');
  }

  # Hints keep an opt-in batch current. They stay silent for people who never
  # batch (no announce-multi/ directory, no branch batch), in encrypted
  # contexts, and without a merged ref; they never change an exit code.
  method _hint_multi_after_init ($cve) {
    return if $encrypted_context || !-d 'announce-multi';
    my $ref = eval { $self->_existing_merged_ref } // return;
    my @batches = eval { $self->_branch_batches($ref) };
    return unless @batches;
    print STDERR "Note: this branch has an announce-multi batch; once $cve is filled in, "
      . "run: cpansec-cna announce-multi --sync\n";
  }

  method _hint_multi_out_of_date () {
    return if $encrypted_context || !-d 'announce-multi';
    my $ref = $self->_existing_merged_ref // return;
    my $plan = eval { $self->_sync_plan($ref, 0) } // return;
    return unless grep { /^(?:writes|removes) / } $self->_sync_plan_lines($plan);
    print STDERR "Note: this branch's announce-multi batch is out of date; run: cpansec-cna announce-multi --sync\n";
  }

  # Load @ids for batching, grouped by primary distribution:
  # ({ dist => [[id, cve5], ...] }, [[id, error], ...]).
  method _load_groups (@ids) {
    my $multi = CPANSec::CVE::AnnounceMulti->new;
    my (%groups, @invalid);
    for my $id (sort_cve_ids(uniq(@ids))) {
      my $cve = eval { $self->_load_multi_cve5($id) };
      my $err = $@;
      my $distribution = $cve ? $multi->primary_distribution($cve) : '';
      if (!length $distribution) {
        ($err ||= 'no primary distribution (affected[0].packageName)') =~ s/\s+\z//;
        push @invalid, [$id, $err];
        next;
      }
      push @{$groups{$distribution}}, [$id, $cve];
    }
    return (\%groups, \@invalid);
  }

  # What --sync and --create do: every distribution with 2+ CVEs (new on the
  # branch, plus @explicit, plus published CVEs the branch's batches already
  # include) is rendered as one batch, and the branch's own superseded batches
  # go. Batches are created for new distributions only under --create;
  # otherwise only distributions with an existing branch batch are updated. A
  # batch is the branch's own when it is unmerged and names a branch CVE;
  # merged batches and batches of already-published CVEs are left alone.
  # Published members of a branch batch are carried forward silently: one that
  # no longer loads is dropped (check reports that batch on its own).
  method _sync_plan ($ref, $create, @explicit) {
    my @branch = $self->_new_on_branch($ref, 'cves');
    my %branch = map { $_ => 1 } @branch;
    my %carried;
    for my $path (glob('announce-multi/*.txt')) {
      next if $self->_git_path_exists_at_ref($ref, $path);
      my (undef, @covered) = parse_batch_filename(basename($path));
      next unless grep { $branch{$_} } @covered;
      $carried{$_} = 1 for grep { !$branch{$_} && -f "cves/$_.yaml" } @covered;
    }
    my %explicit = map { $_ => 1 } @explicit;
    my ($groups, $invalid) = $self->_load_groups(@branch, @explicit, sort keys %carried);
    $invalid = [grep { $branch{$_->[0]} || $explicit{$_->[0]} } @$invalid];
    if (my ($bad) = grep { $explicit{$_->[0]} } @$invalid) {
      die "$bad->[0]: $bad->[1]\n";
    }

    my $multi = CPANSec::CVE::AnnounceMulti->new;
    # Distributions that already have a branch batch: --sync only updates these.
    my %has_batch;
    for my $path (sort glob('announce-multi/*.txt')) {
      next if $self->_git_path_exists_at_ref($ref, $path);
      my ($distribution, @covered) = parse_batch_filename(basename($path));
      $has_batch{$distribution} = 1 if defined $distribution && grep { $branch{$_} } @covered;
    }

    my (@batches, @singles, @uncreated);
    for my $distribution (sort keys %$groups) {
      my @members = $groups->{$distribution}->@*;
      if (@members < 2) {
        push @singles, [$distribution, $members[0][0]];
        next;
      }
      my @ids = map { $_->[0] } @members;
      my $path = File::Spec->catfile('announce-multi', batch_filename($distribution, @ids));
      my $merged = $self->_git_path_exists_at_ref($ref, $path);
      if (!$merged && !$create && !$has_batch{$distribution}) {
        push @uncreated, { distribution => $distribution, ids => \@ids, path => $path };
        next;
      }
      my $text = $multi->render(map { $_->[1] } @members);
      my $state = $merged ? 'merged'
        : (-f $path && _read_text_file($path) eq $text) ? 'unchanged'
        : 'write';
      push @batches, { distribution => $distribution, ids => \@ids, path => $path, text => $text, state => $state };
    }

    my %target = map { $_->{path} => 1 } @batches;
    my @removes;
    for my $path (sort glob('announce-multi/*.txt')) {
      next if $target{$path} || $self->_git_path_exists_at_ref($ref, $path);
      my (undef, @covered) = parse_batch_filename(basename($path));
      push @removes, $path if grep { $branch{$_} } @covered;
    }

    return {
      ref     => $ref,
      branch  => \@branch,
      invalid => $invalid,
      groups  => { map { $_ => [map { $_->[0] } $groups->{$_}->@*] } keys %$groups },
      batches => \@batches,
      singles => \@singles,
      removes => \@removes,
      uncreated => \@uncreated,
    };
  }

  method _sync_plan_lines ($plan) {
    my %verb = (write => 'writes', unchanged => 'unchanged', merged => 'already merged');
    my @lines = map { "$verb{$_->{state}} $_->{path}" } $plan->{batches}->@*;
    push @lines, map { "removes $_" } $plan->{removes}->@*;
    push @lines, map { "skips $_->[0]: only $_->[1] (a batch needs 2+ CVEs)" } $plan->{singles}->@*;
    push @lines, map { "not batched $_->{distribution}: " . join(', ', $_->{ids}->@*) . ' (opt in with --create)' }
      $plan->{uncreated}->@*;
    return @lines ? @lines : ('nothing to batch');
  }

  # Bare announce-multi: what the branch has, what its batches look like, and
  # what to run next. Changes nothing.
  method _announce_multi_status () {
    my $branch = eval { $self->_git_current_branch };
    print "Branch: $branch\n" if defined $branch;
    my $ref = $self->_existing_merged_ref;
    if (!defined $ref) {
      print "Cannot tell which CVEs are new on this branch: neither origin/main nor main exists.\n\n",
        "Next:\n  cpansec-cna announce-multi <CVE-ID> <CVE-ID>... --write\n";
      return 0;
    }
    print "Merged ref: $ref\n\n";

    my $plan = $self->_sync_plan($ref, 0);
    my %groups = $plan->{groups}->%*;
    my @invalid = $plan->{invalid}->@*;
    my $encrypted = () = $self->_new_on_branch($ref, 'encrypted');

    if (!%groups && !@invalid && !$encrypted) {
      print "New CVEs on this branch: none\n";
    } else {
      print "New CVEs on this branch:\n";
      my $width = max(map { length } keys %groups) // 0;
      for my $distribution (sort keys %groups) {
        my @ids = $groups{$distribution}->@*;
        printf "  %-*s  %s%s\n", $width, $distribution, join(', ', @ids),
          @ids == 1 ? ' (only one, nothing to batch)' : '';
      }
      print "  $_->[0]: cannot be loaded: $_->[1]\n" for @invalid;
      printf "  %d CVE%s under encrypted/ skipped (batches are public-only)\n", $encrypted, $encrypted == 1 ? '' : 's'
        if $encrypted;
    }

    my %branch = map { $_ => 1 } $plan->{branch}->@*;
    my @listed;
    for my $path (sort glob('announce-multi/*.txt')) {
      my $merged = $self->_git_path_exists_at_ref($ref, $path);
      my (undef, @covered) = parse_batch_filename(basename($path));
      next if $merged && !grep { $branch{$_} } @covered;
      push @listed, [$path, _batch_status($path, $plan, $merged, \%branch)];
    }
    if (@listed) {
      print "\nBatches:\n";
      print "  $_->[0]\n      $_->[1]\n" for @listed;
    }

    print "\nNext:\n";
    my @changes = grep { /^(?:writes|removes) / } $self->_sync_plan_lines($plan);
    my @uncreated = $plan->{uncreated}->@*;
    if (@invalid) {
      print "  Fix the CVEs that cannot be loaded, then sync.\n";
    }
    if (@changes) {
      print "  cpansec-cna announce-multi --sync\n", map("      $_\n", @changes);
    }
    if (@uncreated) {
      print "  cpansec-cna announce-multi --create   (batches are optional)\n",
        map("      writes $_->{path}\n", @uncreated);
    }
    if (!@invalid && !@changes && !@uncreated) {
      if (grep { $_->{state} eq 'unchanged' } $plan->{batches}->@*) {
        print "  All batches are in sync.\n  cpansec-cna check --changed\n";
      } else {
        print "  Nothing to batch from this branch. To batch already-published CVEs:\n",
          "  cpansec-cna announce-multi <CVE-ID> <CVE-ID>... --write\n";
      }
    }
    return 0;
  }

  method _announce_multi_sync ($opt, @explicit) {
    my $mode = $opt->{create} ? '--create' : '--sync';
    die "--output cannot be combined with $mode (it writes one file per distribution)\n" if defined $opt->{output};
    die "--force cannot be combined with $mode (it never overwrites merged batches)\n" if $opt->{force};
    my $ref = $self->_existing_merged_ref
      // die "Cannot tell which CVEs are new on this branch: neither origin/main nor main exists.\n";
    my $plan = $self->_sync_plan($ref, $opt->{create}, @explicit);
    my $apply = !$opt->{dry_run};

    if (my @bad = $plan->{invalid}->@*) {
      my $list = join('', map { "  $_->[0]: $_->[1]\n" } @bad);
      my $verb = $opt->{create} ? 'create' : 'sync';
      die "Cannot $verb: these CVEs cannot be loaded:\n$list" if $apply;
      print STDERR "Skipped (cannot be loaded):\n$list";
    }

    if (!$apply) {
      print "$mode would:\n", map("  $_\n", $self->_sync_plan_lines($plan));
      print "Run without --dry-run to apply.\n";
      return 0;
    }

    for my $batch ($plan->{batches}->@*) {
      if ($batch->{state} eq 'write') {
        $self->_write_text_file($batch->{path}, $batch->{text});
        print "Wrote $batch->{path}\n";
      } elsif ($batch->{state} eq 'unchanged') {
        print "Unchanged $batch->{path}\n";
      } else {
        print "Already merged $batch->{path}\n";
      }
    }
    for my $path ($plan->{removes}->@*) {
      unlink $path or die "Cannot remove $path: $!\n";
      print "Removed $path\n";
    }
    print "Skipped $_->[0]: only $_->[1] (a batch needs 2+ CVEs)\n" for $plan->{singles}->@*;
    print "Not batched $_->{distribution}: " . join(', ', $_->{ids}->@*) . " (opt in with --create)\n"
      for $plan->{uncreated}->@*;
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

    die "Usage: cna import [CVE-ID|path.json] [--force] [--no-guard]\n"
      unless @positionals <= 1;

    my $target = $positionals[0];
    if (!defined $target) {
      my $cve = $self->_default_cve_from_context
        // die "No CVE provided and no default found (set CPANSEC_CNA_CVE or use a CVE-prefixed branch name).\n";
      $target = $cve;
    }

    my ($json_path, $yaml_path) = $self->_resolve_import_paths($target);
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

  method _cmd_list_cves (@args) {
    my %opt = (branch => 0, ids => 0);
    for my $a (@args) {
      if ($a eq '--branch') { $opt{branch} = 1; next; }
      if ($a eq '--ids') { $opt{ids} = 1; next; }
      die "Unknown option '$a'\n" if $a =~ /^-/;
      die "Unexpected argument '$a'\n";
    }
    die "Usage: list-cves --branch [--ids]\n" unless $opt{branch};

    my $ref = $self->_existing_merged_ref
      // die "list-cves --branch needs origin/main or main to compare against.\n";
    my ($base) = $self->_run_cmd_capture('git', 'merge-base', 'HEAD', $ref);
    die "Cannot find where this branch split from $ref.\n" unless $base;
    chomp $base;

    my $by_id = $self->_branch_cve_changes($base);
    my @ids = sort_cve_ids(keys %$by_id);
    if ($opt{ids}) {
      say for @ids;
      return 0;
    }
    unless (@ids) {
      say "No CVEs changed on this branch (since $ref).";
      return 0;
    }
    for my $id (@ids) {
      say $id;
      say "  $_->[0] $_->[1]" for sort { $a->[1] cmp $b->[1] } $by_id->{$id}->@*;
    }
    return 0;
  }

  # CVE ID => [[status, path], ...] for every CVE file the working tree changes
  # against $base: git status letters (A, M, D, T), and ? for untracked files.
  # Batch files count for every CVE their name lists.
  method _branch_cve_changes ($base) {
    my @changes = map { chomp; [split /\t/, $_, 2] }
      $self->_run_cmd_capture('git', 'diff', '--name-status', '--no-renames', '--relative', $base, '--');
    push @changes, map { chomp; ['?', $_] }
      $self->_run_cmd_capture('git', 'ls-files', '--others', '--exclude-standard');

    my %by_id;
    for my $change (@changes) {
      my ($status, $path) = @$change;
      my @ids = $path =~ m{^(?:cves|encrypted)/(CVE-\d{4}-\d{4,19})\.(?:yaml|json)$}
        ? $1 : $path =~ m{^announce/(CVE-\d{4}-\d{4,19})\.txt$}
        ? $1 : $path =~ m{^reserved/(CVE-\d{4}-\d{4,19})$}
        ? $1 : $path =~ m{^announce-multi/([^/]+\.txt)$}
        ? do { my (undef, @covered) = parse_batch_filename($1); @covered }
        : ();
      push $by_id{$_}->@*, [substr($status, 0, 1), $path] for @ids;
    }
    return \%by_id;
  }

  method _cmd_edit (@args) {
    die "Usage: cna edit [CVE-ID]\n" unless @args <= 1;

    my $cve = $args[0] // $self->_default_cve_from_context
      // die "No CVE provided and no default found (set CPANSEC_CNA_CVE or use a CVE-prefixed branch name).\n";
    my $yaml = $self->_find_yaml_for_cve($cve);

    my $editor = (defined $ENV{VISUAL} && length $ENV{VISUAL})
      ? $ENV{VISUAL}
      : (defined $ENV{EDITOR} && length $ENV{EDITOR})
      ? $ENV{EDITOR}
      : 'vi';
    my @cmd = shellwords($editor);
    die "Invalid editor command in VISUAL/EDITOR\n" unless @cmd;
    push @cmd, $yaml;

    system(@cmd);
    my $rc = $? >> 8;
    die "Editor command failed ($rc): @cmd\n" if $rc != 0;
    return 0;
  }

  method _cmd_yaml_schema_path (@args) {
    die "Usage: cna yaml-schema-path\n" if @args;
    say CPANSec::CVE::YAML2CVE::bundled_schema_path();
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

  # A passing batch has no findings and would leave no trace, so name every
  # batch file that was checked.
  method _print_batch_results ($files, $findings_by_file) {
    for my $path (@$files) {
      my @findings = @{$findings_by_file->{$path} // []};
      my $errors = grep { ($_->{severity} // '') eq 'error' } @findings;
      my $warnings = @findings - $errors;
      print "Checked batch $path: ",
        (@findings ? "$errors error(s), $warnings warning(s)" : 'OK'), "\n";
    }
    return;
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

  method _merge_findings ($findings_by_file, $extra_findings) {
    for my $path (keys %$extra_findings) {
      $findings_by_file->{$path} ||= [];
      push @{$findings_by_file->{$path}}, @{$extra_findings->{$path}};
    }
    return;
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

  method _changed_paths () {
    my @cand = $self->_run_cmd_capture('git', 'diff', '--name-only', 'origin/main...HEAD');
    @cand = $self->_run_cmd_capture('git', 'diff', '--name-only', 'HEAD~1...HEAD') if !@cand;
    chomp @cand;
    return @cand;
  }

  method _changed_yaml_files () {
    my %seen;
    my @files;
    for my $f ($self->_changed_paths) {
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

  # A full check covers every batch file. A targeted or --changed check covers
  # batches naming a targeted CVE, plus (with --changed) batch files changed
  # on the branch.
  method _resolve_multi_check_targets ($cve, $changed, $yaml_files) {
    my @all = sort grep { -f $_ } glob('announce-multi/*.txt');
    my $targeted = defined $cve && length $cve;
    return @all unless $targeted || $changed;

    my %ids = map { m{(CVE-\d{4}-\d{4,19})\.yaml$}i ? ($1 => 1) : () } @$yaml_files;
    $ids{$cve} = 1 if $targeted;
    my %changed_batch;
    if ($changed) {
      $changed_batch{$_} = 1 for grep { m{^announce-multi/[^/]+\.txt$} } $self->_changed_paths;
    }
    return grep { $changed_batch{$_} || _batch_covers($_, \%ids) } @all;
  }

  # $merged_ref is where a batch counts as merged: the PR base under
  # --pr-policy, _merged_ref otherwise.
  method _announce_multi_findings ($files, $merged_ref) {
    my %findings_by_file;
    my $errors = 0;
    for my $path (@$files) {
      my @findings = map {
        +{ severity => 'error', id => $_->[0], message => $_->[1], path => $path, line => 1 }
      } $self->_multi_file_problems($path, $merged_ref);
      $findings_by_file{$path} = \@findings;
      $errors += @findings;
    }
    return (\%findings_by_file, $errors);
  }

  # Advisory: a batch that is the branch's own (unmerged, naming a branch CVE)
  # should name every branch CVE of its distribution. Batches stay optional, so
  # nothing fires without one.
  method _multi_incomplete_findings ($files, $ref) {
    my @branch = $self->_new_on_branch($ref, 'cves');
    my %branch = map { $_ => 1 } @branch;
    my ($groups) = $self->_load_groups(@branch);
    my %findings_by_file;
    my $warnings = 0;
    for my $path (@$files) {
      next if $self->_git_path_exists_at_ref($ref, $path);
      my ($distribution, @ids) = parse_batch_filename(basename($path));
      next unless defined $distribution && grep { $branch{$_} } @ids;
      my %have = map { $_ => 1 } @ids;
      my @missing = grep { !$have{$_} } map { $_->[0] } @{$groups->{$distribution} // []};
      next unless @missing;
      push @{$findings_by_file{$path}}, {
        severity => 'warning',
        id       => 'multi_incomplete',
        message  => "$path leaves out " . join(', ', @missing)
          . ", new on this branch for $distribution; run announce-multi --sync.",
        path     => $path,
        line     => 1,
      };
      $warnings++;
    }
    return (\%findings_by_file, $warnings);
  }

  # Where a batch counts as merged when not under --pr-policy. CI checkouts
  # usually have origin/main but no local main, matching _changed_paths.
  method _merged_ref () {
    my ($rc) = $self->_run_cmd_capture_with_rc('git', 'rev-parse', '--verify', '--quiet', 'origin/main');
    return defined($rc) && $rc == 0 ? 'origin/main' : 'main';
  }

  # origin/main, else main, but only a ref that exists.
  method _existing_merged_ref () {
    for my $ref (qw(origin/main main)) {
      my ($rc) = $self->_run_cmd_capture_with_rc('git', 'rev-parse', '--verify', '--quiet', $ref);
      return $ref if defined($rc) && $rc == 0;
    }
    return undef;
  }

  # Without a merged ref every batch is checked as unmerged; say so once
  # (shallow CI checkouts). Outside a git work tree nothing is merged.
  method _warn_if_no_merged_ref () {
    my ($rc) = $self->_run_cmd_capture_with_rc('git', 'rev-parse', '--is-inside-work-tree');
    return unless defined($rc) && $rc == 0;
    return if defined $self->_existing_merged_ref;
    print STDERR "Warning: neither origin/main nor main exists; merged announce-multi batches cannot be recognised "
      . "and are checked as unmerged (fetch with fetch-depth: 0).\n";
  }

  # Problems as [finding id, message] pairs. A merged batch is a record of what
  # was sent: published CVEs can be updated (or even re-ordered or rejected)
  # later, and renaming it is forbidden, so once merged it only needs a name
  # that parses and names at least 2 distinct CVEs.
  method _multi_file_problems ($path, $merged_ref) {
    my $name = basename($path);
    my ($distribution, @ids) = parse_batch_filename($name);
    return ['multi_filename', "$name is not a valid announce-multi filename (expected <Distribution>--CVE-YYYY-NNNN+NNNN.txt)."]
      unless defined $distribution;
    my %seen;
    return ['multi_filename', "$name must name at least 2 distinct CVE IDs."]
      if @ids < 2 || grep { $seen{$_}++ } @ids;

    return () if $self->_git_path_exists_at_ref($merged_ref, $path);

    my @problems;
    my $canonical = batch_filename($distribution, @ids);
    push @problems, ['multi_filename', "$name is not in canonical form; expected $canonical."]
      if $name ne $canonical;

    my @cves;
    for my $id (@ids) {
      if (-f File::Spec->catfile('encrypted', "$id.yaml")) {
        push @problems, ['multi_cve_missing', "$id resolves to encrypted/; batches may only contain published CVEs under cves/."];
      } elsif (!-f File::Spec->catfile('cves', "$id.yaml")) {
        push @problems, ['multi_cve_missing', "$id has no YAML under cves/."];
      } elsif (my $cve = eval { $self->_load_multi_cve5($id) }) {
        push @cves, $cve;
      } else {
        (my $err = $@) =~ s/\s+\z//;
        push @problems, ['multi_cve_invalid', "$id cannot be rendered: $err"];
      }
    }
    return @problems if @cves != @ids;

    my $multi = CPANSec::CVE::AnnounceMulti->new;
    my @off = grep { $multi->primary_distribution($_) ne $distribution } @cves;
    if (@off) {
      my $list = join(', ', map { "$_->{cveMetadata}{cveId} (" . $multi->primary_distribution($_) . ')' } @off);
      return @problems, ['multi_distribution',
        "Every CVE must have primary distribution $distribution (from the filename); differs for $list."];
    }

    push @problems, ['multi_mismatch', "$path does not match generated announce-multi output; regenerate it with: "
      . "cpansec-cna announce-multi --sync (branch batches) or announce-multi @ids --write."]
      if $multi->render(@cves) ne _read_text_file($path);
    return @problems;
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

    my $branch = eval { $self->_git_current_branch };   # any failure (outside git, detached HEAD) just means no branch hint
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

    # Refuse explicitly (without entering encrypted context / contacting the
    # network) when the only local source is an encrypted/ record. Mirrors the
    # announce command, which also declines encrypted sources.
    my @encrypted = grep { -f $_ } (
      File::Spec->catfile('encrypted', "$cve.yaml"),
      File::Spec->catfile('encrypted', "$cve.json"),
    );
    die "Refusing reconcile for encrypted CVE source ($encrypted[0]); publish it to cves/ first.\n"
      if @encrypted;

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

  # A batch file on the base is frozen, like announce/<CVE>.txt. New batch
  # files are always allowed, so only base-side files are examined. $ids limits
  # this to batches naming those CVEs; undef means every batch.
  method _pr_policy_announce_multi_findings ($base_sha, $ids) {
    my %findings_by_file;
    my $errors = 0;
    for my $path ($self->_run_cmd_capture('git', 'ls-tree', '--name-only', $base_sha, '--', 'announce-multi/')) {
      chomp $path;
      next unless $path =~ m{^announce-multi/[^/]+\.txt$};
      next if $ids && !_batch_covers($path, $ids);

      my $message;
      if (!-f $path) {
        $message = "$path must not be removed once merged.";
      } elsif ($self->_git_show_text_at_ref($base_sha, $path) ne _read_text_file($path)) {
        $message = "$path must not change once merged.";
      }
      next unless defined $message;

      push @{$findings_by_file{$path}}, {
        severity => 'error', id => 'multi_not_allowed', message => $message, path => $path, line => 1,
      };
      $errors++;
    }
    return (\%findings_by_file, $errors);
  }

  method _pr_policy_announce_findings ($yaml_files, $base_sha) {
    my ($check_rc) = $self->_run_cmd_capture_with_rc('git', 'rev-parse', '--verify', '--quiet', "$base_sha^{commit}");
    die "Invalid --base-sha '$base_sha' (not a known git commit)\n"
      if !defined($check_rc) || $check_rc != 0;

    my %findings_by_file;
    my ($errors, $warnings) = (0, 0);

    for my $yaml (@$yaml_files) {
      next unless $yaml =~ m{^cves/(CVE-\d{4}-\d{4,19})\.yaml$}i;
      my $cve = $1;
      my $announce_path = File::Spec->catfile('announce', "$cve.txt");

      my $exists_in_base = $self->_git_path_exists_at_ref($base_sha, File::Spec->catfile('cves', "$cve.yaml"))
        || $self->_git_path_exists_at_ref($base_sha, File::Spec->catfile('cves', "$cve.json"));
      my $announce_in_base = $self->_git_path_exists_at_ref($base_sha, $announce_path);
      my $announce_now = -f $announce_path ? 1 : 0;

      if (!$exists_in_base) {
        if (!$announce_now) {
          my $f = {
            severity => 'error',
            id => 'announce_missing',
            message => "New CVE $cve must include $announce_path in this PR.",
            path => $yaml,
            line => 1,
          };
          push @{$findings_by_file{$yaml}}, $f;
          $errors++;
          next;
        }

        my ($generated, $source_yaml) = $self->_render_announce_text($cve);
        my $actual = _read_text_file($announce_path);
        if ($generated ne $actual) {
          my $f = {
            severity => 'error',
            id => 'announce_mismatch',
            message => "$announce_path does not match generated announce output from $source_yaml.",
            path => $announce_path,
            line => 1,
          };
          push @{$findings_by_file{$announce_path}}, $f;
          $errors++;
        }
        next;
      }

      if (!$announce_in_base && $announce_now) {
        my $f = {
          severity => 'error',
          id => 'announce_not_allowed',
          message => "$announce_path must not be added for existing CVE $cve.",
          path => $announce_path,
          line => 1,
        };
        push @{$findings_by_file{$announce_path}}, $f;
        $errors++;
        next;
      }

      if ($announce_in_base && !$announce_now) {
        my $f = {
          severity => 'error',
          id => 'announce_not_allowed',
          message => "$announce_path must not be removed for existing CVE $cve.",
          path => $yaml,
          line => 1,
        };
        push @{$findings_by_file{$yaml}}, $f;
        $errors++;
        next;
      }

      if ($announce_in_base && $announce_now) {
        my $base_text = $self->_git_show_text_at_ref($base_sha, $announce_path);
        my $head_text = _read_text_file($announce_path);
        if ($base_text ne $head_text) {
          my $f = {
            severity => 'error',
            id => 'announce_not_allowed',
            message => "$announce_path must not change for existing CVE $cve.",
            path => $announce_path,
            line => 1,
          };
          push @{$findings_by_file{$announce_path}}, $f;
          $errors++;
        }
      }
    }

    return (\%findings_by_file, $errors, $warnings);
  }

  method _git_path_exists_at_ref ($ref, $path) {
    my ($rc) = $self->_run_cmd_capture_with_rc('git', 'rev-parse', '--verify', '--quiet', "$ref:$path");
    return defined($rc) && $rc == 0 ? 1 : 0;
  }

  method _git_show_text_at_ref ($ref, $path) {
    my ($rc, @out) = $self->_run_cmd_capture_with_rc('git', 'show', "$ref:$path");
    die "Cannot read $path at git ref $ref\n"
      if !defined($rc) || $rc != 0;
    # git show output is captured as raw bytes; decode so it compares
    # consistently with _read_text_file / _render_announce_text (decoded strings).
    return decode('UTF-8', join('', @out));
  }

  method _yaml_stub (%in) {
    my $repo = defined($in{repo}) && length($in{repo}) ? $in{repo} : 'https://example.invalid/TODO-repo';
    return sprintf <<'YAML', $in{cve}, $in{distribution}, $in{module}, $repo, $in{module}, $in{module};
# yaml-language-server: $schema=../schema/cpansec-cna-schema-01.yaml
cpansec:
  cve: %s
  distribution: %s
  module: %s
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

sub _read_text_file ($path) {
  open(my $fh, '<:encoding(UTF-8)', $path) or die "Cannot read $path: $!\n";
  local $/;
  my $txt = <$fh>;
  close($fh);
  return $txt // '';
}

sub _batch_covers ($path, $ids) {
  my (undef, @covered) = parse_batch_filename(basename($path));
  return scalar grep { $ids->{$_} } @covered;
}

sub _batch_status ($path, $plan, $merged, $branch) {
  return 'merged (frozen)' if $merged;
  my ($distribution, @ids) = parse_batch_filename(basename($path));
  return 'unmerged, filename does not parse' unless defined $distribution;
  return 'unmerged, not tied to this branch (left alone by --sync)' unless grep { $branch->{$_} } @ids;
  my ($target) = grep { $_->{distribution} eq $distribution } $plan->{batches}->@*;
  return 'unmerged, out of sync: --sync removes it' unless $target;
  if ($target->{path} eq $path) {
    return $target->{state} eq 'unchanged' ? 'unmerged, in sync' : 'unmerged, stale: content out of date';
  }
  my %have = map { $_ => 1 } @ids;
  my @missing = grep { !$have{$_} } $target->{ids}->@*;
  return @missing
    ? 'unmerged, out of sync: missing ' . join(', ', @missing)
    : "unmerged, out of sync: --sync replaces it with $target->{path}";
}

sub _normalize_cna_for_reconcile ($cna) {
  my $copy = dclone($cna);

  # Reconciliation should focus on published vulnerability content, not
  # provider metadata maintained by CVE Services.
  delete $copy->{providerMetadata};

  # Likewise the generator stamp: it identifies the build that produced the
  # record, so it changes with every commit to this tool and would otherwise
  # report a difference for every record that was published by an older build.
  delete $copy->{x_generator};

  return $copy;
}

1;
