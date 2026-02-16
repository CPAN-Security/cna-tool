package CPANSec::CVE::YAML2CVE;

use v5.42;
use feature qw(class);
no warnings qw(experimental::class);

use CPAN::Meta::YAML ();
use CPANSec::CNA ();
use CPANSec::CVE::Model ();
use CPANSec::CVE::VersionPhrase qw(template_version_range_from_affected);
use Cwd qw(abs_path);
use File::Basename qw(dirname);
use File::Spec ();
use JSON::PP ();
use JSON::Validator ();

sub default_schema_path () {
  my $root_schema = File::Spec->catfile("schema", "cpansec-cna-schema-01.yaml");
  return $root_schema if -f $root_schema;
  return File::Spec->catfile(_module_project_root(), "schema", "cpansec-cna-schema-01.yaml");
}

sub default_cve_schema_path () {
  if (defined $ENV{CPANSEC_CNA_CVE_SCHEMA} && length $ENV{CPANSEC_CNA_CVE_SCHEMA}) {
    return $ENV{CPANSEC_CNA_CVE_SCHEMA};
  }

  my $submodule_schema = File::Spec->catfile("cve-schema", "schema", "CVE_Record_Format.json");
  return $submodule_schema if -f $submodule_schema;

  my $root_schema = File::Spec->catfile("cve-record-format-5.2.0.json");
  return $root_schema if -f $root_schema;

  my $module_submodule = File::Spec->catfile(_module_project_root(), "cve-schema", "schema", "CVE_Record_Format.json");
  return $module_submodule if -f $module_submodule;

  return File::Spec->catfile(_module_project_root(), "cve-record-format-5.2.0.json");
}

sub _module_project_root () {
  return abs_path(File::Spec->catdir(dirname(__FILE__), "..", "..", ".."));
}

class CPANSec::CVE::YAML2CVE {
  field $schema_file :param = default_schema_path();
  field $cve_schema_file :param = default_cve_schema_path();
  field $assigner_org_id :param = "00000000-0000-4000-9000-000000000000";

  method schema_file () { return $schema_file; }
  method cve_schema_file () { return $cve_schema_file; }

  method validate_yaml_file ($infile) {
    $self->_read_and_validate_yaml($infile);
    return;
  }

  method load_yaml_model ($infile) {
    my ($doc) = $self->_read_and_validate_yaml($infile);
    die "Top-level 'cpansec' object is required\n"
      unless ref($doc) eq 'HASH' && ref($doc->{cpansec}) eq 'HASH';

    return CPANSec::CVE::Model->new(
      cpansec => $doc->{cpansec},
      source_file => $infile,
    );
  }

  method convert_model ($model, %opts) {
    my $cna_only = $opts{cna_only} ? 1 : 0;
    die "convert_model expects CPANSec::CVE::Model\n"
      unless eval { $model->isa('CPANSec::CVE::Model') };

    my $json_obj = $self->_convert_cpansec_to_json($model->cpansec, $cna_only);
    $self->_validate_output_cve_schema($json_obj, !$cna_only);
    return $json_obj;
  }

  method convert_yaml_file ($infile, %opts) {
    my $model = $self->load_yaml_model($infile);
    return $self->convert_model($model, %opts);
  }

  method convert_yaml_file_to_json ($infile, %opts) {
    my $json_obj = $self->convert_yaml_file($infile, %opts);
    return $self->encode_json($json_obj);
  }

  method encode_json ($json_obj) {
    my $json = JSON::PP->new->utf8->pretty->canonical;
    return $json->encode($json_obj);
  }

  method _read_and_validate_yaml ($infile) {
    open(my $in, '<:encoding(UTF-8)', $infile) or die "Cannot read $infile: $!\n";
    local $/;
    my $yaml_text = <$in>;
    close($in);
    $yaml_text = _normalize_empty_literal_blocks($yaml_text // '');

    my $yaml_docs = CPAN::Meta::YAML->read_string($yaml_text)
      or die "Failed to parse YAML from $infile\n";
    my $schema_docs = CPAN::Meta::YAML->read($schema_file)
      or die "Failed to parse schema YAML from $schema_file\n";

    my $doc = $yaml_docs->[0];
    my $schema = $schema_docs->[0];

    $doc = coerce_for_schema($doc, $schema);
    validate_schema($doc, $schema);

    return ($doc, $schema);
  }

  method _convert_cpansec_to_json ($in, $cna_only) {
    die "cpansec model data must be a hash\n" unless ref($in) eq 'HASH';

    my $cve_id = $in->{cve};

    my $title = normalize_single_line(_interpolate_templates($in, $in->{title}, 'cpansec.title'));
    my $description = normalize_prose_text(_interpolate_templates($in, $in->{description}, 'cpansec.description'));

    my %affected = (
      collectionURL  => "https://cpan.org/modules",
      defaultStatus  => "unaffected",
      packageName    => $in->{distribution},
      product        => $in->{module},
      vendor         => $in->{author},
      versions       => [ map { parse_affected_version($_) } @{array_ref($in->{affected}, "cpansec.affected")} ],
    );

    $affected{repo} = $in->{repo} if defined $in->{repo} && length $in->{repo};
    $affected{programFiles} = [ @{array_ref($in->{files}, "cpansec.files")} ]
      if exists $in->{files};
    if (exists $in->{routines}) {
      $affected{programRoutines} = [
        map { +{ name => $_ } } @{array_ref($in->{routines}, "cpansec.routines")}
      ];
    }

    my %cna = (
      affected => [ \%affected ],
      descriptions => [
        {
          lang => "en",
          value => $description,
        }
      ],
      providerMetadata => {
        orgId => $assigner_org_id,
      },
      references => [
        map {
          my $ref = $_;
          my %out = ( url => $ref->{link} );
          $out{name} = $ref->{name} if exists $ref->{name};
          $out{tags} = normalize_tags($ref->{tags}) if exists $ref->{tags};
          \%out;
        } @{reference_list($in->{references})}
      ],
      source => {
        discovery => "UNKNOWN",
      },
      title => $title,
      x_generator => {
        engine => "cpansec-cna-tool " . CPANSec::CNA->VERSION,
      },
    );

    if (exists $in->{cwes}) {
      $cna{problemTypes} = [
        map { cwe_to_problem_type($_) } @{array_ref($in->{cwes}, "cpansec.cwes")}
      ];
    }

    if (exists $in->{solution}) {
      my @vals = grep { defined($_) && $_ =~ /\S/ }
        map { normalize_prose_text($_) } @{string_or_array($in->{solution}, "cpansec.solution")};
      if (@vals) {
        $cna{solutions} = [ map { text_entry($_) } @vals ];
      }
    }

    if (exists $in->{mitigation}) {
      my @vals = grep { defined($_) && $_ =~ /\S/ }
        map { normalize_prose_text($_) } @{string_or_array($in->{mitigation}, "cpansec.mitigation")};
      if (@vals) {
        $cna{workarounds} = [ map { text_entry($_) } @vals ];
      }
    }

    if (exists $in->{credits}) {
      my $credits = array_ref($in->{credits}, "cpansec.credits");
      $cna{credits} = [
        map { credit_entry($_) } @$credits
      ];
    }

    if (exists $in->{impacts}) {
      $cna{impacts} = [
        map { impact_entry($_) } @{array_ref($in->{impacts}, "cpansec.impacts")}
      ];
    }

    if (exists $in->{timeline}) {
      my $timeline = array_ref($in->{timeline}, "cpansec.timeline");
      $cna{timeline} = [
        map { timeline_entry($_) } @$timeline
      ];
    }

    return $cna_only
      ? \%cna
      : {
          dataType => "CVE_RECORD",
          dataVersion => "5.1",
          cveMetadata => {
            assignerOrgId => $assigner_org_id,
            cveId => $cve_id,
            requesterUserId => $assigner_org_id,
            serial => 1,
            state => "PUBLISHED",
          },
          containers => {
            cna => \%cna,
          },
        };
  }

  method _validate_output_cve_schema ($json_obj, $full_record) {
    die "CVE output schema not found at '$cve_schema_file' (use --cve-schema)\n"
      unless -f $cve_schema_file;

    open(my $fh, "<", $cve_schema_file) or die "Cannot read CVE schema '$cve_schema_file': $!\n";
    local $/;
    my $schema_text = <$fh>;
    close($fh);

    my $schema = JSON::PP::decode_json($schema_text);
    my $schema_path = abs_path($cve_schema_file) // $cve_schema_file;
    $schema = normalize_cve_schema_refs($schema, $schema_path);

    my $jv = JSON::Validator->new;
    my $target_schema = $full_record ? $schema : {
      '$schema'     => $schema->{'$schema'},
      '$id'         => $schema->{'$id'},
      definitions   => $schema->{definitions},
      '$ref'        => '#/definitions/cnaPublishedContainer',
    };
    $jv->schema($target_schema);
    my @errors = $jv->validate($json_obj);
    if (@errors) {
      my @lines = map {
        my $path = eval { $_->path } // '$';
        my $msg  = eval { $_->message } // "$_";
        "$path $msg";
      } @errors;
      die "Generated JSON failed CVE schema validation:\n" . join("\n", @lines) . "\n";
    }
  }
}

sub _normalize_empty_literal_blocks ($text) {
  # CPAN::Meta::YAML rejects truly empty literal blocks. Allow common optional
  # keys to be written as `key: |` with no content by normalizing to empty strings.
  my $out = $text;
  $out =~ s{
    ^([ \t]*)(solution|mitigation):\s*\|[+-]?\s*\n
    (?:(^\1[ \t]*\n))*
    (?=^\1[^\s]|\z)
  }{$1$2: ""\n}gmx;
  return $out;
}

sub array_ref ($value, $name) {
  die "$name must be an array\n" unless ref($value) eq "ARRAY";
  return $value;
}

sub reference_list ($value) {
  my $refs = array_ref($value, "cpansec.references");
  for my $r (@$refs) {
    die "cpansec.references entries must be objects\n" unless ref($r) eq "HASH";
    die "cpansec.references[].link is required\n"
      unless defined $r->{link} && length $r->{link};
    if (exists $r->{name}) {
      die "cpansec.references[].name must be a string\n" if ref($r->{name});
      die "cpansec.references[].name cannot be empty\n" unless length $r->{name};
    }
  }
  return $refs;
}

sub parse_affected_version ($expr) {
  die "cpansec.affected entries must be non-empty strings\n"
    unless defined $expr && !ref($expr) && $expr =~ /\S/;

  $expr =~ s/^\s+|\s+$//g;

  # Range: "<from> <= <to>" or "<from> < <to>"
  if ($expr =~ /^(\S+)\s*(<=|<)\s*(\S+)$/) {
    my ($from, $op, $to) = ($1, $2, $3);
    my %v = (versionType => "custom", status => "affected", version => $from);
    $v{$op eq "<=" ? "lessThanOrEqual" : "lessThan"} = $to;
    return \%v;
  }

  # Upper bound only: "<= <to>" or "< <to>"
  if ($expr =~ /^(<=|<)\s*(\S+)$/) {
    my ($op, $to) = ($1, $2);
    my %v = (versionType => "custom", status => "affected", version => "0");
    $v{$op eq "<=" ? "lessThanOrEqual" : "lessThan"} = $to;
    return \%v;
  }

  # Exact version
  return {
    versionType => "custom",
    status      => "affected",
    version     => $expr,
  };
}

sub normalize_tags ($tags) {
  my %legacy_map = (
    advisory => 'vendor-advisory',
    misc     => 'related',
  );

  my %allowed = map { $_ => 1 } qw(
    broken-link customer-entitlement exploit government-resource issue-tracking
    mailing-list mitigation not-applicable patch permissions-required media-coverage
    product related release-notes signature technical-description third-party-advisory
    vendor-advisory vdb-entry
  );

  my $normalize = sub ($tag) {
    my $t = defined($tag) ? "$tag" : "";
    $t =~ s/^\s+|\s+$//g;
    $t = lc $t;
    $t = $legacy_map{$t} if exists $legacy_map{$t};
    return $t;
  };

  my $finalize = sub ($items) {
    my %seen;
    my @out;
    for my $raw (@$items) {
      my $t = $normalize->($raw);
      next unless length $t;
      die "cpansec.references[].tags contains unsupported tag '$t'\n"
        unless $allowed{$t};
      next if $seen{$t}++;
      push @out, $t;
    }
    return \@out;
  };

  if (ref($tags) eq "ARRAY") {
    return $finalize->($tags);
  }

  if (!ref($tags)) {
    my $raw = $tags // "";
    $raw =~ s/^\s+|\s+$//g;
    if ($raw =~ /^\[(.*)\]$/) {
      my $inner = $1;
      my @items = grep { length $_ } map {
        my $x = $_;
        $x =~ s/^\s+|\s+$//g;
        $x =~ s/^['"]|['"]$//g;
        $x;
      } split(/\s*,\s*/, $inner);
      return $finalize->(\@items);
    }
    return $finalize->([ $raw ]);
  }

  die "cpansec.references[].tags must be an array or string\n";
}

sub cwe_to_problem_type ($entry) {
  die "cpansec.cwes entries must be strings\n" if ref($entry);
  $entry =~ /^(CWE-\d+)(?:\s*:\s*|\s+)(.+)$/
    or die "Invalid CWE entry: '$entry' (expected: 'CWE-123 description' or 'CWE-123: description')\n";

  return {
    descriptions => [
      {
        type        => "CWE",
        lang        => "en",
        cweId       => $1,
        description => "$1 $2",
      }
    ],
  };
}

sub text_entry ($text) {
  return {
    lang => "en",
    value => $text,
  };
}

sub normalize_text ($text) {
  die "Expected a string field\n" if ref($text);
  $text //= "";
  $text =~ s/\r\n?/\n/g;
  $text =~ s/\s+\z//;
  return $text;
}

sub normalize_prose_text ($text) {
  $text = normalize_text($text);
  return $text unless length $text;

  my @segments;
  my @current;
  my $mode = '';
  my $flush = sub {
    return unless @current;
    push @segments, { mode => $mode, lines => [ @current ] };
    @current = ();
  };

  for my $line (split /\n/, $text) {
    if ($line =~ /^\s*$/) {
      $flush->();
      $mode = '';
      next;
    }

    my $line_mode = $line =~ /^\s/ ? 'pre' : 'prose';
    if (!$mode) {
      $mode = $line_mode;
    } elsif ($mode ne $line_mode) {
      $flush->();
      $mode = $line_mode;
    }
    push @current, $line;
  }
  $flush->();

  my @out;
  for my $seg (@segments) {
    if ($seg->{mode} eq 'pre') {
      push @out, join("\n", @{$seg->{lines}});
    } else {
      my @lines = map {
        my $x = $_;
        $x =~ s/^\s+|\s+$//g;
        $x;
      } @{$seg->{lines}};
      push @out, join(' ', grep { length $_ } @lines);
    }
  }

  return join("\n\n", @out);
}

sub _interpolate_templates ($cpansec, $text, $field) {
  return $text if !defined $text || ref($text);

  my $out = $text;
  $out =~ s/(\{\{\s*([^{}]+?)\s*\}\})/_resolve_template_token($cpansec, $1, $2, $field)/ge;

  if ($out =~ /\{\{|\}\}/) {
    warn "$field contains unmatched template delimiters\n";
  }

  return $out;
}

sub _resolve_template_token ($cpansec, $full_token, $token_raw, $field) {
  my $token = $token_raw;
  $token =~ s/^\s+|\s+$//g;
  if ($token eq 'VERSION_RANGE') {
    my $phrase = template_version_range_from_affected($cpansec->{affected});
    if (!length $phrase) {
      warn "$field contains {{VERSION_RANGE}} but no version range could be derived from cpansec.affected\n";
      return $full_token;
    }
    return $phrase;
  }

  warn "$field contains unsupported template token {{$token}}\n";
  return $full_token;
}

sub string_or_array ($value, $name) {
  if (ref($value) eq "ARRAY") {
    return $value;
  }
  if (!ref($value)) {
    return [ $value ];
  }
  die "$name must be a string or array of strings\n";
}

sub normalize_single_line ($text) {
  $text = normalize_text($text);
  $text =~ s/\s+/ /g;
  return $text;
}

sub credit_entry ($entry) {
  die "cpansec.credits entries must be objects\n" unless ref($entry) eq "HASH";
  die "cpansec.credits[].type is required\n" unless defined $entry->{type} && length $entry->{type};
  die "cpansec.credits[].value is required\n" unless defined $entry->{value} && length $entry->{value};
  return {
    lang  => $entry->{lang} // "en",
    type  => $entry->{type},
    value => $entry->{value},
  };
}

sub impact_entry ($entry) {
  die "cpansec.impacts entries must be strings\n" if ref($entry);
  $entry =~ /^(CAPEC-\d+)\s+(.+)$/
    or die "Invalid impact entry: '$entry' (expected: 'CAPEC-123 description')\n";

  return {
    capecId => $1,
    descriptions => [
      {
        lang  => "en",
        value => "$1 $2",
      }
    ],
  };
}

sub timeline_entry ($entry) {
  die "cpansec.timeline entries must be objects\n" unless ref($entry) eq "HASH";
  die "cpansec.timeline[].time is required\n" unless defined $entry->{time} && length $entry->{time};
  die "cpansec.timeline[].value is required\n" unless defined $entry->{value} && length $entry->{value};
  my $time = $entry->{time};
  $time =~ s/^\s+|\s+$//g;
  if ($time =~ /^\d{4}-\d{2}-\d{2}$/) {
    $time .= "T00:00:00Z";
  }
  return {
    lang  => $entry->{lang} // "en",
    time  => $time,
    value => $entry->{value},
  };
}

sub coerce_for_schema ($data, $schema) {
  return $data unless ref($schema) eq 'HASH';

  my $type = $schema->{type} // '';

  if ($type eq 'array') {
    if (!ref($data)) {
      my $raw = $data // "";
      $raw =~ s/^\s+|\s+$//g;
      if ($raw =~ /^\[(.*)\]$/) {
        my $inner = $1;
        my @items = grep { length $_ } map {
          my $x = $_;
          $x =~ s/^\s+|\s+$//g;
          $x =~ s/^['"]|['"]$//g;
          $x;
        } split(/\s*,\s*/, $inner);
        my $item_schema = $schema->{items};
        return [ map { coerce_for_schema($_, $item_schema) } @items ];
      }
    }
    if (ref($data) eq 'ARRAY' && ref($schema->{items}) eq 'HASH') {
      my $item_schema = $schema->{items};
      for my $i (0 .. $#$data) {
        $data->[$i] = coerce_for_schema($data->[$i], $item_schema);
      }
    }
    return $data;
  }

  if ($type eq 'object' && ref($data) eq 'HASH' && ref($schema->{properties}) eq 'HASH') {
    my $props = $schema->{properties};
    for my $k (keys %$props) {
      next unless exists $data->{$k};
      $data->{$k} = coerce_for_schema($data->{$k}, $props->{$k});
    }
  }

  return $data;
}

sub validate_schema ($data, $schema) {
  my $jv = JSON::Validator->new;
  $jv->schema($schema);
  my @errors = $jv->validate($data);
  if (@errors) {
    my @lines = map {
      my $path = eval { $_->path } // '$';
      my $msg  = eval { $_->message } // "$_";
      "$path $msg";
    } @errors;
    die join("\n", @lines) . "\n";
  }
}

sub normalize_cve_schema_refs ($schema, $schema_path) {
  # Treat local schema file as canonical base id and normalize file:refs used by upstream.
  if ($schema_path =~ m{^/}) {
    $schema->{'$id'} = "file://$schema_path";
  }

  rewrite_schema_refs($schema);
  return $schema;
}

sub rewrite_schema_refs ($node) {
  if (ref($node) eq "HASH") {
    if (exists $node->{'$ref'} && !ref($node->{'$ref'})) {
      my $r = $node->{'$ref'};
      if ($r =~ m{^file:(tags|imports)/}) {
        $r =~ s{^file:}{};
        $node->{'$ref'} = $r;
      }
    }
    rewrite_schema_refs($_) for values %$node;
    return;
  }

  if (ref($node) eq "ARRAY") {
    rewrite_schema_refs($_) for @$node;
  }
}

1;
