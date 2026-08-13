package CPANSec::CVE::CVE2YAML;

use v5.42;
use feature qw(class);
no warnings qw(experimental::class);

use CPANSec::CVE::YAML2CVE ();
use File::Temp qw(tempfile);
use JSON::PP qw(decode_json);
use YAML::PP ();
use YAML::PP::Common qw(PRESERVE_ORDER);

class CPANSec::CVE::CVE2YAML {
  field $yaml2cve :param = CPANSec::CVE::YAML2CVE->new;
  field $yaml_schema_hint :param = '# yaml-language-server: $schema=../schema/cpansec-cna-schema-01.yaml';

  method convert_json_file_to_yaml ($json_path, %opts) {
    my $guard = exists $opts{guard} ? $opts{guard} : 1;
    my $doc = _read_json_file($json_path);
    my $cpansec = $self->convert_cve_doc_to_cpansec($doc);

    my $yaml = $self->encode_cpansec_yaml($cpansec);

    if ($guard) {
      my ($fh, $tmp) = tempfile('cpansec-cve2yaml-XXXX', TMPDIR => 1, SUFFIX => '.yaml', UNLINK => 1);
      print {$fh} $yaml;
      close($fh);

      my $rebuilt = $yaml2cve->convert_yaml_file($tmp);

      my $source_projection = _project_roundtrip_view($doc);
      my $rebuilt_projection = _project_roundtrip_view($rebuilt);
      my $json = JSON::PP->new->canonical;
      my $a = $json->encode($source_projection);
      my $b = $json->encode($rebuilt_projection);
      if ($a ne $b) {
        my $diff = _projection_diff_text($source_projection, $rebuilt_projection);
        die "JSON->YAML round-trip guard failed: source/rebuilt projections differ\n$diff\n";
      }
    }

    return $yaml;
  }

  method convert_cve_doc_to_cpansec ($doc) {
    my $cna = $doc->{containers}{cna}
      or die "Expected CVE JSON with containers.cna\n";
    my @affected = @{$cna->{affected} // []};
    my $aff = $affected[0] // {};

    # The macro carries a single shared module, so an entry naming several is not
    # representable. Reject here rather than in the guard alone: --no-guard would
    # otherwise drop the extras silently.
    for my $i (0 .. $#affected) {
      my $modules = _modules_of($affected[$i]);
      next if @$modules <= 1;
      die "containers.cna.affected[$i] lists " . scalar(@$modules) . " modules ("
        . join(', ', @$modules) . "); the cpansec macro carries a single shared module\n";
    }

    my %cp = (
      cve => $doc->{cveMetadata}{cveId},
      module => _normalize_import_text(_module_of($aff) // ''),
      title => _normalize_import_text($cna->{title} // ''),
      description => _normalize_import_text(_first_en_value($cna->{descriptions})),
      references => [ map { _reference_to_cpansec($_) } @{$cna->{references} // []} ],
    );

    my @entries = map { _distribution_entry($_) } @affected;
    if (@entries > 1) {
      $cp{affected} = \@entries;
    } else {
      # A single distribution keeps the flat spelling, so existing records are
      # not rewritten into the object form on import.
      my $entry = $entries[0] // { distribution => '', versions => [] };
      $cp{distribution} = $entry->{distribution};
      $cp{affected} = $entry->{versions};
      for my $key (qw(repo files routines)) {
        $cp{$key} = $entry->{$key} if exists $entry->{$key};
      }
    }

    # Only legacy records carry the PAUSE ID, in vendor; nothing emits it now.
    if (defined $aff->{vendor} && length $aff->{vendor}) {
      $cp{author} = _normalize_import_text($aff->{vendor});
    }

    my @cwes = _extract_cwe_descriptions($cna->{problemTypes});
    $cp{cwes} = \@cwes if @cwes;

    if (ref($cna->{solutions}) eq 'ARRAY' && @{$cna->{solutions}}) {
      my @vals = map { _normalize_import_text($_->{value} // '') } @{$cna->{solutions}};
      $cp{solution} = @vals == 1 ? $vals[0] : \@vals;
    }

    if (ref($cna->{workarounds}) eq 'ARRAY' && @{$cna->{workarounds}}) {
      my @vals = map { _normalize_import_text($_->{value} // '') } @{$cna->{workarounds}};
      $cp{mitigation} = @vals == 1 ? $vals[0] : \@vals;
    }

    if (ref($cna->{impacts}) eq 'ARRAY' && @{$cna->{impacts}}) {
      my @vals = map { _impact_to_string($_) } @{$cna->{impacts}};
      @vals = grep { defined($_) && length($_) } @vals;
      $cp{impacts} = \@vals if @vals;
    }

    if (ref($cna->{credits}) eq 'ARRAY' && @{$cna->{credits}}) {
      my @credits;
      for my $cr (@{$cna->{credits}}) {
        next unless ref($cr) eq 'HASH';
        push @credits, {
          type => _normalize_import_text($cr->{type} // ''),
          value => _normalize_import_text($cr->{value} // ''),
          (($cr->{lang} // 'en') ne 'en' ? (lang => _normalize_import_text($cr->{lang})) : ()),
        };
      }
      $cp{credits} = \@credits if @credits;
    }

    if (ref($cna->{timeline}) eq 'ARRAY' && @{$cna->{timeline}}) {
      my @tl;
      for my $t (@{$cna->{timeline}}) {
        next unless ref($t) eq 'HASH';
        push @tl, {
          time => _normalize_import_text($t->{time}),
          value => _normalize_import_text($t->{value}),
        }
          if defined $t->{time} && defined $t->{value};
      }
      $cp{timeline} = \@tl if @tl;
    }

    return \%cp;
  }

  method encode_cpansec_yaml ($cpansec) {
    my $ypp = YAML::PP->new(
      schema => [qw/ Core /],
      header => 0,
      preserve => PRESERVE_ORDER,
    );
    my $yaml = $ypp->dump_string({
      cpansec => _preserved_cpansec_mapping($ypp, $cpansec),
    });

    # Prefer strip-chomp style for common multiline prose fields.
    $yaml =~ s/^(\s*(?:description|solution|mitigation):)\s*\|\s*$/$1 |-/mg;
    $yaml =~ s/[ \t]+\n/\n/g;
    return $yaml_schema_hint . "\n" . $yaml;
  }
}

sub _read_json_file ($path) {
  open(my $fh, '<', $path) or die "Cannot read $path: $!\n";
  local $/;
  my $json = <$fh>;
  close($fh);
  return decode_json($json);
}

sub _version_to_expr ($v) {
  return '' unless ref($v) eq 'HASH';
  my $from = $v->{version} // '';
  if (defined $v->{lessThanOrEqual}) {
    return $from && $from ne '0' ? "$from <= $v->{lessThanOrEqual}" : "<= $v->{lessThanOrEqual}";
  }
  if (defined $v->{lessThan}) {
    return $from && $from ne '0' ? "$from < $v->{lessThan}" : "< $v->{lessThan}";
  }
  return $from;
}

sub _reference_to_cpansec ($r) {
  my %out = (link => _normalize_import_text($r->{url}));
  $out{name} = _normalize_import_text($r->{name}) if defined $r->{name};
  if (ref($r->{tags}) eq 'ARRAY' && @{$r->{tags}}) {
    $out{tags} = [ map { _normalize_import_text($_) } @{$r->{tags}} ];
  }
  return \%out;
}

sub _first_en_value ($entries) {
  for my $e (@{$entries // []}) {
    return $e->{value} // '' if ($e->{lang} // '') eq 'en';
  }
  return '';
}

sub _extract_cwe_descriptions ($problem_types) {
  my @out;
  for my $pt (@{$problem_types // []}) {
    for my $d (@{$pt->{descriptions} // []}) {
      my $id = $d->{cweId};
      my $desc = $d->{description};
      next unless defined $id && $id =~ /^CWE-\d+$/;
      next unless defined $desc && length $desc;
      if ($desc =~ /^\Q$id\E\s+/) {
        push @out, $desc;
      } else {
        push @out, "$id $desc";
      }
    }
  }
  return @out;
}

sub _impact_to_string ($impact) {
  return undef unless ref($impact) eq 'HASH';
  my $id = $impact->{capecId};
  return undef unless defined $id && $id =~ /^CAPEC-\d+$/;
  my $desc = _first_en_value($impact->{descriptions});
  $desc =~ s/^\Q$id\E\s+//;
  $desc =~ s/^\s+|\s+$//g;
  return length($desc) ? "$id $desc" : $id;
}

sub _project_roundtrip_view ($doc) {
  my $cna = $doc->{containers}->{cna};
  my @affected = @{$cna->{affected} // []};

  return {
    cve => $doc->{cveMetadata}->{cveId},
    module => _module_of($affected[0] // {}),
    # author is deliberately absent: nothing emits the PAUSE ID any more, so it
    # cannot round-trip and guarding it would fail on every legacy record.
    # Every entry is projected, so a dropped distribution cannot slip past.
    distributions => [ map { +{
      distribution => $_->{packageName},
      # The whole module list per entry, so neither a disagreement between
      # entries nor extra modules within one entry can collapse unnoticed.
      # Reading it through _modules_of keeps legacy product-only records
      # comparable against records that use modules[].
      modules => _modules_of($_),
      repo => $_->{repo},
      versions => [ map { _normalize_version_entry($_) } @{$_->{versions} // []} ],
      files => [ sort @{$_->{programFiles} // []} ],
      routines => [ sort map { $_->{name} } @{$_->{programRoutines} // []} ],
    } } @affected ],
    title => _normalize_ws($cna->{title} // ""),
    description => _normalize_ws(_first_en_value($cna->{descriptions})),
    cwes => [ sort map { _normalize_ws($_) } _extract_cwe_descriptions($cna->{problemTypes}) ],
    solution => [ map { _normalize_ws($_) } @{$cna->{solutions} ? [ map { $_->{value} // "" } @{$cna->{solutions}} ] : []} ],
    mitigation => [ map { _normalize_ws($_) } @{$cna->{workarounds} ? [ map { $_->{value} // "" } @{$cna->{workarounds}} ] : []} ],
    references => [
      map { _normalize_reference($_) }
      sort { ($a->{url} // "") cmp ($b->{url} // "") } @{$cna->{references} // []}
    ],
    impacts => [
      sort grep { length $_ } map { _normalize_ws($_) } map { _impact_to_string($_) // '' } @{$cna->{impacts} // []}
    ],
    credits => [
      map { _normalize_credit($_) }
      sort { (($a->{type} // '') . "\0" . ($a->{value} // '') . "\0" . ($a->{lang} // ''))
           cmp (($b->{type} // '') . "\0" . ($b->{value} // '') . "\0" . ($b->{lang} // '')) } @{$cna->{credits} // []}
    ],
    timeline => [
      map { _normalize_timeline($_) }
      sort { (($a->{time} // '') . "\0" . ($a->{value} // '') . "\0" . ($a->{lang} // ''))
           cmp (($b->{time} // '') . "\0" . ($b->{value} // '') . "\0" . ($b->{lang} // '')) } @{$cna->{timeline} // []}
    ],
  };
}

sub _distribution_entry ($aff) {
  my %entry = (
    distribution => _normalize_import_text($aff->{packageName} // ''),
    versions     => [ map { _version_to_expr($_) } @{$aff->{versions} // []} ],
  );

  $entry{repo} = _normalize_import_text($aff->{repo})
    if defined $aff->{repo} && length $aff->{repo};
  $entry{files} = [ map { _normalize_import_text($_) } @{$aff->{programFiles}} ]
    if ref($aff->{programFiles}) eq 'ARRAY' && @{$aff->{programFiles}};
  $entry{routines} = [ map { _normalize_import_text($_->{name}) } @{$aff->{programRoutines}} ]
    if ref($aff->{programRoutines}) eq 'ARRAY' && @{$aff->{programRoutines}};

  return \%entry;
}

# The module lives in modules[] since 5.2.0; product carried it in older records.
sub _modules_of ($aff) {
  my $modules = $aff->{modules};
  return [ @$modules ] if ref($modules) eq 'ARRAY' && @$modules;
  return defined $aff->{product} ? [ $aff->{product} ] : [];
}

sub _module_of ($aff) {
  return _modules_of($aff)->[0];
}

sub _normalize_version_entry ($v) {
  return {
    versionType => $v->{versionType},
    status => $v->{status},
    version => $v->{version},
    (exists $v->{lessThan} ? (lessThan => $v->{lessThan}) : ()),
    (exists $v->{lessThanOrEqual} ? (lessThanOrEqual => $v->{lessThanOrEqual}) : ()),
  };
}

sub _normalize_reference ($r) {
  return {
    link => $r->{url},
    (exists $r->{name} ? (name => _normalize_ws($r->{name})) : ()),
    (exists $r->{tags} ? (tags => [ sort @{$r->{tags}} ]) : ()),
  };
}

sub _normalize_credit ($cr) {
  return {
    type => _normalize_ws($cr->{type} // ''),
    value => _normalize_ws($cr->{value} // ''),
    lang => _normalize_ws($cr->{lang} // 'en'),
  };
}

sub _normalize_timeline ($entry) {
  return {
    time => _normalize_ws($entry->{time} // ''),
    value => _normalize_ws($entry->{value} // ''),
    lang => _normalize_ws($entry->{lang} // 'en'),
  };
}

sub _normalize_ws ($text) {
  $text //= "";
  $text =~ s/\x{A0}/ /g;
  $text =~ s/\r\n?/\n/g;
  $text =~ s/\s+/ /g;
  $text =~ s/^\s+//;
  $text =~ s/\s+$//;
  return $text;
}

sub _normalize_import_text ($text) {
  return '' unless defined $text;
  $text = "$text";
  $text =~ s/\x{A0}/ /g;
  return $text;
}

sub _ordered_cpansec_keys ($cpansec) {
  my @order = qw(
    cve distribution module author repo affected
    title description
    cwes impacts solution mitigation files routines timeline credits
    references
  );

  my %seen;
  my @out;
  for my $key (@order) {
    next unless exists $cpansec->{$key};
    push @out, $key;
    $seen{$key} = 1;
  }

  for my $key (sort keys %$cpansec) {
    next if $seen{$key};
    push @out, $key;
  }

  return \@out;
}

sub _preserved_cpansec_mapping ($ypp, $cpansec) {
  my $map = $ypp->preserved_mapping({});
  for my $key (@{_ordered_cpansec_keys($cpansec)}) {
    $map->{$key} = _preserve_value_for_key($ypp, $key, $cpansec->{$key});
  }
  return $map;
}

sub _preserve_value_for_key ($ypp, $key, $value) {
  return $value if !ref($value);

  if (ref($value) eq 'ARRAY') {
    if ($key eq 'affected') {
      # Version-range strings pass through; distribution objects get a stable
      # key order so multi-distribution records round-trip identically.
      return [ map {
        ref($_) eq 'HASH'
          ? _preserved_hash_with_order($ypp, $_, [qw(distribution versions author repo files routines)])
          : $_
      } @$value ];
    }
    if ($key eq 'references') {
      return [ map { _preserved_hash_with_order($ypp, $_, [qw(link name tags)]) } @$value ];
    }
    if ($key eq 'credits') {
      return [ map { _preserved_hash_with_order($ypp, $_, [qw(type value lang)]) } @$value ];
    }
    if ($key eq 'timeline') {
      return [ map { _preserved_hash_with_order($ypp, $_, [qw(time value lang)]) } @$value ];
    }
    return [ map { _preserve_value_for_key($ypp, '', $_) } @$value ];
  }

  if (ref($value) eq 'HASH') {
    return _preserved_hash_with_order($ypp, $value, [ sort keys %$value ]);
  }

  return $value;
}

sub _preserved_hash_with_order ($ypp, $hash, $order) {
  return $hash unless ref($hash) eq 'HASH';

  my $map = $ypp->preserved_mapping({});
  my %seen;
  for my $k (@$order) {
    next unless exists $hash->{$k};
    $map->{$k} = _preserve_value_for_key($ypp, $k, $hash->{$k});
    $seen{$k} = 1;
  }
  for my $k (sort keys %$hash) {
    next if $seen{$k};
    $map->{$k} = _preserve_value_for_key($ypp, $k, $hash->{$k});
  }
  return $map;
}

sub _projection_diff_text ($source, $rebuilt, $limit = 80) {
  my @lines;
  my $truncated = 0;
  _collect_projection_diff($source, $rebuilt, '', \@lines, $limit, \$truncated);
  push @lines, '(diff truncated)' if $truncated;
  return "Projection diff (source vs rebuilt):\n" . join("\n", map { "  - $_" } @lines);
}

sub _collect_projection_diff ($source, $rebuilt, $path, $lines, $limit, $truncated_ref) {
  if (@$lines >= $limit) {
    $$truncated_ref = 1;
    return;
  }

  my $source_ref = ref($source);
  my $rebuilt_ref = ref($rebuilt);

  if ($source_ref eq 'HASH' && $rebuilt_ref eq 'HASH') {
    my %keys = map { $_ => 1 } (keys %$source, keys %$rebuilt);
    for my $key (sort keys %keys) {
      my $next = length($path) ? "$path.$key" : $key;
      _collect_projection_diff($source->{$key}, $rebuilt->{$key}, $next, $lines, $limit, $truncated_ref);
      return if @$lines >= $limit;
    }
    return;
  }

  if ($source_ref eq 'ARRAY' && $rebuilt_ref eq 'ARRAY') {
    my $max = @$source > @$rebuilt ? scalar(@$source) : scalar(@$rebuilt);
    for my $idx (0 .. $max - 1) {
      my $next = length($path) ? "$path\[$idx\]" : "[$idx]";
      _collect_projection_diff($source->[$idx], $rebuilt->[$idx], $next, $lines, $limit, $truncated_ref);
      return if @$lines >= $limit;
    }
    return;
  }

  if ($source_ref ne $rebuilt_ref) {
    push @$lines, sprintf(
      "%s type mismatch: source=%s rebuilt=%s",
      _display_path($path),
      _display_type($source),
      _display_type($rebuilt),
    );
    return;
  }

  my $source_value = _display_value($source);
  my $rebuilt_value = _display_value($rebuilt);
  return if $source_value eq $rebuilt_value;

  push @$lines, sprintf(
    "%s differs: source=%s rebuilt=%s",
    _display_path($path),
    $source_value,
    $rebuilt_value,
  );
}

sub _display_path ($path) {
  return length($path) ? $path : '(root)';
}

sub _display_type ($value) {
  return ref($value) || 'SCALAR';
}

sub _display_value ($value) {
  my $json = JSON::PP->new->canonical;
  my $rendered = eval { $json->encode($value) };
  if (!defined $rendered || $@) {
    $rendered = defined($value) ? "$value" : 'null';
  }
  $rendered =~ s/\n/\\n/g;
  if (length($rendered) > 180) {
    $rendered = substr($rendered, 0, 177) . '...';
  }
  return $rendered;
}

1;
