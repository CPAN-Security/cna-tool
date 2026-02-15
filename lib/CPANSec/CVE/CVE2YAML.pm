package CPANSec::CVE::CVE2YAML;

use v5.42;
use feature qw(class);
no warnings qw(experimental::class);

use CPANSec::CVE::YAML2CVE ();
use File::Temp qw(tempfile);
use JSON::PP qw(decode_json);
use YAML::PP ();

class CPANSec::CVE::CVE2YAML {
  field $yaml2cve :param = CPANSec::CVE::YAML2CVE->new;

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
      die "JSON->YAML round-trip guard failed: source/rebuilt projections differ\n"
        if $a ne $b;
    }

    return $yaml;
  }

  method convert_cve_doc_to_cpansec ($doc) {
    my $cna = $doc->{containers}{cna}
      or die "Expected CVE JSON with containers.cna\n";
    my $aff = $cna->{affected}[0] // {};

    my %cp = (
      cve => $doc->{cveMetadata}{cveId},
      distribution => $aff->{packageName} // '',
      module => $aff->{product} // '',
      author => $aff->{vendor} // '',
      affected => [ map { _version_to_expr($_) } @{$aff->{versions} // []} ],
      title => $cna->{title} // '',
      description => _first_en_value($cna->{descriptions}),
      references => [ map { _reference_to_cpansec($_) } @{$cna->{references} // []} ],
    );

    $cp{repo} = $aff->{repo} if defined $aff->{repo} && length $aff->{repo};

    if (ref($aff->{programFiles}) eq 'ARRAY' && @{$aff->{programFiles}}) {
      $cp{files} = [ @{$aff->{programFiles}} ];
    }
    if (ref($aff->{programRoutines}) eq 'ARRAY' && @{$aff->{programRoutines}}) {
      $cp{routines} = [ map { $_->{name} } @{$aff->{programRoutines}} ];
    }

    my @cwes = _extract_cwe_descriptions($cna->{problemTypes});
    $cp{cwes} = \@cwes if @cwes;

    if (ref($cna->{solutions}) eq 'ARRAY' && @{$cna->{solutions}}) {
      my @vals = map { $_->{value} // '' } @{$cna->{solutions}};
      $cp{solution} = @vals == 1 ? $vals[0] : \@vals;
    }

    if (ref($cna->{workarounds}) eq 'ARRAY' && @{$cna->{workarounds}}) {
      my @vals = map { $_->{value} // '' } @{$cna->{workarounds}};
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
          type => $cr->{type} // '',
          value => $cr->{value} // '',
          (($cr->{lang} // 'en') ne 'en' ? (lang => $cr->{lang}) : ()),
        };
      }
      $cp{credits} = \@credits if @credits;
    }

    if (ref($cna->{timeline}) eq 'ARRAY' && @{$cna->{timeline}}) {
      my @tl;
      for my $t (@{$cna->{timeline}}) {
        next unless ref($t) eq 'HASH';
        push @tl, { time => $t->{time}, value => $t->{value} }
          if defined $t->{time} && defined $t->{value};
      }
      $cp{timeline} = \@tl if @tl;
    }

    return \%cp;
  }

  method encode_cpansec_yaml ($cpansec) {
    my $ypp = YAML::PP->new(schema => [qw/ Core /]);
    my $yaml = $ypp->dump_string({ cpansec => $cpansec });
    # Prefer strip-chomp style for common multiline prose fields.
    $yaml =~ s/^(\s*(?:description|solution|mitigation):)\s*\|\s*$/$1 |-/mg;
    return $yaml;
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
  my %out = (link => $r->{url});
  $out{name} = $r->{name} if defined $r->{name};
  if (ref($r->{tags}) eq 'ARRAY' && @{$r->{tags}}) {
    $out{tags} = [ @{$r->{tags}} ];
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
  my $affected = $cna->{affected}->[0] // {};

  return {
    cve => $doc->{cveMetadata}->{cveId},
    distribution => $affected->{packageName},
    module => $affected->{product},
    author => $affected->{vendor},
    repo => $affected->{repo},
    affected => [ map { _normalize_version_entry($_) } @{$affected->{versions} // []} ],
    files => [ sort @{$affected->{programFiles} // []} ],
    routines => [ sort map { $_->{name} } @{$affected->{programRoutines} // []} ],
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
  $text =~ s/\r\n?/\n/g;
  $text =~ s/\s+/ /g;
  $text =~ s/^\s+//;
  $text =~ s/\s+$//;
  return $text;
}

1;
