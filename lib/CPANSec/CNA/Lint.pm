package CPANSec::CNA::Lint;

use v5.42;
use feature qw(class);
no warnings qw(experimental::class);
use CPANSec::CVE::VersionPhrase qw(template_version_range_from_affected);

class CPANSec::CNA::Lint {
  method run_model ($model, %opts) {
    my $path = $opts{path} // $model->source_file // '';
    my $cpansec = $model->cpansec;

    my @findings;
    push @findings, _rule_title_repeated($cpansec, $path);
    push @findings, _rule_template_tokens($cpansec, $path);
    push @findings, _rule_announce_wording($cpansec, $path);
    push @findings, _rule_title_style($cpansec, $path);
    push @findings, _rule_cvss_present($cpansec, $path);
    push @findings, _rule_solution_or_mitigation($cpansec, $path);
    push @findings, _rule_reference_quality($cpansec, $path);
    push @findings, _rule_metacpan_changelog_version_pinned($cpansec, $path);
    push @findings, _rule_description_length($cpansec, $path);
    push @findings, _rule_placeholders($cpansec, $path);

    return \@findings;
  }
}

sub _f ($severity, $id, $message, $path, $line) {
  return {
    severity => $severity,
    id       => $id,
    message  => $message,
    path     => $path,
    line     => $line // 1,
  };
}

sub _line_for_key ($path, $key) {
  return 1 unless $path && -f $path;
  open my $fh, '<', $path or return 1;
  my $line = 1;
  while (my $row = <$fh>) {
    return $line if $row =~ /^\s*\Q$key\E\s*:/;
    $line++;
  }
  return 1;
}

sub _desc_first_line ($desc) {
  return '' unless defined $desc;
  my $n = "$desc";
  $n =~ s/\r\n?/\n/g;
  $n =~ s/^\s+//;
  for my $line (split /\n/, $n) {
    $line =~ s/^\s+|\s+$//g;
    return $line if length $line;
  }
  return '';
}

sub _rule_title_repeated ($cpansec, $path) {
  my $title = _interpolate_version_range($cpansec, $cpansec->{title} // '');
  my $desc = _interpolate_version_range($cpansec, $cpansec->{description} // '');
  return () unless length $title && length $desc;

  my $first = _desc_first_line($desc);
  return () unless length $first;
  return () unless lc($first) eq lc($title);

  return _f(
    'error',
    'title_repeated_in_description',
    'Title is repeated as the first line of description.',
    $path,
    _line_for_key($path, 'description'),
  );
}

sub _rule_template_tokens ($cpansec, $path) {
  my @bad;
  my @fields = (
    [title => ($cpansec->{title} // '')],
    [description => ($cpansec->{description} // '')],
  );

  for my $f (@fields) {
    my ($name, $value) = @$f;
    next if ref($value);
    my $text = $value // '';
    while ($text =~ /\{\{\s*([^{}]+?)\s*\}\}/g) {
      my $token = $1;
      if ($token eq 'VERSION_RANGE') {
        my $phrase = template_version_range_from_affected($cpansec->{affected});
        push @bad, "$name:{{VERSION_RANGE}}" unless length $phrase;
      } else {
        push @bad, "$name:{{$token}}";
      }
    }
    my $rest = $text;
    $rest =~ s/\{\{\s*[^{}]+?\s*\}\}//g;
    if ($rest =~ /\{\{|\}\}/) {
      push @bad, "$name:unmatched-template-delimiter";
    }
  }

  return () unless @bad;
  return _f(
    'warning',
    'template_token_unresolved',
    'Template token issue(s): ' . join(', ', @bad) . '.',
    $path,
    1,
  );
}

sub _rule_announce_wording ($cpansec, $path) {
  my $expected = _expected_announce_lead($cpansec);
  return () unless length $expected;

  my $title = _normalize_inline(_interpolate_version_range($cpansec, $cpansec->{title} // ''));
  my $first = _normalize_inline(_desc_first_line(_interpolate_version_range($cpansec, $cpansec->{description} // '')));

  my @issues;
  push @issues, 'title' if length($title) && $title !~ /^\Q$expected\E\b/i;
  push @issues, 'description first line' if length($first) && $first !~ /^\Q$expected\E\b/i;
  return () unless @issues;

  return _f(
    'warning',
    'announce_wording_mismatch',
    "Announce wording guideline: " . join(' and ', @issues)
      . " should start with '$expected' to match announce version phrasing.",
    $path,
    _line_for_key($path, 'title'),
  );
}

sub _rule_title_style ($cpansec, $path) {
  my $title = _interpolate_version_range($cpansec, $cpansec->{title} // '');
  return () unless length $title;

  my @issues;
  push @issues, 'should mention Perl' unless $title =~ /\bPerl\b/i;
  push @issues, 'should include affected version context (e.g. before/through/from)'
    unless $title =~ /\b(before|through|from|versions?)\b/i;
  push @issues, 'should not end with punctuation'
    if $title =~ /[.!?]\s*$/;

  return () unless @issues;
  return _f(
    'warning',
    'title_style_standard',
    'Title style guideline: ' . join('; ', @issues) . '.',
    $path,
    _line_for_key($path, 'title'),
  );
}

sub _expected_announce_lead ($cpansec) {
  my $module = _normalize_inline($cpansec->{module} // '');
  return '' unless length $module;

  my $phrase = template_version_range_from_affected($cpansec->{affected});
  return '' unless length $phrase;

  return "$module $phrase for Perl";
}

sub _normalize_inline ($text) {
  $text //= '';
  $text =~ s/\s+/ /g;
  $text =~ s/^\s+|\s+$//g;
  return $text;
}

sub _interpolate_version_range ($cpansec, $text) {
  return $text if !defined($text) || ref($text);
  my $out = $text;
  return $out unless $out =~ /\{\{\s*VERSION_RANGE\s*\}\}/;
  my $phrase = template_version_range_from_affected($cpansec->{affected});
  return $out unless length $phrase;
  $out =~ s/\{\{\s*VERSION_RANGE\s*\}\}/$phrase/g;
  return $out;
}

sub _rule_cvss_present ($cpansec, $path) {
  return () unless exists $cpansec->{metrics} || exists $cpansec->{cvss};
  return _f(
    'warning',
    'cvss_present',
    'CVSS/metrics are present. CPANSec generally avoids CVSS scores unless there is a clear reason.',
    $path,
    _line_for_key($path, exists $cpansec->{metrics} ? 'metrics' : 'cvss'),
  );
}

sub _rule_solution_or_mitigation ($cpansec, $path) {
  my $has_solution = _has_nonempty_text($cpansec->{solution});
  my $has_mitigation = _has_nonempty_text($cpansec->{mitigation});
  return () if $has_solution || $has_mitigation;

  return _f(
    'warning',
    'missing_solution_or_mitigation',
    'Neither solution nor mitigation is provided.',
    $path,
    1,
  );
}

sub _has_nonempty_text ($value) {
  return 0 unless defined $value;
  if (ref($value) eq 'ARRAY') {
    for my $item (@$value) {
      next if ref($item);
      return 1 if defined($item) && $item =~ /\S/;
    }
    return 0;
  }
  return 0 if ref($value);
  return $value =~ /\S/ ? 1 : 0;
}

sub _rule_reference_quality ($cpansec, $path) {
  my $refs = $cpansec->{references};
  return () unless ref($refs) eq 'ARRAY' && @$refs;

  my %tag;
  my $has_vendor_like = 0;
  for my $r (@$refs) {
    next unless ref($r) eq 'HASH';
    my $tags = $r->{tags};
    my @tags = ref($tags) eq 'ARRAY' ? @$tags : (!ref($tags) && defined($tags) ? ($tags) : ());
    $tag{$_} = 1 for @tags;
    my $url = $r->{link} // '';
    $has_vendor_like = 1 if $url =~ m{github\.com|gitlab\.com|metacpan\.org/release}i;
  }

  my @issues;
  push @issues, 'no patch/release-notes/issue-tracking tag found'
    unless $tag{patch} || $tag{'release-notes'} || $tag{'issue-tracking'};
  push @issues, 'references do not seem to include an upstream/vendor source'
    unless $has_vendor_like;

  return () unless @issues;
  return _f(
    'warning',
    'reference_quality',
    'Reference quality guideline: ' . join('; ', @issues) . '.',
    $path,
    _line_for_key($path, 'references'),
  );
}

sub _rule_description_length ($cpansec, $path) {
  my $desc = $cpansec->{description} // '';
  $desc =~ s/\s+/ /g;
  $desc =~ s/^\s+|\s+$//g;
  return () if length($desc) >= 80;

  return _f(
    'warning',
    'description_too_short',
    'Description is very short; consider adding impact/context details.',
    $path,
    _line_for_key($path, 'description'),
  );
}

sub _rule_metacpan_changelog_version_pinned ($cpansec, $path) {
  my $refs = $cpansec->{references};
  return () unless ref($refs) eq 'ARRAY' && @$refs;

  my @bad;
  for my $r (@$refs) {
    next unless ref($r) eq 'HASH';
    my $url = $r->{link};
    next unless defined($url) && !ref($url);
    next unless _is_metacpan_changelog_link($url);
    next if _metacpan_changelog_is_version_pinned($url);
    push @bad, $url;
  }

  return () unless @bad;
  my $example = $bad[0];
  my $more = @bad > 1 ? sprintf(' (+%d more)', scalar(@bad) - 1) : '';
  return _f(
    'warning',
    'metacpan_changelog_not_version_pinned',
    "MetaCPAN changelog reference should target a specific release changelog file; avoid unversioned links like /dist/.../changes (e.g. $example$more).",
    $path,
    _line_for_key($path, 'references'),
  );
}

sub _is_metacpan_changelog_link ($url) {
  return 0 unless $url =~ m{^https?://metacpan\.org/}i;

  return 1 if $url =~ m{/dist/[^/?#]+/changes(?:[/?#]|$)}i;
  return 1 if $url =~ m{/changes?(?:[/?#]|$)}i;
  return 1 if $url =~ m{/source/[^?#]+/(?:changes?|changelog|history|news)(?:\.[A-Za-z0-9._-]+)?(?:[?#]|$)}i;

  return 0;
}

sub _metacpan_changelog_is_version_pinned ($url) {
  return 0 if $url =~ m{^https?://metacpan\.org/dist/}i;
  return $url =~ m{^https?://metacpan\.org/(?:release|source)/(?:[^/?#]+/)?[^/?#]*-(?:v?\d)[^/?#]*(?:/|$)}i ? 1 : 0;
}

sub _rule_placeholders ($cpansec, $path) {
  my @hits;
  for my $key (qw(title description distribution module author)) {
    my $v = $cpansec->{$key};
    next if ref($v);
    next unless defined $v;
    push @hits, $key if $v =~ /\b(TODO|TBD|example\.invalid|FIXME)\b/i;
  }

  my $refs = $cpansec->{references};
  if (ref($refs) eq 'ARRAY') {
    for my $r (@$refs) {
      next unless ref($r) eq 'HASH';
      my $link = $r->{link};
      next unless defined $link && !ref($link);
      push @hits, 'references' if $link =~ /example\.invalid/i;
    }
  }

  return () unless @hits;
  return _f(
    'error',
    'placeholder_content',
    'Placeholder content found in: ' . join(', ', @hits) . '.',
    $path,
    1,
  );
}

1;
