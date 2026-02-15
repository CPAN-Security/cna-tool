use strict;
use v5.42;

use Test::More;

use lib 'lib';
use CPANSec::CNA::App ();

my $app = CPANSec::CNA::App->new;

is(
  $app->_normalize_prefill_repo_url('git://github.com/example/project.git'),
  'https://github.com/example/project',
  'git github URL is rewritten to https without .git',
);

is(
  $app->_normalize_prefill_repo_url('git://github.com/example/project'),
  'https://github.com/example/project',
  'git github URL without suffix is rewritten to https',
);

is(
  $app->_normalize_prefill_repo_url('https://github.com/example/project.git'),
  'https://github.com/example/project',
  'https github URL drops trailing .git',
);

is(
  $app->_normalize_prefill_repo_url('https://example.com/example/project.git'),
  'https://example.com/example/project.git',
  'non-github URL is unchanged',
);

done_testing();
