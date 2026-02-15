requires 'perl', '5.042000';

# Runtime
requires 'CPAN::Meta::YAML';
requires 'JSON::Validator';
requires 'YAML::PP';

# Used by init helpers (slugify + MetaCPAN prefill)
requires 'Mojolicious';
requires 'MetaCPAN::Client';

on 'test' => sub {
  requires 'Test::Warnings';
};

