{ pkgs ? import <nixpkgs> {} }:

with pkgs;

let perl' = perl.withPackages (p: [
  p.TestWarnings
  p.YAMLPP
  p.JSONValidator
  p.MetaCPANClient
  p.Mojolicious
]);
in mkShell {
  buildInputs = [
    perl'
  ];
}
