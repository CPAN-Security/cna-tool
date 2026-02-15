{ pkgs ? import <nixpkgs> {} }:

with pkgs;

let perl' = perl.withPackages(p: [p.TestWarnings p.EmailStuffer p.AuthenSASL p.IOSocketSSL p.ArchiveZip p.IOString p.XMLLibXML p.YAMLPP p.JSONValidator p.MetaCPANClient p.Mojolicious ]);
in mkShell {
  buildInputs = [
    perl'
    python3Packages.cvelib
  ];
}
