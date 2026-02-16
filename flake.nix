{
  description = "CPANSec CNA tool";

  inputs = {
    nixpkgs.url = "flake:nixpkgs";
    cve-schema = {
      url = "github:CVEProject/cve-schema";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, cve-schema }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system:
        f (import nixpkgs { inherit system; }) system);
    in {
      packages = forAllSystems (pkgs: system:
        let
          perlEnv = pkgs.perl.withPackages (p: [
            p.YAMLPP
            p.JSONValidator
            p.MetaCPANClient
            p.Mojolicious
          ]);
          cveSchemaOnly = pkgs.runCommand "cve-schema-only" {} ''
            mkdir -p "$out"
            cp -R ${cve-schema}/schema "$out/schema"
          '';
        in {
          cna = pkgs.writeShellApplication {
            name = "cna";
            runtimeInputs = [ perlEnv ];
            text = ''
              export CPANSEC_CNA_CVE_SCHEMA="${cveSchemaOnly}/schema/CVE_Record_Format.json"
              exec ${self}/scripts/cna "$@"
            '';
          };

          default = pkgs.symlinkJoin {
            name = "cpansec-cna-tool";
            paths = [ self.packages.${system}.cna ];
          };
        });

      apps = forAllSystems (pkgs: system: {
        cna = {
          type = "app";
          program = "${self.packages.${system}.cna}/bin/cna";
        };
        default = self.apps.${system}.cna;
      });

      devShells = forAllSystems (pkgs: _system:
        let
          perlEnv = pkgs.perl.withPackages (p: [
            p.TestWarnings
            p.YAMLPP
            p.JSONValidator
            p.MetaCPANClient
            p.Mojolicious
          ]);
        in {
          default = pkgs.mkShell {
            packages = [
              perlEnv
            ];
          };
        });
    };
}
