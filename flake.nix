{
  description = "CPANSec CNA tool";

  inputs = {
    nixpkgs.url = "flake:nixpkgs";
  };

  outputs = { self, nixpkgs }:
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
        in {
          cna = pkgs.writeShellApplication {
            name = "cna";
            runtimeInputs = [ perlEnv ];
            text = ''
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
