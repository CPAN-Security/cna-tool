{
  description = "CPANSec CNA tool";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
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
        f (import nixpkgs { inherit system; }));
    in {
      packages = forAllSystems (pkgs:
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
            paths = [ self.packages.${pkgs.system}.cna ];
          };
        });

      apps = forAllSystems (pkgs: {
        cna = {
          type = "app";
          program = "${self.packages.${pkgs.system}.cna}/bin/cna";
        };
        default = self.apps.${pkgs.system}.cna;
      });

      devShells = forAllSystems (pkgs:
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
