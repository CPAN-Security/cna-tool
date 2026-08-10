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

      # Not yet packaged in nixpkgs; runtime deps are core-only.
      uriPackageURL = pkgs: pkgs.perlPackages.buildPerlPackage {
        pname = "URI-PackageURL";
        version = "2.25";
        src = pkgs.fetchurl {
          url = "mirror://cpan/authors/id/G/GD/GDT/URI-PackageURL-2.25.tar.gz";
          hash = "sha256-lBEZ/mlXHqeGY9JoCUsUvYy+u6NXoTfr66hLiRBo5ZA=";
        };
        buildInputs = [ pkgs.perlPackages.CPANDistnameInfo ];
        meta = {
          description = "Perl extension for Package URL (purl)";
          homepage = "https://metacpan.org/dist/URI-PackageURL";
          license = with pkgs.lib.licenses; [ artistic2 ];
        };
      };

      perlDeps = pkgs: p: [
        p.YAMLPP
        p.JSONValidator
        p.MetaCPANClient
        p.Mojolicious
        (uriPackageURL pkgs)
      ];
    in {
      packages = forAllSystems (pkgs: system:
        let
          perlEnv = pkgs.perl.withPackages (perlDeps pkgs);
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
          perlEnv = pkgs.perl.withPackages (p: [ p.TestWarnings ] ++ perlDeps pkgs p);
        in {
          default = pkgs.mkShell {
            packages = [
              perlEnv
            ];
          };
        });
    };
}
