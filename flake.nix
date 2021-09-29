{
  inputs = {
    utils.url = "github:numtide/flake-utils";
    naersk.url = "github:nmattia/naersk";
    mozillapkgs = {
      url = "github:mozilla/nixpkgs-mozilla";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, utils, naersk, mozillapkgs, }:
    utils.lib.eachDefaultSystem
      (system:
        let
          pkgs = nixpkgs.legacyPackages."${system}";

          # Get a specific rust version
          mozilla = pkgs.callPackage (mozillapkgs + "/package-set.nix") { };
          rust = (mozilla.rustChannelOf {
            channel = "stable";
            version = "1.55.0";
            sha256 = "HNIlEerJvk6sBfd8zugzwSgSiHcQH8ZbqWQn9BGfmpo=";
          }).rust;

          # Override the version used in naersk
          naersk-lib = naersk.lib."${system}".override {
            cargo = rust;
            rustc = rust;
          };

        in
        rec {
          # `nix build`
          packages.iroha = naersk-lib.buildPackage {
            pname = "iroha";
            root = ./.;
            targets = [ "iroha_cli" "iroha_client_cli" "iroha_crypto_cli" ];
            nativeBuildInputs = with pkgs; [ rust perl gcc ];
          };
          defaultPackage = packages.iroha;

          # `nix run`
          apps.iroha = utils.lib.mkApp {
            drv = packages.iroha;
          };
          defaultApp = apps.iroha;

          # `nix develop`
          devShell = pkgs.mkShell {
            nativeBuildInputs = with pkgs; [ rust perl gcc ];
          };
        }
      );
}
