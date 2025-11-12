{
  description = "ISO/IEC 14443 Rust library";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      rust-overlay,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [
            "rust-src"
            "rustfmt"
            "clippy"
          ];
        };

        buildInputs = with pkgs; [
          rustToolchain
        ];
      in
      {
        devShells.default = pkgs.mkShell {
          inherit buildInputs;
          RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";
        };

        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "iso14443";
          version = "0.1.0";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
          inherit buildInputs;
        };

        apps = {
          build = {
            type = "app";
            program = "${pkgs.writeShellScript "build" ''
              cargo build
            ''}";
          };
          test = {
            type = "app";
            program = "${pkgs.writeShellScript "test" ''
              cargo test
            ''}";
          };
          cli = {
            type = "app";
            program = "${pkgs.writeShellScript "cli" ''
              cargo run --example cli_parser -- "$@"
            ''}";
          };
        };
      }
    );
}
