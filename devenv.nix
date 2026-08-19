{
  pkgs,
  lib,
  config,
  ...
}:
{
  # https://devenv.sh/languages/
  languages.rust.enable = true;
  # Same toolchain as CI: version and components come from the file
  languages.rust.toolchainFile = ./rust-toolchain.toml;

  # https://devenv.sh/packages/
  packages = [ pkgs.cargo-msrv pkgs.cargo-sort ];

  # https://devenv.sh/git-hooks/
  git-hooks.hooks = {
    rustfmt.enable = true;
    clippy.enable = true;
  };

  # See full reference at https://devenv.sh/reference/options/
}
