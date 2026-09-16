{ pkgs ? import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/nixos-23.11.tar.gz") {} }:

let
  # The ast-grep of nixpkgs 23.11 (0.13.1) is too old for the rules of
  # evaluation-ddyf/count_fields.sh, so it is taken from a more recent channel.
  pkgsRecent = import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/nixos-25.05.tar.gz") {};
in

pkgs.llvmPackages_14.stdenv.mkDerivation {
  name = "llvm_shell";
  nativeBuildInputs = [
    pkgs.rustup
    pkgs.just

    pkgs.cmake
    pkgs.llvmPackages_14.llvm

    # wolfSSL
    pkgs.autoconf
    pkgs.automake
    pkgs.libtool

    # BoringSSL
    pkgs.go

    # openssh
    pkgs.openssl

    pkgs.graphviz
    pkgs.yajl

    # counting the TLS fields ignored by the oracle (evaluation-ddyf/count_fields.sh)
    pkgsRecent.ast-grep

    # Python environment of the evaluation scripts (see evaluation-ddyf/). A
    # single withPackages environment, so that `python` always resolves to the
    # interpreter that has pandas and matplotlib.
    (pkgs.python310.withPackages (ps: with ps; [
      pip
      virtualenv

      pandas
      matplotlib
      numpy
    ]))

    # docs / website
    pkgs.nodejs_20
  ] ++
  pkgs.lib.optionals pkgs.stdenv.isDarwin [
    pkgs.libiconv
    pkgs.darwin.apple_sdk.frameworks.CoreFoundation
    pkgs.darwin.apple_sdk.frameworks.CoreServices
    pkgs.darwin.apple_sdk.frameworks.Security
    pkgs.darwin.apple_sdk.frameworks.System
  ];

  # Hardening is not really important for tlspuffin and might introduce weird compiler flags
  hardeningDisable = [ "all" ];

  RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";

  shellHook = ''
    echo "Rust version: $(rustc --version)"
    echo "Cargo version: $(cargo --version)"
    echo "RUST_SRC_PATH: $RUST_SRC_PATH"
    export LIBCLANG_PATH="${pkgs.llvmPackages_14.libclang.lib}/lib";
    export LIBAFL_EDGES_MAP_SIZE=262144 # 2^18
  '';
}
