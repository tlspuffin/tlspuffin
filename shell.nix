{ pkgs ? import <nixpkgs> { } }:

pkgs.llvmPackages_14.stdenv.mkDerivation {
  name = "llvm_shell";
  nativeBuildInputs = [
    pkgs.rustup
    pkgs.just

    pkgs.gcovr

    pkgs.cmake

    # wolfSSL
    pkgs.autoconf
    pkgs.automake
    pkgs.libtool

    # macos
    pkgs.libiconv

    # openssh
    pkgs.openssl_1_1

    # Old openssl
    pkgs.xorg.makedepend

    pkgs.graphviz
    pkgs.yajl
    pkgs.python310Packages.pip
    pkgs.python310Packages.virtualenv
  ] ++
  pkgs.lib.optionals pkgs.stdenv.isDarwin [
    pkgs.darwin.apple_sdk.frameworks.Security
  ];
  # Hardening is not really important for tlspuffina nd might introduce weird compiler flags
  hardeningDisable = [ "all" ];
  shellHook = ''
    export LIBCLANG_PATH="${pkgs.llvmPackages_14.libclang.lib}/lib";
  '';
}
