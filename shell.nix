{ pkgs ? import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/nixos-23.11.tar.gz") {} }:

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
    pkgs.python310Packages.pip
    pkgs.python310Packages.virtualenv

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
  
  shellHook = ''
    export LIBCLANG_PATH="${pkgs.llvmPackages_14.libclang.lib}/lib";
    export LIBAFL_EDGES_MAP_SIZE=262144 # 2^18
  '';
}
