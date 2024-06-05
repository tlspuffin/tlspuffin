{ pkgs ? import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/nixos-23.11.tar.gz") {} }:

pkgs.llvmPackages_14.stdenv.mkDerivation {
  name = "llvm_shell";
  nativeBuildInputs = [
    pkgs.git
    pkgs.rustup
    pkgs.just

    pkgs.cmake
    pkgs.llvmPackages_14.llvm

    pkgs.perl # OpenSSL, mk_vendor

    pkgs.autoconf # wolfSSL
    pkgs.automake # wolfSSL
    pkgs.libtool  # wolfSSL

    pkgs.go # BoringSSL

    pkgs.openssl # sshpuffin

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
    export CARGO_HOME=''${CARGO_HOME:-~/.cargo}
    export RUSTUP_HOME=''${RUSTUP_HOME:-~/.rustup}
    export PATH=''${PATH}:''${CARGO_HOME}/bin
    export LIBCLANG_PATH="${pkgs.llvmPackages_14.libclang.lib}/lib";
    export LIBAFL_EDGES_MAP_SIZE=262144 # 2^18
  '';
}
