{ pkgs ? import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/nixos-24.05.tar.gz") {} }:

let
  llvmPackages = pkgs.llvmPackages_14;
in

pkgs.mkShell.override { stdenv = llvmPackages.stdenv; } {
  name = "tlspuffin-dev";

  packages = [
    (pkgs.lib.hiPrio pkgs.clang-tools)

    pkgs.git
    pkgs.rustup
    pkgs.just
    pkgs.cmake

    pkgs.perl # OpenSSL, mk_vendor

    pkgs.autoconf # wolfSSL
    pkgs.automake # wolfSSL
    pkgs.libtool  # wolfSSL

    pkgs.go # BoringSSL

    pkgs.openssl # sshpuffin
    pkgs.zlib    # sshpuffin

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
    export LIBCLANG_PATH="${llvmPackages.libclang.lib}/lib";
    export LIBAFL_EDGES_MAP_SIZE=524288 # 2^19
  '';
}
