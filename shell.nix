{ pkgs ? import <nixpkgs> { } }:

pkgs.mkShell {
  nativeBuildInputs = [
    pkgs.rustup
    pkgs.just
  
    pkgs.llvmPackages_14.llvm
    pkgs.llvmPackages_14.clang
    pkgs.darwin.apple_sdk.frameworks.Security

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
  ];
  shellHook = ''
export LIBCLANG_PATH="${pkgs.llvmPackages_14.libclang.lib}/lib";
  '';
}

