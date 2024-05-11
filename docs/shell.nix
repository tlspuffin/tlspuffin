{ pkgs ? import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/nixos-23.11.tar.gz") {} }:

pkgs.stdenv.mkDerivation {
    name = "nodejs-env";
    nativeBuildInputs = [
        pkgs.cacert
        pkgs.nodejs_20
    ];
    shellHook = ''
        export PATH="$PWD/node_modules/.bin/:$PATH"
    '';
}
