# Nix shell used inside the DDYF container.
#
# It is the repository's ./shell.nix plus the handful of tools that a normal
# workstation provides but a bare container does not: `git` (used by
# `mk_vendor` to fetch the PUT sources), `perl` (OpenSSL's Configure) and the
# usual build utilities.
{ pkgs ? import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/nixos-23.11.tar.gz") {} }:

(import ./shell.nix { inherit pkgs; }).overrideAttrs (old: {
  name = "ddyf_container_shell";

  nativeBuildInputs = old.nativeBuildInputs ++ (with pkgs; [
    bashInteractive
    cacert
    coreutils
    curl
    diffutils
    file
    findutils
    gawk
    gnugrep
    gnumake
    gnupatch
    gnused
    gnutar
    gzip
    git
    less
    perl
    pkg-config
    procps
    which
    xz
  ]);
})
