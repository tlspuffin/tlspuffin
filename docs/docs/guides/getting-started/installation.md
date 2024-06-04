---
title: 'Installation'
---

## Before you start

`tlspuffin` relies on [Nix](https://nixos.org/) to setup an environment with all the necessary dependencies and to provide a consistent development experience. This guide will leverage Nix to simplify the install process and **we strongly encourage you to setup Nix** on your machine as a pre-requisite. If you are new to Nix, we recommend using the [Zero to Nix install guide](https://zero-to-nix.com/start/install).

Otherwise, you can manually install the dependencies listed in the repository's [README](https://github.com/tlspuffin/tlspuffin?tab=readme-ov-file#dependencies) file, as well as the dependencies for building the OpenSSL fuzz target used in this guide.

## Install

Download the latest sources of tlspuffin:
```sh
git clone https://github.com/tlspuffin/tlspuffin
```

Note that all the subsequent commands in this guide should be run from the root `tlspuffin` folder that was just downloaded through git:
```sh
cd tlspuffin
```

The provided nix shell environment will provide all the dependencies and tools necessary for this guide:
```sh
nix-shell
```
