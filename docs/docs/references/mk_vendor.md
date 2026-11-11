---
title: 'mk_vendor CLI'
---

:::warning[Ongoing Work]

This page is currently under development. Information presented here might be incomplete or outdated.

:::

:::tip[What is it?]

`mk_vendor` is a tool to build specific versions of *vendor libraries*, like OpenSSL, which can then be harnessed and bundled into a puffin fuzzer.

```man
Usage: mk_vendor make [OPTIONS] <CONFIG>
       mk_vendor resolve <CONFIG> [--json]
       mk_vendor modifiers <VENDOR> [--json]
       mk_vendor list <CONFIG> [--json]
       mk_vendor list --check [--json]
       mk_vendor check-patches [<VENDOR>]

make: build a vendor library
  <CONFIG>      '<vendor>:<version>[,<modifier>…]' (e.g. 'openssl:1.1.1j,asan', 'wolfssl:5.4.0,only-BUF',
                'wolfssl:5.4.0,fix-all'), a preset (e.g. 'openssl:openssl312'), or a bug of the vendor's
                vulnerability catalogue alone ('wolfssl:CVE-2022-39173'); the library directory and the PUT
                are named after the build (a preset's name, or e.g. 'wolfssl540-asan-only-CVE-2022-39173')
  -n, --name <NAME>  Name the library directory and the PUT otherwise
  -f, --force        Force configuration rebuild if it already exists
      --asan         Build with AddressSanitizer whatever the name says

resolve: what a name builds (canonical name, directory and PUT name, sources, options, fixes, bugs)
modifiers: the modifiers of a vendor (asan, sancov, gcov, llvm_cov, its builder's options) and its versions
list: the known vulnerabilities of a build and their state, the validation set of a preset
list --check: the builds the vulnerability catalogue is checked on
check-patches: dry-run the catalogue's patches on the sources of the versions of their ranges (after
               the patches presets.toml applies to each version)
```

For the complete list of preconfigured targets `<CONFIG>`, you can look at our [support matrix](./support-matrix).
For more details, check the puffin [build process](../developer/build#mk_vendor). The names of builds and the vulnerability
catalogue are documented in `puffin-build/README.md`.


:::
