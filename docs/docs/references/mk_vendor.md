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
       mk_vendor list <CONFIG> [--json]
       mk_vendor list --check [--json]
       mk_vendor check-patches [<VENDOR>]

make: build a vendor library
  <CONFIG>      '<vendor>:<name>': a preset (e.g. 'openssl:openssl312') or a name derived from the vendor's
                vulnerability catalogue (e.g. 'wolfssl:CVE-2022-39173', 'wolfssl:wolfssl540-asan-only-CVE-2022-39173',
                'wolfssl:wolfssl540-asan-fix-all')
  -n, --name <NAME>  Override the preset's name
  -f, --force        Force configuration rebuild if it already exists
      --asan         Build with AddressSanitizer whatever the preset says

list: the known vulnerabilities of a build and their state, the validation set of a preset
list --check: the presets the vulnerability catalogue is checked on
check-patches: dry-run the catalogue's patches on the sources of the presets of their ranges
```

For the complete list of preconfigured targets `<CONFIG>`, you can look at our [support matrix](./support-matrix).
For more details, check the puffin [build process](../developer/build#mk_vendor). The vulnerability catalogue and the
derived names are documented in `puffin-build/README.md`.


:::
