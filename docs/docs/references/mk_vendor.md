---
title: 'mk_vendor CLI'
---

:::warning[Ongoing Work]

This page is currently under development. Information presented here might be incomplete or outdated.

:::

:::tip[What is it?]

`mk_vendor` is a tool to build specific versions of *vendor libraries*, like OpenSSL, which can then be harnessed and bundled into a puffin fuzzer.

```man
`mk_vendor make [--force] [--name=<name>] <config>`

Usage: mk_vendor make [OPTIONS] <CONFIG>

Arguments:
  <CONFIG>  The configuration to build (e.g. 'openssl:openssl312')

Options:
  -n, --name <NAME>  Override the preset's name
  -f, --force        Force configuration rebuild if it already exists
  -h, --help         Print help
```

For the complete list of preconfigured targets `<CONFIG>`, you can look at our [support matrix](./support-matrix).
For more details, check the puffin [build process](../developer/build#mk_vendor).


:::
