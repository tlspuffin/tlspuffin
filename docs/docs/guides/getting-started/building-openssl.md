---
title: 'Building OpenSSL'
---

## Building a Preconfigured Targets

*tlspuffin* comes with several preconfigured fuzz targets and a wrapper script `mk_vendor` to simplify the build process:

```sh
./tools/mk_vendor make openssl:openssl312 --options=sancov
```

This command will fetch the sources for OpenSSL 3.1.2 and build it with clang's [SanitizerCoverage](https://clang.llvm.org/docs/SanitizerCoverage.html) activated.

:::tip[Want to try another target?]

For the complete list of preconfigured targets, you can browse mk_vendor's configuration file located in `puts/vendor/configs/openssl.toml` or have a look at our [support matrix](../../references/support-matrix).

**[Ongoing Work]** You might not want to use a preconfigured target but rather build your own from scratch, independently of the tooling provided by *tlspuffin*. In that case, you can simply install the result of your build process in subfolder of `./vendor`. This will automatically make it available to *tlspuffin*, using the name of the subfolder as identifer.

:::

## Checking The Build Result

By default, `mk_vendor` will store the result of the build process in a subfolder of the `vendor/` folder at the root of the project. In our case:

```sh
ls -al ./vendor/openssl312-sancov
```

This folder is a standard install prefix containing most notably the `include` and `lib` folders that will allow *tlspuffin* to link against the fuzz target.
