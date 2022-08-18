# libressl-src

This package contains the logic to build [LibreSSL](https://www.libressl.org/)
and is intended to be consumed by
the [openssl-sys](https://lib.rs/crates/openssl-sys) package.

Currently it builds LibreSSL 3.1.4, released 17 Aug 2020.
We're not yet building 3.2.2 (the latest stable release since 18 Oct 2020), because
[openssl-sys isn't yet supporting it](https://github.com/sfackler/rust-openssl/issues/1309).
(See discussion on [this PR](https://github.com/sfackler/rust-openssl/pull/1333).)

To use, make sure that `openssl-sys` is built with the `"vendored"` feature
(the [openssl](https://lib.rs/crates/openssl)
package also accepts that feature, and passes it on to `openssl-sys`).
Then add the following to your top-level `Cargo.toml`, for a package that has `openssl-sys`
as a direct or indirect dependency:

```
[patch.crates-io]
libressl-src = { git = "https://github.com/tlspuffin/libressl-src" }
```

This will substitute this repository into your build process where cargo would
otherwise have used [openssl-src](https://lib.rs/crates/openssl-src). The downsides
of this method are:

* this method only works on a top-level `Cargo.toml`; it will not be inherited
  by other packages that depend on that package
* a package with a `patch` section can't itself be published on
  [crates.io](https://crates.io/) (CHECK)

I'll try to get the maintainers of `openssl-sys`
to accommodate other methods, but for the moment
[they're disinclined to do so](https://github.com/sfackler/rust-openssl/issues/1283).

For the time being, you'll also need to add this entry to the `patch` section, too:

```
autotools = { git = "https://github.com/dubiousjim/autotools-rs", branch = "master" }
```

But once a newer version of this package (> 0.2.1) is published, this will no longer be necessary.

This package builds and provides linking information for each of LibreSSL's `libtls`, `libssl`, and `libcrypto`. However `openssl-sys` will only include the last two of these. If you want to link against LibreSSL's `libtls`, consider the [libtls](https://lib.rs/crates/libtls) package. (Though this doesn't yet seem to provide a mechanism for using a vendored copy of LibreSSL.)


# License

This project is licensed under either of

 * Apache License, Version 2.0, (<!-- [LICENSE-APACHE](LICENSE-APACHE) or -->
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license (<!-- [LICENSE-MIT](LICENSE-MIT) or -->
   http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in libressl-src by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
