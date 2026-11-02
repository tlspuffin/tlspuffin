# OpenSSL claims instrumentation

The same instrumentation is applied on the official sources of every OpenSSL version >= 1.1.1
(`builder.cmake`). Nothing is forked: it is made of

- `puffin_claims.h`: the hooks (`PUFFIN_CLAIM_READ`, ...), the fields added to the connection
  structure and the HKDF-label to claim mapping. Copied to `ssl/`.
- `puffin_claims.c`: claim registration and extraction (`register_claimer`, `fill_claim`, ...) and
  the TLS state to claim mapping. Appended to `ssl/ssl_lib.c`. The few differences between versions
  (location of the connection state, signature algorithm field) are handled by macros at the top
  of the file.
- `apply_hooks.cmake`: inserts the one-line hooks (`PUFFIN_CLAIM_READ`, `PUFFIN_CLAIM_WRITE`, ...)
  at literal anchors in `ssl_local.h`, `statem.c`, `statem_srvr.c` and `tls13_enc.c`. Every anchor
  must match exactly once, otherwise the build fails.

OpenSSL >= 3.2 additionally gets `../patches/deterministic-time.patch`, which makes
`ossl_time_now()` deterministic.

To support a new version, build it: a failing anchor or a compilation error points at what changed.
