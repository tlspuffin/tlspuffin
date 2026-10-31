# LibreSSL 3.x patches

`tls13-claims.patch` is applied on top of the **official release tarball** (e.g.
`libressl-3.3.3.tar.gz`). It threads a `struct tls13_ctx *` through the TLS 1.3 key schedule
(`tls13_hkdf_expand_label*`, `tls13_derive_*`, `tls13_record_layer_set_*_traffic_key`) so that
the transcript claim can be emitted from `tls13_hkdf_expand_label_with_length`, and adds the
`claim`/`claim_ctx` fields to `struct ssl_st`.

The standalone parts live outside the patch to keep it small: `../puffin_claims.c` is appended to
`ssl/ssl_lib.c` by `../builder.cmake`.

3.3.3 is a frozen release, so this patch is not expected to need rebasing. To regenerate it from a
modified tree: extract the tarball twice (`a/`, `b/`), edit `b/`, then
`diff -ruN a b > tls13-claims.patch` (and strip the timestamps from the headers).
