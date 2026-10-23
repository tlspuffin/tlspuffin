---
title: 'Support Matrix'
---

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

*tlspuffin* provides tooling to download, patch, and build several *preset* library configurations.
This page describes the current support for these presets.

Each preset is built with the *mk_vendor* tool:
```
./tools/mk_vendor make <preset>
```

Then build *tlspuffin* with the harnesses (CPUTs) of all the libraries that have been built:
```
cargo build --release -p tlspuffin --features=cputs
```

The ASAN variants are separate presets (e.g. `openssl:openssl340-asan`).

<Tabs>

  <TabItem value="openssl" label="OpenSSL" default>
    | Version    | ASAN support[^1]  | security claims | transcript extraction | mk_vendor preset[^2]   |
    | :--------: | :---------------: | :-------------: | :-------------------: | ---------------------- |
    | 3.4.1      | yes               | yes             | yes                   | `openssl:openssl341`   |
    | 3.4.0      | yes               | yes             | yes                   | `openssl:openssl340`   |
    | 3.2.0      | yes               | yes             | yes                   | `openssl:openssl320`   |
    | 3.1.2      | yes               | yes             | yes                   | `openssl:openssl312`   |
    | 1.1.1u     | yes               | yes             | yes                   | `openssl:openssl111u`  |
    | 1.1.1k     | yes               | yes             | yes                   | `openssl:openssl111k`  |
    | 1.1.1j     | yes               | yes             | yes                   | `openssl:openssl111j`  |
    | 1.0.2u     | yes               | no              | no                    | `openssl:openssl102u`  |
    | 1.0.1f     | yes               | no              | no                    | `openssl:openssl101f`  |
  </TabItem>

  <TabItem value="libressl" label="LibreSSL">
    | Version    | ASAN support[^1]  | security claims | transcript extraction | mk_vendor preset[^2]                             |
    | :--------: | :---------------: | :-------------: | :-------------------: | ------------------------------------------------ |
    | 4.2.1      | yes               | yes             | yes                   | `libressl:libressl421`                           |
    | 3.3.3      | yes               | yes             | yes                   | `libressl:libressl333`                           |
  </TabItem>

  <TabItem value="wolfssl" label="wolfSSL">
    | Version    | ASAN support[^1]  | security claims | transcript extraction | mk_vendor preset[^2]                             |
    | :--------: | :---------------: | :-------------: | :-------------------: | ------------------------------------------------ |
    | 4.3.0      | yes               | no              | yes                   | `wolfssl:wolfssl430`  |
    | 5.1.0      | yes               | yes             | yes                   | `wolfssl:wolfssl510`  |
    | 5.2.0      | yes               | yes             | yes                   | `wolfssl:wolfssl520`  |    
    | 5.3.0      | yes               | yes             | yes                   | `wolfssl:wolfssl530`  |    
    | 5.4.0      | yes               | yes             | yes                   | `wolfssl:wolfssl540`  |    
    | 5.5.2      | yes               | yes             | yes                   | `wolfssl:wolfssl552`, WARNING: not fully functional |    
    | 5.7.2      | yes               | yes             | yes                   | `wolfssl:wolfssl572`  |    
    | 5.8.0      | yes               | yes             | yes                   | `wolfssl:wolfssl580`  |
</TabItem>
 


  <TabItem value="boringssl" label="BoringSSL">
    | Version    | ASAN support[^1]  | security claims | transcript extraction | mk_vendor preset[^2]   |
    | :--------: | :---------------: | :-------------: | :-------------------: | ---------------------- |
    | 0.20260508.0 | yes             | yes             | yes                   | `boringssl:boringssl20260508` |
  </TabItem>

</Tabs>

[^1]: ASAN is available on platforms where *Clang* has [support for ASAN](https://clang.llvm.org/docs/AddressSanitizer.html#supported-platforms)
[^2]: [*mk_vendor*](./mk_vendor) let you build a preset library independently of *tlspuffin*'s cargo-based build system, by running `./tools/mk_vendor make <preset>`