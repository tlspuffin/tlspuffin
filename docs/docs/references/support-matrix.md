---
title: 'Support Matrix'
---

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

*tlspuffin* provides tooling to download, patch, and build several *preset* library configurations.
This page describes the current support for these presets.

:::warning[tooling support]

The process for building the preset libraries is currently transitioning to use the *mk_vendor* tool
in a manner consistent across all presets using:
```
./tools/mk_vendor make <preset>
```

As this is still work in progress, if a preset is marked with no *mk_vendor* support, you will need to build it through cargo:
```
cargo build --release -p tlspuffin --features=<preset>[,asan]
```
In that case, you can enable or disable ASAN by using the feature flag `asan`, in addition to the `<preset>`. For example:
```shell
cargo build --release -p tlspuffin --features=wolfssl540,asan
```
will build `tlspuffin` for the WolfSSL540 PUT with ASAN enabled.
:::

<Tabs>

  <TabItem value="openssl" label="OpenSSL" default>
    | Version    | ASAN support[^1]  | security claims | transcript extraction | mk_vendor preset[^2]   |
    | :--------: | :---------------: | :-------------: | :-------------------: | ---------------------- |
    | 3.1.2      | yes               | yes             | yes                   | `openssl:openssl312`   |
    | 1.1.1u     | yes               | yes             | yes                   | `openssl:openssl111u`  |
    | 1.1.1k     | yes               | yes             | yes                   | `openssl:openssl111k`  |
    | 1.1.1j     | yes               | yes             | yes                   | `openssl:openssl111j`  |
    | 1.0.2u     | yes               | yes             | yes                   | `openssl:openssl102u`  |
    | 1.0.1f     | yes               | yes             | yes                   | `openssl:openssl101f`  |
  </TabItem>

  <TabItem value="libressl" label="LibreSSL">
    | Version    | ASAN support[^1]  | security claims | transcript extraction | mk_vendor preset[^2]                             |
    | :--------: | :---------------: | :-------------: | :-------------------: | ------------------------------------------------ |
    | 3.3.3      | yes               | no              | no                    | *work in progress* (cargo preset: `libressl333`) |
  </TabItem>

  <TabItem value="wolfssl" label="wolfSSL">
    | Version    | ASAN support[^1]  | security claims | transcript extraction | mk_vendor preset[^2]                             |
    | :--------: | :---------------: | :-------------: | :-------------------: | ------------------------------------------------ |
    | 4.3.0      | yes               | no              | yes                   | *work in progress* (cargo preset: `wolfssl430`)  |
    | 5.1.0      | yes               | no              | yes                   | *work in progress* (cargo preset: `wolfssl510`)  |
    | 5.2.0      | yes               | no              | yes                   | *work in progress* (cargo preset: `wolfssl520`)  |
    | 5.3.0      | yes               | no              | yes                   | *work in progress* (cargo preset: `wolfssl530`)  |
    | 5.4.0      | yes               | no              | yes                   | *work in progress* (cargo preset: `wolfssl540`)  |
  </TabItem>

  <TabItem value="boringssl" label="BoringSSL">
    | Version    | ASAN support[^1]  | security claims | transcript extraction | mk_vendor preset[^2]   |
    | :--------: | :---------------: | :-------------: | :-------------------: | ---------------------- |
    | [2023.11](https://github.com/google/boringssl/commit/698aa894c96412d4df20e2bb031d9eb9c9d5919a)    | yes               | no              | yes                   | *work in progress* (cargo preset: `boringssl202311`) |
    | [2024.03](https://github.com/google/boringssl/commit/368d0d87d0bd00f8227f74ce18e8e4384eaf6afa)    | yes               | no              | yes                   | *work in progress* (cargo preset: `boringssl202403`) |
  </TabItem>

</Tabs>

[^1]: ASAN is available on platforms where *Clang* has [support for ASAN](https://clang.llvm.org/docs/AddressSanitizer.html#supported-platforms)
[^2]: [*mk_vendor*](./mk_vendor) let you build a preset library independently of *tlspuffin*'s cargo-based build system, by running `./tools/mk_vendor make <preset>`