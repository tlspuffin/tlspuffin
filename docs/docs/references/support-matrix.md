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

ASAN is a modifier of the name (e.g. `openssl:3.4.0,asan`, also written `openssl:openssl340-asan`): `mk_vendor modifiers <vendor>` lists them.

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
    | 5.8.4      | yes               | yes             | yes                   | `wolfssl:wolfssl584`  |
    | 5.8.0      | yes               | yes             | yes                   | `wolfssl:wolfssl580`  |
    | 5.7.2      | yes               | yes             | yes                   | `wolfssl:wolfssl572`  |
    | 5.5.2      | yes               | yes             | yes                   | `wolfssl:wolfssl552`  |
    | 5.4.0      | yes               | yes             | yes                   | `wolfssl:wolfssl540`  |
    | 5.3.0      | yes               | yes             | yes                   | `wolfssl:wolfssl530`  |
    | 5.2.0      | yes               | yes             | yes                   | `wolfssl:wolfssl520`  |
    | 5.1.1      | yes               | yes             | yes                   | `wolfssl:wolfssl511`  |
    | 5.1.0      | yes               | yes             | yes                   | `wolfssl:wolfssl510`  |
    | 5.0.0      | yes               | yes             | yes                   | `wolfssl:wolfssl500`  |
    | 4.4.0      | yes               | yes             | yes                   | `wolfssl:wolfssl440`  |
    | 4.3.0      | yes               | yes             | yes                   | `wolfssl:wolfssl430`  |
</TabItem>
 


  <TabItem value="boringssl" label="BoringSSL">
    | Version    | ASAN support[^1]  | security claims | transcript extraction | mk_vendor preset[^2]   |
    | :--------: | :---------------: | :-------------: | :-------------------: | ---------------------- |
    | 0.20260508.0 | yes             | yes             | yes                   | `boringssl:boringssl20260508` |
  </TabItem>

</Tabs>

## SSH (*sshpuffin*)

*sshpuffin* builds its PUTs the same way, from the `libssh` and `wolfssh` presets (e.g. `./tools/mk_vendor make libssh:0.12.2,asan`).
Its single-PUT objective oracle is the entity-authentication oracle[^3]; a version marked otherwise does not get the full objective oracle.

<Tabs>

  <TabItem value="libssh" label="libssh" default>
    | Version    | ASAN support[^1]  | security claims | entity-auth oracle: C1 · C2 · S1[^3] | mk_vendor preset[^2] |
    | :--------: | :---------------: | :-------------: | :----------------------------------: | -------------------- |
    | 0.12.2     | yes               | yes             | yes · yes · yes                      | `libssh:libssh0122`  |
    | 0.11.4     | yes               | yes             | yes · yes · yes                      | `libssh:libssh0114`  |
    | 0.10.4     | yes               | yes             | yes · yes · yes                      | `libssh:libssh0104`  |
    | 0.8.3      | yes               | yes             | **no** · partial · partial[^4]       | `libssh:libssh083`   |
  </TabItem>

  <TabItem value="wolfssh" label="wolfSSH">
    | Version    | ASAN support[^1]  | security claims | entity-auth oracle: C1 · C2 · S1[^3] | mk_vendor preset[^2] |
    | :--------: | :---------------: | :-------------: | :----------------------------------: | -------------------- |
    | 1.6.0      | yes               | yes             | yes · yes · yes                      | `wolfssh:wolfssh160`  |
    | 1.5.0      | yes               | yes             | yes · yes · yes                      | `wolfssh:wolfssh150`  |
    | 1.4.21     | yes               | yes             | yes · yes · yes                      | `wolfssh:wolfssh1421` |
    | 1.4.20     | yes               | yes             | yes · yes · yes                      | `wolfssh:wolfssh1420` |
  </TabItem>

</Tabs>

[^1]: ASAN is available on platforms where *Clang* has [support for ASAN](https://clang.llvm.org/docs/AddressSanitizer.html#supported-platforms)
[^2]: [*mk_vendor*](./mk_vendor) let you build a preset library independently of *tlspuffin*'s cargo-based build system, by running `./tools/mk_vendor make <preset>`
[^3]: The entity-authentication oracle (`SshSecurityViolationPolicy`, see `hunt/ENTITY-AUTH-ORACLE.md`) has three invariants, each checked by the harness: **C1**, a client is never keyed without the server's host-key signature having verified; **C2**, a client never accepts user-authentication success before it is keyed; **S1**, a server never authenticates a client its harness did not approve. *yes*: instrumented on that version (its accessors are compiled in), no false alarm on the honest seed corpus, and shown to fire. C1 and S1 were shown to fire on every version marked *yes*, by mutation tests that disable the harness's record. C1 also fires on the CVE-2025-11625 witness (wolfSSH 1.4.20). C2 fires on the CVE-2025-14942 witness (wolfSSH 1.4.20, 1.4.21); later wolfSSH versions use the same accessor, which only a new bug could make fire. On libssh, C2 was shown to fire by a mutation test of the client's authentication state.
[^4]: **libssh 0.8.3 does not support the full objective oracle.** C1 is not instrumented: 0.8.x verifies the server's host key in another key-exchange code, which the host-key record does not cover. C2 and S1 are instrumented but stay inactive in campaigns with the standard seed corpora, which negotiate AES-GCM, a cipher 0.8.3 lacks: the key exchange fails before any authentication. S1 was shown to fire there only with the non-AEAD seed `seed_client_attacker_full_ctr`, which no corpus registers.
