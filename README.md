# DY Fuzzing: Formal Dolev-Yao Models Meet Cryptographic Protocol Fuzz Testing

[![unstable](http://badges.github.io/stability-badges/dist/unstable.svg)](http://github.com/badges/stability-badges)[![CI Status](https://img.shields.io/github/actions/workflow/status/tlspuffin/tlspuffin/on-pr-merged.yml?branch=main&style=flat-square&label=CI)](https://github.com/tlspuffin/tlspuffin/actions/workflows/on-pr-merged.yml)

## What is `puffin`?

The `puffin` fuzzer is the reference implementation for the [Dolev-Yao fuzzing approach](https://www.computer.org/csdl/pds/api/csdl/proceedings/download-article/1Ub234bjuWA/pdf) (eprint publicly accessible [here](https://eprint.iacr.org/2023/57)).
It aims at fuzzing cryptographic protocol implementations. For now, it is shipped with harnesses for several TLS implementations (OpenSSL, BoringSSL, LibreSSL, and wolfSSL) and
preliminary versions of a harness for OpenSSH. We built `puffin` so that new protocols and protocol implementations can be added.
Internally, `puffin` uses the library [LibAFL](https://aflplus.plus/libafl-book/) to drive the fuzzing loop.

We sometimes use `tlspuffin` instead of `puffin` to name the fuzzer and this project. This is because the first protocol we implemented was TLS. However, `puffin` and DY fuzzing in general are not limited to the TLS protocol.

## Building and using `puffin`
Please refer to the up-to-date [user manual](https://tlspuffin.github.io/docs/overview).
We also provide a [quickstart guide](https://tlspuffin.github.io/docs/guides/quickstart) for a fast setup.

## License

Licensed under either of

* Apache License, Version 2.0
  ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license
  ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/blog/license/mit)

at your option.
Note that tlspuffin also contains code/modification from external projects. See [THIRD_PARTY](THIRD_PARTY) for more details.

## Contributing to `puffin`
We welcome any external contributions through [pull requests](https://github.com/tlspuffin/tlspuffin/pulls), see for example the [list](https://github.com/tlspuffin/tlspuffin/issues?q=is%3Aissue%20state%3Aopen%20(label%3A%22help%20wanted%22%20OR%20label%3A%22good%20first%20issue%22%20)%20) of "good first issues".  
Please refer to the up-to-date [developer documentation](https://tlspuffin.github.io/docs/overview).
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.


## Background on DY Fuzzing
Critical and widely used cryptographic protocols have repeatedly been found to contain flaws in their design and implementation. A prominent class of such vulnerabilities is **logical attacks**, e.g., attacks that exploit flawed protocol logic. Automated formal verification methods, based on the **Dolev-Yao (DY) attacker** (shown in green in the Figure below), formally define and excel at finding such flaws but operate only on abstract specification models. Fully automated verification of existing protocol implementations is today still out of reach. This leaves open whether such implementations are secure. Unfortunately, this blind spot hides numerous attacks, such as recent logical attacks on widely used TLS implementations introduced by implementation bugs.

### Challenges in Detecting Implementation-Level Logical Attacks

We are concerned with finding implementation-level logical attacks in large cryptographic protocol code bases. For this, we build on **fuzz testing**. However, state-of-the-art fuzzers (shown on the left in the Figure) cannot capture the class of logical attacks for two main reasons. First, they fail to effectively **capture the DY attacker**, particularly the ability of structural modifications on the term representation of messages in DY models (e.g., re-signing a message with some adversarial-controlled key), a prerequisite to capture logical attacks. We emphasize that logical attacks may trigger protocol or memory vulnerabilities. Second, they cannot detect **protocol vulnerabilities**, which are security violations at the protocol level, e.g., for the attacks that trigger protocol vulnerabilities, which are not memory-related, such as an authentication bypass.

###  DY Model-Guided Fuzzing

We answer in [1] by proposing a novel and effective technique called DY model-guided fuzzing, which precludes logical attacks against protocol implementations. The main idea is to consider as possible test cases the set of abstract DY executions of the DY attacker, and use a novel mutation-based fuzzer to explore this set (shown in the middle of the Figure). The DY fuzzer concretizes each abstract execution to test it on the program under test. This approach enables reasoning at a more structural and security-related level of messages represented as formal terms (e.g., decrypt a message and re-encrypt it with a different key) instead of random bit-level modifications that are much less likely to produce relevant logical adversarial behaviors.


<center><img src="https://tlspuffin.github.io/assets/images/DYF_illustrations-7f3ce4e536a9e941373f30a7de1e1b94.png " width="900"></center>
<center>The gap filled by DY fuzzing and tlspuffin (shown in the middle).</center>


### Implementation

[tlspuffin](https://github.com/tlspuffin/tlspuffin) is our reference implementation of such a DY fuzzer. It is built modularly so that new protocols and Programs Under Test (PUTs) can be integrated and tested. We have already integrated the TLS protocol and the OpenSSL, BoringSSL, WolfSSL, and LibreSSL PUTs. tlspuffin has already found 8 CVEs (see table below), including five new ones (including a critical one) that were all acknowledged and patched.
Interestingly and as a witness to the claims above,
those five newly found bugs are not currently found by state-of-the-art fuzzers [1].


| CVE ID                                                             | CVSS | Type         | Novel                                   | Version   |
|--------------------------------------------------------------------|-----|--------------|-----------------------------------------|---------|
| [2021-3449](https://www.cve.org/CVERecord?id=CVE-2021-3449)        | 5.9 | Server DoS | ❌                                       | 1.1.1j   |
| [2022-25638](https://www.cve.org/CVERecord?id=CVE-2022-25638)      | 6.5 | Auth. Bypass | ❌                                       | 5.1.0   |
| [2022-25640](https://www.cve.org/CVERecord?id=CVE-2022-25640)      | ️7.5❗ | Auth. Bypass | ❌                                      | 5.1.0     |
| [2022-38152](https://www.cve.org/CVERecord?id=CVE-2022-38152)      | 7.5❗ | Server DoS | ✅                                       | 5.4.0     |
| [2022-38153](https://www.cve.org/CVERecord?id=CVE-2022-38153)      | 5.9 | Client DoS | ✅ | 5.3.0     |
| [2022-39173](https://www.cve.org/CVERecord?id=CVE-2022-39173)      | 7.5❗ | Server DoS | ✅ | 5.5.0    |
| [2022-42905](https://www.cve.org/CVERecord?id=CVE-2022-42905)      | 9.1❗ | Info. Leak | ✅ | 5.5.0   |
| [2023-6936](https://www.cve.org/CVERecord?id=CVE-2023-6936)      | 5.3 | Info. Leak | ✅ | 5.6.6     |


Some features:
* Uses the [LibAFL fuzzing framework](https://github.com/AFLplusplus/LibAFL)
* Fuzzer which is inspired by the [Dolev-Yao models](https://en.wikipedia.org/wiki/Dolev%E2%80%93Yao_model) used in protocol verification
* Domain specific mutators for Protocol Fuzzing!
* Supported Libraries Under Test:
  * OpenSSL 1.0.1f, 1.0.2u, 1.1.1k
  * LibreSSL 3.3.3
  * wolfSSL 5.1.0 - 5.4.0
  * BoringSSL (last commit tested 368d0d87d0bd00f8227f74ce18e8e4384eaf6afa)
    - Disclaimer : there is a bug will building in debug mode with asan (set `lto=true` in `Cargo.toml` to circumvent)
* Reproducible for each LUT. We use sources from fresh git clone of vendor libraries.
* 70% Test Coverage
* Written in Rust!



## Team

- [Tom Gouville](https://github.com/aeyno) - [Loria](https://www.loria.fr), [Inria](https://www.inria.fr)
- [Lucca Hirschi](https://members.loria.fr/LHirschi/) - [Loria](https://www.loria.fr), [Inria](https://www.inria.fr)
- [Steve Kremer](https://members.loria.fr/SKremer/) - [Loria](https://www.loria.fr), [Inria](https://www.inria.fr)
- [Michael Mera](https://github.com/michaelmera) - [Loria](https://www.loria.fr), [Inria](https://www.inria.fr)
- [Max Ammann](https://github.com/maxammann)

This project is partially funded by the [ANR JCJC project ProtoFuzz](https://project.inria.fr/protofuzz/).
We are still looking to hire motivated students/postdocs/engineers in Nancy, France as part of this project.

## References

[1] [M. Ammann, L. Hirschi and S. Kremer, "DY Fuzzing: Formal Dolev-Yao Models Meet Cryptographic Protocol Fuzz Testing," in 2024 IEEE Symposium on Security and Privacy (SP), San Francisco, CA, USA, 2024 pp. 99-99.](https://www.computer.org/csdl/pds/api/csdl/proceedings/download-article/1Ub234bjuWA/pdf)

[2] [DY Fuzzing Poster](https://tlspuffin.github.io/assets/files/SP24_Poster-f90cdd5b2df492a64fa18089c98a7b2e.pdf)