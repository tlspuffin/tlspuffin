---
title: 'Overview'
---
import Architecture from './libafl-architecture_new.drawio.svg';


# What is puffin?

The `puffin` fuzzer is the reference implementation for the [Dolev-Yao fuzzing approach](https://www.computer.org/csdl/pds/api/csdl/proceedings/download-article/1Ub234bjuWA/pdf) (eprint publicly accessible [here](https://eprint.iacr.org/2023/57)).
It aims at fuzzing cryptographic protocol implementations. For now, it is shipped with harnesses for several TLS implementations (OpenSSL, BoringSSL, LibreSSL, and wolfSSL) and 
preliminary versions of a harness for OpenSSH. We built `puffin` so that new protocols and protocol implementations can be added.
Internally, `puffin` uses the library [LibAFL](https://aflplus.plus/libafl-book/) to drive the fuzzing loop.

We sometimes use `tlspuffin` instead of `puffin` to name the fuzzer and this project. This is because the first protocol we implemented was TLS. However, `puffin` and DY fuzzing in general are not limited to the TLS protocol.

:::tip[Terminology]

We define some terms in the context of `puffin`:
- **Program Under Test** **(PUT)** (also called **vendor library**): a protocol implementation to be tested. For example: OpenSSL v3.1.2, wolfSSL v5.3.0, etc.
- **Harness**: a wrapper around a PUT that provides a common interface for the fuzzer to interact with the PUT. For example: we built one for all PUTs compatible with the OpenSSL API (hence all OpenSSL and LibreSSL PUTs versions).
- **Target**: a specific PUT version with its harness. This is the program that the fuzzer will interact with.
- **Trace**: a test-case representation, which is a sequence of protocol messages describing a protocol interaction of protocol agents (e.g., TLS clients, servers) with a network attacker. The specifity here is that protocol messages are represented as formal terms built with abstract function symbols such as: `encryption(.,.)`, `signature(.,.)`, `CLientHello(.,.,.,.)`, etc. This representation of protocol interactions stems from formal Dolev-Yao models, see our [paper](https://eprint.iacr.org/2023/57) for more details.

:::


## Fuzzing Loop

The following image shows the terminology and the flow of test cases through the fuzzer. We typically start the fuzzing with some "happy protocol flows" in the corpus and start the fuzzing loop depicted below:


<Architecture />


The main components of the fuzzer are:
- **State:** Comprising "Corpus" and "Objectives," this stores all test cases with their traces and metadata, with the Objectives focusing specifically on cases that have triggered security violations. Note that those test cases are structured *traces* of protocol messages represented as *formal terms* as defined in Dolev-Yao models.
- **Scheduler:** This selects and schedules test cases from the Corpus for mutation and re-testing, based on various strategic criteria.
- **Mutational Stage:** The "Mutator" alters a trace from a scheduled test case to create a mutated test case, which is then sent to the harness. The mutations transform traces and are able to modify the formal terms, hence the protocol messages, in a given trace, thus creating new kinds of protocol interactions.
- **Harness:** The harness executes the mutated test case in the Program Under Test (PUT) and observes the execution.
- **Feedback:** This component evaluates the observed outcomes of the test case execution, adding interesting cases to the Corpus for further testing.
- **Objective Oracle:** It checks test cases for violations of security policies, adding those that do violate to the Objectives for focused analysis.

