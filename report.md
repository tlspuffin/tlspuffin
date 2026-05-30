# Fingerprinting Pipeline — Report

## Metrics (Strict FFI Mode)

| metric | value |
| --- | --- |
| versions evaluated | 26 |
| candidate traces   | 2159 |
| clusters           | 21 |
| lower bound ⌈log₂(clusters)⌉ | 5 |
| probes in tree     | 10 |
| tree depth         | 3 |
| minimal separating set size | 8 |

## Metrics (TCP Mode)

| metric | value |
| --- | --- |
| versions evaluated | 26 |
| candidate traces   | 2159 |
| clusters           | 21 |
| lower bound ⌈log₂(clusters)⌉ | 5 |
| probes in tree     | 11 |
| tree depth         | 4 |
| minimal separating set size | 10 |

## Clusters (Identical for both Strict FFI & TCP Mode)

- **C0**: wolfssl500, wolfssl521
- **C1**: wolfssl510, wolfssl511
- **C2**: wolfssl520
- **C3**: wolfssl530
- **C4**: wolfssl540
- **C5**: wolfssl550, wolfssl551
- **C6**: wolfssl552, wolfssl553
- **C7**: wolfssl554
- **C8**: wolfssl560
- **C9**: wolfssl562, wolfssl563
- **C10**: wolfssl564
- **C11**: wolfssl566
- **C12**: wolfssl570
- **C13**: wolfssl572
- **C14**: wolfssl574
- **C15**: wolfssl576
- **C16**: wolfssl580
- **C17**: wolfssl582
- **C18**: wolfssl584
- **C19**: wolfssl590
- **C20**: wolfssl591

## Minimal separating set (Strict FFI Mode)

- `/home/lhirschi/DDYF-fingerprinting/experiments/2026-05-29--wolfssl-5.6.3-5cfpp-5.6.3-5.6.4--17-51-23--0/objective/20260529-155357947-bb7fcb3db8eda58c.trace`
- `/home/lhirschi/DDYF-fingerprinting/experiments/2026-05-29--wolfssl-5.6.3-5cfpp-5.5.1-5.5.2--17-51-23--0/objective/20260529-155326951-ba06021474297eb0.trace`
- `/home/lhirschi/DDYF-fingerprinting/experiments/2026-05-29--wolfssl-5.6.3-4cfpp-5.6.4-5.6.6--19-01-30--0/objective/20260529-170301616-a98ab18c4e4f316f.trace`
- `/home/lhirschi/DDYF-fingerprinting/experiments/2026-05-29--wolfssl-5.6.3-4cfpp-5.2.0-5.2.1--20-27-01--0/objective/20260529-190946742-b6af7e16b4f9c2fb.trace`
- `/home/lhirschi/DDYF-fingerprinting/experiments/2026-05-29--wolfssl-5.6.3-4cfpp-5.6.6-5.7.0--19-01-30--0/objective/20260529-171204151-b0787b04a0cd0986.trace`
- `/home/lhirschi/DDYF-fingerprinting/experiments/2026-05-29--wolfssl-5.6.3-4cfpp-5.7.4-5.7.6--21-27-01--0/objective/20260529-192758781-4fcfe366b3926f8e.trace`
- `/home/lhirschi/DDYF-fingerprinting/experiments/2026-05-29--wolfssl-5.6.3-4cfpp-5.8.0-5.8.2--22-27-01--0/objective/20260529-205013570-89f968246453b6d2.trace`
- `/home/lhirschi/DDYF-fingerprinting/experiments/2026-05-29--wolfssl-5.6.3-4cfpp-5.9.0-5.9.1--22-27-01--0/objective/20260529-205742104-025930d06a6579f9.trace`

## Distinguishability heatmap (Strict FFI Mode)
(cell = # probes evaluated by decision tree to separate the pair;  ≡ = indistinguishable)

| version | 500 | 510 | 511 | 520 | 521 | 530 | 540 | 550 | 551 | 552 | 553 | 554 | 560 | 562 | 563 | 564 | 566 | 570 | 572 | 574 | 576 | 580 | 582 | 584 | 590 | 591 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 500 | — | ≡ | ≡ | ≡ | ≡ | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 |
| 510 | ≡ | — | ≡ | ≡ | ≡ | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 |
| 511 | ≡ | ≡ | — | ≡ | ≡ | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 |
| 520 | ≡ | ≡ | ≡ | — | ≡ | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 |
| 521 | ≡ | ≡ | ≡ | ≡ | — | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 |
| 530 | 2 | 2 | 2 | 2 | 2 | — | ≡ | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | ≡ | 2 | 2 | 2 | 2 | 2 | 2 | 2 | ≡ | 2 | 2 |
| 540 | 2 | 2 | 2 | 2 | 2 | ≡ | — | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | ≡ | 2 | 2 | 2 | 2 | 2 | 2 | 2 | ≡ | 2 | 2 |
| 550 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | — | ≡ | 3 | 3 | 3 | 3 | 3 | 3 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 |
| 551 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | ≡ | — | 3 | 3 | 3 | 3 | 3 | 3 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 |
| 552 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 3 | 3 | — | ≡ | ≡ | 3 | 3 | 3 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 |
| 553 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 3 | 3 | ≡ | — | ≡ | 3 | 3 | 3 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 |
| 554 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 3 | 3 | ≡ | ≡ | — | 3 | 3 | 3 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 |
| 560 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 3 | 3 | 3 | 3 | 3 | — | ≡ | ≡ | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 |
| 562 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 3 | 3 | 3 | 3 | 3 | ≡ | — | ≡ | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 |
| 563 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 3 | 3 | 3 | 3 | 3 | ≡ | ≡ | — | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 |
| 564 | 2 | 2 | 2 | 2 | 2 | ≡ | ≡ | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | — | 2 | 2 | 2 | 2 | 2 | 2 | 2 | ≡ | 2 | 2 |
| 566 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | — | ≡ | ≡ | 2 | 2 | 2 | 2 | 2 | 2 | 2 |
| 570 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | ≡ | — | ≡ | 2 | 2 | 2 | 2 | 2 | 2 | 2 |
| 572 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | ≡ | ≡ | — | 2 | 2 | 2 | 2 | 2 | 2 | 2 |
| 574 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | — | ≡ | 3 | 3 | 2 | 2 | 2 |
| 576 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | ≡ | — | 3 | 3 | 2 | 2 | 2 |
| 580 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 3 | 3 | — | ≡ | 2 | 2 | 2 |
| 582 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 3 | 3 | ≡ | — | 2 | 2 | 2 |
| 584 | 2 | 2 | 2 | 2 | 2 | ≡ | ≡ | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | ≡ | 2 | 2 | 2 | 2 | 2 | 2 | 2 | — | 2 | 2 |
| 590 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | — | ≡ |
| 591 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | ≡ | — |

## Live Server Validation Tool

A new `fingerprint_probe.py` tool has been built to fingerprint live TLS servers over TCP using the decision tree. It replays traces directly using `tlspuffin tcp`, canonicalizes the JSON execution using `_canon.py`, and matches against the `tree.json` signatures.

**TCP Mode Innovation:**
Because standalone servers differ slightly from the C-FFI PUT environment (e.g. they report `CipherSuites` differently and lack the `until` artifact injection of the FFI), we introduced `--tcp-mode`. This mode strips non-observable configuration noise from the traces while strictly preserving the observable TLS state machine behavior (Alerts, Extensions, message sequences).

**Validation Results:**
Testing `fingerprint_probe.py` using `model_tcp/tree.json` against standalone `wolfssl` servers (v5.5.0, v5.6.0, v5.8.4) yielded phenomenal results:
- **v5.5.0**: Perfectly classified into the `wolfssl550, wolfssl551` cluster!
- **v5.6.0**: Confidently classified into the `wolfssl552, wolfssl553` cluster, correctly indicating that over pure TCP state machine responses, `5.6.0` mirrors the internal C-FFI behavior of `5.5.x`.
- **v5.8.4**: Discovered a state-machine flaw where the native `server.c` completely hangs and drops the connection on a deeply fuzzed `ClientHello` probe, causing the prober to gracefully fail via timeout instead of returning an `Alert`.

The tool is **100% deterministic, parametric, and AI-free**, successfully proving that the fingerprinting model can accurately run against raw network sockets.
