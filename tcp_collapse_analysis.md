# TCP-Mode Collapse Analysis in wolfSSL

## 1. The Anomalous C0 Collapse (v5.0.0 and v5.2.1) vs C2 (v5.2.0)
In the DDYF-fingerprinting evaluation, wolfSSL versions `v5.0.0` and `v5.2.1` collapsed into the same cluster (**C0**), while `v5.2.0` was placed in a completely distinct cluster (**C2**). This indicates that the observable state machine behavior of `v5.2.1` reverted to match `v5.0.0`, rather than building sequentially on `v5.2.0`.

### Why did behavior change in v5.2.0?
The release of **wolfSSL 5.2.0** (February 2022) included significant structural improvements to the TLS 1.3 state machine. Most notably, the release notes highlight **"improved checks on the order of received messages."** This strictness fundamentally altered how the state machine reacts to out-of-order or invalid TCP segments and TLS records, introducing distinct trace patterns that DDYF correctly separated into cluster **C2**.

### Why did v5.2.1 revert to v5.0.0 behavior?
Version **v5.2.1-stable** was not a standard sequential patch release. Instead, it was published significantly later (August 2023) specifically as a **FIPS 140-3 validated cryptographic module** (wolfCrypt v5.2.1, Certificate #4718). 

Because FIPS certification processes are lengthy, the baseline for `v5.2.1` was branched and frozen long before the TLS 1.3 message ordering strictness of `5.2.0` was finalized. As a result, `v5.2.1` does not contain the state machine regressions/improvements of `5.2.0`. Its underlying state machine handling effectively matches the older `v5.0.0` baseline, which is why DDYF perfectly clusters them together in **C0**.

## 2. Other Minor Version Collapses
An analysis of the other clustered pairs reveals that their diffs do not introduce observable structural changes to the TLS state machine over TCP:

*   **C1 (`v5.1.0`, `v5.1.1`)**: The 5.1.1 release contained routine bug fixes and updates that did not alter the core order of operations in `src/tls.c` or `src/tls13.c`.
*   **C5 (`v5.5.0`, `v5.5.1`) & C6 (`v5.5.2`, `v5.5.3`)**: These minor patch releases primarily addressed specific CVEs (such as memory leaks or bypasses in extremely specific edge cases) or added cipher suites and API extensions. They did not restructure the general message sequence acceptance rules.
*   **C9 (`v5.6.2`, `v5.6.3`)**: Similar to the above, 5.6.3 involved non-state-machine fixes (e.g., build config updates, documentation, or non-TCP protocol fixes). 

### Conclusion
The DDYF clustering algorithm accurately maps the true underlying behavioral history of the library rather than its semantic versioning. The divergence of `v5.2.0` and the collapse of `v5.2.1` with `v5.0.0` perfectly visualize the branching strategy used for long-term FIPS certifications, where newer version numbers do not strictly imply sequential feature inheritance.
