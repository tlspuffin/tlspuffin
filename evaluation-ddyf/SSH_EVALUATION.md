# DDYF artifact evaluation — SSH (sshpuffin) as a second protocol

This is the self-contained artifact support for the claims of the DDYF paper [A] about
**Differential Dolev–Yao Fuzzing (DDYF)**. It uses the SSH integration
(sshpuffin: **libssh 0.11.4** vs **wolfSSH 1.5.0**) as a *second* protocol — after
TLS — to substantiate three claims. It is deliberately narrow and transparent: we do
**not** claim a comprehensive security evaluation of either SSH stack.

Evidence is tagged **[live]** (a deterministic command re-run for this artifact) or
**[test]** (pinned by a unit test in the CI suite).

---

## Relationship to the tlspuffin artifact

There is a separate, earlier artifact evaluating **tlspuffin** (TLS). This SSH
artifact is deliberately kept distinct, for three reasons:

1. **Timeline / upstream drift.** SSH was integrated into puffin *after* TLS, and
   puffin evolved in between. This artifact is built on the **current upstream**
   puffin, so its framework is newer than the one the TLS artifact was frozen
   against — pinning both to a single puffin revision would have meant re-freezing
   one of them.
2. **This artifact is a superset.** It contains **both** tlspuffin **and** sshpuffin,
   and DDYF is integrated for **both** protocols here. The DDYF machinery for TLS is
   present and exercisable in this same tree — nothing TLS-specific was removed.
3. **We did not re-run the full TLS evaluation here (cost).** Because DDYF-for-TLS is
   present, the TLS evaluation *could* be reproduced in this tree (which would leave a
   single, unified artifact). We chose not to: a full TLS re-evaluation is expensive
   in compute and wall-clock time, and some numbers (performance, objective counts) would
   differ slightly from the frozen TLS artifact simply due to the newer puffin and
   different machines. Rather than publish subtly-shifted TLS numbers, we kept the
   authoritative TLS evaluation in its own artifact and made this one the
   authoritative **SSH** evaluation.

**Practical guidance:** everything needed to run **either** protocol is present here,
so for actually *using* or *extending* puffin/DDYF — TLS or SSH — prefer **this**
version (it is the up-to-date one). Use the separate tlspuffin artifact when you
specifically want to reproduce the frozen TLS numbers of the paper [A]. To reproduce
the SSH evaluation, run every command block below marked `# REPRODUCIBILITY STEPS`, in
order, from the repo root.

---

> Experiments presented in the paper were run on a machine with 48 AMD EPYC 9275F cores
> (96 threads) with hyperthreading enabled and 768 GiB of RAM. The machine was running
> Debian GNU/Linux 13.7 (trixie) with kernel 6.12. Expect some variability in the results
> when running on a different machine.

## Scaled-down experiments

The paper's headline campaigns run for **24–48 h**, so reproducing the exact paper numbers in
the allotted time is not feasible. The SSH checks in this document are therefore deliberately
**short**: the `[live]` commands take minutes, the `[test]` suite seconds, and the §2b
differential campaign is bounded to **~10 minutes** — so everything here reproduces in well
under an hour on a multi-core host. Each claim's commands live inline under its section
(§1, §2); they all first need the one-time §0 build, and within §2 the steps are ordered
((i) campaign → (ii) triage → (iii) per-bug counts).

## Prerequisites

All experiments with DDYF were run on **Linux** and may not work on other operating systems.

> A long SSH campaign can write a large number of objective/metadata files into one directory
> (tens of thousands in ~10 min; millions over a day) — make sure your filesystem can hold
> that many files in a single directory.
>
> Do not run two campaigns in the same working directory at once, or they will interfere.
> Experiment mode (`differential-experiment -t <title>`, §2b) already isolates each run under
> `experiments/<title>/`.

The triaging script `evaluation-ddyf/ssh/sort_objectives_libssh_wolfssh.py` reads the
environment variables `SSHPUFFIN_FIRST_PUT`, `SSHPUFFIN_SECOND_PUT` and
`SSHPUFFIN_TRIAGE_PARALLELISM` (the last selects how many objectives are triaged in parallel;
recommended maximum ≈ 2× core count). Overriding the PUT names lets the same buckets be
applied to a campaign run against another version of a PUT. `PUFFIN_PATH` must point at the
SSH binary (see §2b).

### Running with Nix

To ensure reproducibility, dependencies are managed with [Nix](https://nixos.org/). Run
everything inside a [Nix shell](https://nixos.wiki/wiki/Development_environment_with_nix-shell):

```bash
nix-shell ./shell.nix
```

The `evaluation-ddyf/` scripts are committed with the executable bit set and use
`#!/usr/bin/env bash`, so they run inside or outside the Nix shell. If the permissions were
lost while extracting an archive of this artifact, restore them with:

```bash
chmod +x ./evaluation-ddyf/*sh
```

---

## 0. Setup

All commands run from the repo root inside the project nix shell (`nix-shell`), which
provides clang-14, cargo, cmake and autotools. Build the two PUTs — the
non-ASAN-instrumented `libssh0114` (libssh 0.11.4) and `wolfssh150` (wolfSSH 1.5.0)
vendors — and the fuzzer:

```sh
# REPRODUCIBILITY STEPS
just mk_vendor libssh  libssh0114     # -> vendor/libssh0114
just mk_vendor wolfssh wolfssh150     # -> vendor/wolfssh150
cargo build -p sshpuffin --release    # -> target/release/sshpuffin
target/release/sshpuffin seed         # dumps the honest corpus to ./seeds (17 traces)
```

The `sshpuffin` harness links the ASAN runtime even against the non-instrumented
vendors, so prefix every run with `ASAN_OPTIONS=detect_leaks=0` (harness allocations
are not the target).

`differential-execute <put1> <put2> <trace>` runs one trace on both PUTs and prints
the **filtered** differences (the objective decision, i.e. after shadowing). It first
uniformises the two PUTs' configs, so a reported divergence is a real behavioural
difference, not a config artifact.

A single run on an honest seed (no divergence expected) looks like:

```sh
ASAN_OPTIONS=detect_leaks=0 target/release/sshpuffin differential-execute libssh0114 wolfssh150 ./seeds/seed_client_attacker_pubkey_aesgcm.trace
#   -> No differences
```

To *shadow* a divergence class means to suppress it before it becomes an objective —
either a documented benign non-bug, or a real bug already filed that we do not want
re-surfaced on every run. Two master switches in `sshpuffin/src/protocol.rs` gate this
(both default `true`): `SHADOW_KNOWN_BENIGN` (benign classes, e.g. libssh's stricter
banner-length limit) and `SHADOW_KNOWN_BUGS` (the filed wolfSSH port-echo, #1246). They are
runtime **environment variables** (`SSHPUFFIN_SHADOW_KNOWN_BENIGN` /
`SSHPUFFIN_SHADOW_KNOWN_BUGS`): set one to `0` to re-surface its class — **no rebuild** —
as used in §2b(iv) to reveal the shadowed port-echo bug on its seed.

---

## Claim 1 — the DDYF objective-oracle features generalise from TLS to SSH, and are sufficient

**Statement.** Every objective-oracle feature DDYF added for TLS was also needed for
SSH, and the *same* feature set is *sufficient*: before it the differential produced
false positives (drowning real divergences and inflating objective volume); with it,
honest seeds are 0-diff and real divergences still surface.

### 1a. Every TLS-derived oracle hook is used by SSH  [live]

The DDYF protocol-layer interface (`puffin::ProtocolTypes`) is identical for both
protocols; all its differential hooks are overridden by SSH
(`impl ProtocolTypes for SshProtocolTypes`, `sshpuffin/src/protocol.rs`):

| DDYF oracle feature (TLS origin)          | SSH hook | prevents the false positive… |
|-------------------------------------------|---|---|
| knowledge type whitelist                  | `differential_fuzzing_whitelist` | compare only meaningful knowledge types |
| claims blacklist                          | `differential_fuzzing_claims_blacklist` | volatile claims (timers, counters) |
| decryption recipes + encryption-key claim | `differential_fuzzing_terms_to_eval` (+ `fn_fold_s2c_transcript`, `fn_claim_exchange_hash`) | compare the *decrypted* record layer |
| PUT-config alignment API                  | `differential_fuzzing_uniformise_put_config` | algorithm-advertisement / cipher-choice diffs |
| custom comparison + field blacklist       | `AlignedTranscript` + 12× `#[comparable_ignore]`/`_synthetic` | server-chosen channel numbers, timestamps |
| objective filter                          | `differential_fuzzing_filter_diff` / `filter_diffs` | documented benign/known classes (shadowing) |

Each feature's necessity is pinned by a unit test that fails if it is removed  [test]:
`channel_number_choice_is_benign` vs `recipient_channel_divergence_fires` (field
blacklist), `concatenated_flights_reread_as_one_stream` (whole-stream decryption
recipe), `same_message_set_is_equal` / `cross_kind_transposition_fires` (alignment),
`fully_fail_closed_keeps_every_kind` / `transcript_presence_without_banner_is_kept` /
`userauth_success_asymmetry_is_always_kept` (filter safety). Run them:

```sh
# REPRODUCIBILITY STEPS
cargo test -p sshpuffin -p puffin
```
Observed: `test result: ok` for both crates — every named test passes; deleting or
weakening any one of the features above makes its test fail (that is what pins the
feature as load-bearing).

### 1b. After the features: honest seeds are 0-diff  [live]

With the full feature set (default build), every honest corpus seed is 0-diff:

```sh
# REPRODUCIBILITY STEPS
for t in ./seeds/*.trace; do
  echo "== $(basename $t)"
  ASAN_OPTIONS=detect_leaks=0 target/release/sshpuffin differential-execute libssh0114 wolfssh150 "$t"
done
```
Observed — **11 / 11 `No differences`**:
`channel_data, ext_info, forwarding, full_aesgcm, full_kexinit_synth,
impersonate_a_with_b, passwd_change, pubkey_aesgcm, pubkey_b, rekey,
unauthorized_key_c`.

That the *shadowing* is load-bearing (not just cosmetic) is shown concretely in §2b(iv):
the honest `forwarding` seed is `No differences` by default but re-surfaces the filed
wolfSSH port-echo bug the moment its shadow is disabled. Each individual feature's
necessity is pinned mechanically by the `[test]` suite above (remove a feature → a named
test fails), so no manual ablation is needed to trust it.

---

## Claim 2 — DDYF + triaging finds RFC-conformance (and other) bugs

**Statement.** Differential fuzzing plus triaging surfaces genuine cross-implementation
bugs. We do **not** claim a comprehensive evaluation — this is a capability
demonstration.

### 2a. By-design probes surface as differential objectives  [live]

Two of the four bugs are reproduced directly by by-design-divergent probe traces (the
minimised traces DDYF first found by fuzzing). Emit them and run each on both PUTs:

```sh
# REPRODUCIBILITY STEPS
cargo test -p sshpuffin emit_eval_probe_traces -- --ignored   # -> /tmp/eval_probes/
for t in bad_service kexinit_injection; do
  echo "== $t"
  ASAN_OPTIONS=detect_leaks=0 target/release/sshpuffin differential-execute libssh0114 wolfssh150 /tmp/eval_probes/$t.trace
done
```

Observed  [live] — both **DIFF**:

| probe | result | finding |
|---|---|---|
| `bad_service` | **DIFF** | wolfSSH accepts a `USERAUTH_REQUEST` with service ≠ `ssh-connection` (RFC 4252 §5), reaches `USERAUTH_SUCCESS` (msg 52) and opens the channel; libssh replies `USERAUTH_FAILURE` (msg 51) |
| `kexinit_injection` | **DIFF** | wolfSSH processes traffic during an incomplete peer-initiated rekey (RFC 4253 §7.1); libssh withholds |

(The same emitter also writes `unknown_msg` — an additional §11.4 tolerate-vs-abort
divergence, *not* one of the four headline bugs — and `dh_bad_exponent`, a both-reject
sanity control that is correctly `No differences`.)

### 2b. Campaign → triage → per-bug buckets  [live]

The end-to-end loop — fuzz, triage the objectives with the committed script, and confirm
each bug's bucket is non-empty. **Three** of the four bugs surface as differential
objectives and land in named triage buckets; the **fourth** (the filed port-echo) is
shadowed by default and is revealed by disabling its shadow on the seed that carries it.

**(i) Run a bounded differential campaign.** Experiment mode writes objectives under
`experiments/<title>/objective/` (leaving `./objective` untouched); 10 minutes on 4 cores
(here pinned to cores 0-3 — change `-c 0-3` to suit your host) is enough to hit the mutations:

```sh
# REPRODUCIBILITY STEPS
ASAN_OPTIONS=detect_leaks=0 \
  target/release/sshpuffin -c 0-3 differential-experiment libssh0114 wolfssh150 -t ddyf_eval
# The campaign fuzzes indefinitely — let it run ~10 minutes, then stop it with Ctrl-C.
# Objectives are written incrementally, so Ctrl-C loses nothing. If worker processes
# linger afterwards:  pkill -f 'release/sshpuffin.*differential-experiment'
```

**(ii) Triage the objectives** with the committed bucket script — it re-executes each
objective via `differential-execute --json` and files it into a named bucket. `PUFFIN_PATH`
must point at the SSH binary (the library default is the TLS one):

```sh
# REPRODUCIBILITY STEPS
OBJ=$(find experiments -type d -name objective -path '*ddyf_eval*' | sort | tail -1)   # newest campaign if several
# `python -m` needs an underscore-named package; bridge the hyphenated dir once (idempotent):
ln -sfn evaluation-ddyf evaluation_ddyf
ASAN_OPTIONS=detect_leaks=0 PUFFIN_PATH=target/release/sshpuffin \
  python -m evaluation_ddyf.ssh.sort_objectives_libssh_wolfssh "$OBJ"
```

**(iii) Confirm the three surfacing bugs' buckets are non-empty** — one count per bug:

```sh
# REPRODUCIBILITY STEPS
OBJ=$(find experiments -type d -name objective -path '*ddyf_eval*' | sort | tail -1)   # (re-)resolve; newest campaign if several
find "$OBJ/diverge_wolfssh_accepts_bad_service"    -name '*.trace' | wc -l  # RFC 4252 §5 service-name (wolfSSH)
find "$OBJ/known_rekey_kexinit_presence"           -name '*.trace' | wc -l  # RFC 4253 §7.1 incomplete rekey (wolfSSH)
find "$OBJ/diverge_wolfssh_accepts_libssh_rejects" -name '*.trace' | wc -l  # RFC 4253 §4.2 over-strict banner (libssh)
```

**What you should see:** three non-zero counts — all three bug buckets are non-empty.

For this artifact's run: a ~10-minute, 4-core campaign produced **37,313 objectives**;
triaging a random **8,000-objective sample** filled all three buckets —
`diverge_wolfssh_accepts_bad_service` = **10**, `known_rekey_kexinit_presence` = **9**,
`diverge_wolfssh_accepts_libssh_rejects` = **143** (the last is the wolfSSH-accepts /
libssh-rejects class, of which the over-strict banner is one member). To make this
**deterministic** (independent of campaign luck), the by-design probe traces sort into
exactly these three buckets — verified for this artifact by feeding them through the same
script: `bad_service → diverge_wolfssh_accepts_bad_service`,
`kexinit_injection → known_rekey_kexinit_presence`, and the oversized-banner probe
`banner_oversized → diverge_wolfssh_accepts_libssh_rejects` (libssh errors "too large
banner" on a >129-byte identification string while wolfSSH completes; emit it with
`cargo test -p sshpuffin --features claims emit_banner_probe_traces -- --ignored`). The
`diverge_wolfssh_accepts_bad_service` bucket was **added to the triaging script for this
finding**: both stacks complete without a status error, so it is neither an accept-vs-reject
status bucket nor benign — it matches the decrypted-transcript signature "`UserAuthSuccess`
(msg 52) added ∧ `UserAuthFailure` (msg 51) removed".

**(iv) The fourth bug is shadowed — reveal it on its seed.** The filed wolfSSH port-echo
(RFC 4254 §7.1, [wolfSSL/wolfssh#1246](https://github.com/wolfSSL/wolfssh/issues/1246)) rides the honest `forwarding` seed and is suppressed by
`SHADOW_KNOWN_BUGS`, so it is `No differences` by default and never becomes an objective.
Toggle the shadow to see it:

```sh
# REPRODUCIBILITY STEPS
# shadow ON (default): the known, filed bug stays suppressed
ASAN_OPTIONS=detect_leaks=0 target/release/sshpuffin differential-execute libssh0114 wolfssh150 seeds/seed_client_attacker_forwarding.trace
#   -> No differences
# shadow OFF: set the env var and re-run the SAME binary — no rebuild, no source edit
SSHPUFFIN_SHADOW_KNOWN_BUGS=0 ASAN_OPTIONS=detect_leaks=0 target/release/sshpuffin differential-execute libssh0114 wolfssh150 seeds/seed_client_attacker_forwarding.trace
#   -> msg 81 REQUEST_SUCCESS diverges: wolfSSH appends [0,0,0,22] (bound port 22); libssh sends a bare reply
```

**What you should see:** the first run prints `No differences` (shadow on); the second, with
`SSHPUFFIN_SHADOW_KNOWN_BUGS=0`, prints the port-echo divergence — a `msg 81 REQUEST_SUCCESS`
change where wolfSSH appends `[0,0,0,22]` (the bound port, 22) that libssh does not.

The shadow master switches are runtime env vars (`SSHPUFFIN_SHADOW_KNOWN_BUGS` /
`SSHPUFFIN_SHADOW_KNOWN_BENIGN`, both default on; set `=0` to re-surface a class). The
shadow-OFF outcome is also pinned by the unit test `fwd_reqsuccess_port_echo_is_shadowed`.

**The cross-implementation divergences located over this effort** — each an
adversarially-mutated trace under the Dolev–Yao attacker model, root cause and per-class
guard determined by manual triage — are:

| divergence | side / RFC | status |
|---|---|---|
| `tcpip-forward` REQUEST_SUCCESS echoes the bound port | wolfSSH, RFC 4254 §7.1 | reported by us, acknowledged by vendor; [wolfSSL/wolfssh#1246](https://github.com/wolfSSL/wolfssh/issues/1246); fixed on master after our report ([`24c2139a`](https://github.com/wolfSSL/wolfssh/commit/24c2139a), 2026-09-10), still present in the pinned v1.5.0-stable |
| identification string > 129 bytes rejected | libssh, RFC 4253 §4.2 | reported by us, acknowledged by vendor; [libssh-mirror#376](https://gitlab.com/libssh/libssh-mirror/-/issues/376); live on master |
| `USERAUTH_REQUEST` service ≠ `ssh-connection` accepted | wolfSSH, RFC 4252 §5 | rediscovered by us; fixed upstream; [wolfSSL/wolfssh@`0068d52e`](https://github.com/wolfSSL/wolfssh/commit/0068d52e) |
| non-KEX traffic during incomplete rekey | wolfSSH, RFC 4253 §7.1/§9 | rediscovered by us; fixed upstream; [wolfSSL/wolfssh#1200](https://github.com/wolfSSL/wolfssh/pull/1200); NIL security impact |
| unknown high-numbered message pre-auth: tolerate vs abort | libssh vs wolfSSH, §11.4 | rediscovered by us, but not first-found (public via a third party); [wolfSSL/wolfssh#1047](https://github.com/wolfSSL/wolfssh/issues/1047); maintainer left as-is |

All sit on adversarially-mutated traces (the Dolev–Yao attacker model); no honest run
diverges (§1b). 0 memory-safety bugs across the single-PUT ASAN campaigns — two mature
stacks — which is why the *conformance* findings are the salient result.

**Headline count (the paper's framing).** DDYF surfaced **4 genuine RFC-conformance bugs
in two mature SSH stacks — 3 in wolfSSH, 1 in libssh** — of which:
- **2 are new and acknowledged:** wolfSSH wrongly sending the bound port in a
  `REQUEST_SUCCESS` message (RFC 4254 §7.1, [wolfSSL/wolfssh#1246](https://github.com/wolfSSL/wolfssh/issues/1246)) and libssh rejecting an
  identification banner larger than 129 bytes where the RFC permits up to 255
  (RFC 4253 §4.2, [libssh-mirror#376](https://gitlab.com/libssh/libssh-mirror/-/issues/376));
- **2 were independently rediscovered by DDYF** from honest seeds — two wolfSSH bugs
  (unvalidated USERAUTH service name, RFC 4252 §5, fixed upstream [`0068d52e`](https://github.com/wolfSSL/wolfssh/commit/0068d52e); and traffic processed during an
  incomplete rekey, RFC 4253 §7.1/§9, fixed upstream [wolfSSL/wolfssh#1200](https://github.com/wolfSSL/wolfssh/pull/1200)) that had been fixed upstream around the time this
  work matured — evidence the oracle flags true positives, not merely that it stays quiet.

**How each was surfaced (probe vs blind fuzzing).** The two rediscovered wolfSSH bugs were
found by *fuzzing from honest seeds* (the committed `bad_service` / `kexinit_injection`
traces are their minimised reproducers). The libssh over-strict banner bug was **not**
found by blind fuzzing: it was surfaced by a **targeted probe seed** (`banner_probe_seed`,
hypothesis H2 — "does each stack bind a 200-byte identification line?") that uses
purpose-built oversized-banner atoms (`fn_banner_wire_oversized` / `fn_vc_oversized`).
Those atoms are registered `[no_gen]`, so the mutator cannot synthesise them into
generated terms; with the current grammar the fuzzer would not reach this bug unaided.
DDYF's contribution for this bug is the *oracle*: once the probe sent the out-of-spec
banner, the cross-stack disagreement (libssh "too large banner" vs wolfSSH completing)
flagged it, and the triage bucket (§2b) classifies it.

(The unknown-high-numbered-message §11.4 divergence and the embedded-NUL banner handling
are additional observed divergences, not counted in the headline 4: the former is public
in [wolfssh#1047](https://github.com/wolfSSL/wolfssh/issues/1047) and not first-found, the latter informational.) These conformance bugs are
**by design hard for a non-differential oracle to flag** — each handshake still completes
(or fails) plausibly on the affected stack, so only the cross-implementation disagreement
surfaces it.

**Honest scope.** These SSH experiments were **not as extensive as the TLS evaluation**:
they demonstrate DDYF's capability on a second protocol, not a complete SSH security
analysis. A longer campaign and a complete triage would be needed to finish such an
analysis.

---

## Appendix — supplementary SSH evidence (beyond the paper's scope)

> This appendix records extra evidence produced while building the artifact that goes
> **beyond what the paper claims for SSH** (the paper deliberately scopes SSH as a
> genericity demonstration, not a complete security analysis). Nothing in the main body
> above depends on it; it can be removed wholesale without affecting the supported
> claims. Evidence tags here: **[campaign]** a recorded large historical run, **[run]** a
> bounded campaign+triage performed for this artifact.

### B0. Shared DDYF-framework cost (puffin-level, one-time)

Complementing Claim 3's *per-protocol* figure: the one-time extension to the protocol-layer
*interface*, reused by every protocol (not a per-protocol cost), is
`git diff --stat origin/dev -- puffin/` = **7 files, +254/−32** (exact; the `filter_diffs`
set-filter + fail-closed runner, the `concatenate_all` whole-stream query, the
`preprocess_trace` hook, a `[u8;16]` codec bounds fix). These core edits are **additive,
intent-preserving fixes**, not semantic changes — e.g. the `filter_diffs` evaluation-order
fix corrects a latent ordering bug that never manifested in TLS because the TLS oracle does
not filter `Status` diffs; so TLS is unaffected both by preserved defaults *and* because the
fixed edge-cases do not arise there.

### B1. Before the features: false positives + objective volume  [campaign]

Recorded campaign runs on the un-tamed differential (reproducible with the campaign
scripts; the numbers below are the measured results) show the two failure modes DDYF's
features address:

- **False positives that mask real behaviour.** A harness-fidelity defect produced a
  whole spurious "libssh-accepts / wolfSSH-rejects" auth-divergence class (fixed once
  the wolfSSH worker was looped to quiescence); an un-aligned, positionally-indexed
  decryption recipe produced batching false positives; and without PUT-config
  alignment the honest KEXINIT differed on algorithm advertisement. Each was a
  differential artifact, not a real stack difference.
- **Objective volume.** An exhaustive classification of **3,040,217** objectives showed
  that both stacks agreed in **83.3%** of cases, with the remainder dominated by benign
  classes (≈4k banner/version-strictness traces in a ~4.9k-trace bucket sample); genuine
  content divergences were **28 / 3.04M ≈ 0.0009%**. Without the field blacklist /
  alignment / shadowing, those benign classes bury the signal.

### B2. End-to-end: a DDYF campaign + triage  [run]

The deterministic checks above are complemented by an actual short fuzzing campaign,
run for this artifact, showing the campaign→triage→interpret loop at volume.

**Launch** a bounded differential campaign (writes objectives incrementally to
`experiments/<title>/objective/`):

```sh
ASAN_OPTIONS=detect_leaks=0 \
  target/release/sshpuffin -c 0-3 differential-experiment libssh0114 wolfssh150 -t ddyf_eval
```

**Triage** the objectives into named benign/actionable buckets (the script
re-executes each objective via `differential-execute --json` and classifies the diff;
PUT names + worker count are env-overridable):

```sh
OBJ=$(find experiments -type d -name objective -path '*ddyf_eval*' | sort | tail -1)   # newest campaign if several
ln -sfn evaluation-ddyf evaluation_ddyf   # underscore-named package bridge (see §2b)
ASAN_OPTIONS=detect_leaks=0 PUFFIN_PATH=target/release/sshpuffin \
SSHPUFFIN_FIRST_PUT=libssh0114 SSHPUFFIN_SECOND_PUT=wolfssh150 \
  python -m evaluation_ddyf.ssh.sort_objectives_libssh_wolfssh "$OBJ"
```

> **`PUFFIN_PATH` is required here.** The triaging script re-executes each objective by
> shelling out to the fuzzer binary named in the `PUFFIN_PATH` environment variable. Its
> library default (`evaluation-ddyf/diff_analyzer.py`) is `target/release/tlspuffin` —
> the TLS binary — so for the SSH pipeline you **must** export
> `PUFFIN_PATH=target/release/sshpuffin` (as above), otherwise every objective silently
> fails to execute and the run reports nothing useful. The same variable is honoured by
> the SSH helper scripts in `evaluation-ddyf/ssh/` (e.g. `find_content_diffs.py`).

**Scanning for genuine content divergences.** To answer the sharper question — did any
objective carry a real *same-message, different-bytes* divergence in the decrypted s2c
transcript, rather than a mere presence/ordering difference? — run the content scanner
over the objective tree. It walks recursively, re-executes each trace, and splits
`CONTENT` (`Changed(AlignmentKey …)` — the strongest signal) from `PRESENCE`
(`Added/Removed(AlignmentKey …)`, e.g. the known RFC 4253 §7.1 rekey KexInit one stack
emits and the other withholds):

```sh
OBJ=$(find experiments -type d -name objective -path '*ddyf_eval*' | sort | tail -1)   # (re-)resolve; newest campaign if several
ASAN_OPTIONS=detect_leaks=0 PUFFIN_PATH=target/release/sshpuffin \
SSHPUFFIN_FIRST_PUT=libssh0114 SSHPUFFIN_SECOND_PUT=wolfssh150 \
  python evaluation-ddyf/ssh/find_content_diffs.py "$OBJ"
```

On a **25,000-objective** random sample of the large campaign below, 844 objectives
carried a decryption diff; splitting them gives **0 CONTENT diffs on any security-bearing
message** — the *only* same-message byte differences are two known/benign classes: msg 92
`CHANNEL_OPEN_FAILURE` reason-code latitude (39×, both stacks reject the channel; RFC 4254
§5.1) and msg 81 `REQUEST_SUCCESS` port-echo (6× = the filed [wolfssh#1246](https://github.com/wolfSSL/wolfssh/issues/1246)). Every PRESENCE
class is known benign reply-framing / flow-control latitude (WINDOW_ADJUST, UNIMPLEMENTED,
§7.1 rekey KexInit, EOF/CLOSE, …). No new divergence type appears.

**Observed (this artifact run).** The full campaign is the clean build (`--release`, no
ASAN, exactly the two non-ASAN vendors) on 29 cores, producing **511,060 objectives**
(`experiments/2026-09-17--…-29cddyf_1M…`). Triaging a **10,000-objective** random sample
with the iterated bucket set (`ssh/sort_objectives_libssh_wolfssh.py`) reaches **99.7 %
named-bucket coverage** of the diverging stream:

| class | share of diverging | kind |
|---|---:|---|
| `bootstrap_unknown_error_code` / `bootstrap_claim_presence` | ≈57% | benign — wolfSSH parse noise on corrupted ciphertext; one stack finalised KEX (`BOTH_ERROR`-guarded) |
| `diverge_libssh_accepts_wolfssh_rejects` (+ mirror) | ≈27% | **audit pile** — accept-vs-reject (libssh input leniency); never auto-classed benign |
| benign wolfSSH internal-reject / negotiation / libssh KEX-crypto / mapper-artifact / decrypt-framing | ≈15% | benign, each `BOTH_ERROR`- or precise-shape-guarded |
| **unbucketed** | **0.3%** | the fail-open audit pile — claim-presence that is *not* both-error + a few tiny benign framing shapes |
| **shadowed classes** (banner strictness, USERAUTH_FAILURE-only, port-echo) | **0** | suppressed online by the shadows |
| **new memory-safety / security bug** | **0** | — |

> **Note — "banner strictness" shadowed here vs the banner bucket in §2b are consistent.**
> The shadow `is_banner_strictness_diff` masks *only* the pure banner-length **Status**
> class (libssh rejecting a >129-byte identification string with "too large banner" while
> wolfSSH progresses, RFC 4253 §4.2). It does not erase the divergence: the oversized-banner
> trace still surfaces as an objective via its downstream accept-vs-reject / claim
> asymmetry — which is exactly what §2b's non-empty `diverge_wolfssh_accepts_libssh_rejects`
> bucket collects. Shadowing suppresses the benign *class label*, not the fact that the
> trace diverges.

**Interpretation (candid).** Three results: (i) the shadowed classes — including the filed
port-echo — do **not** re-appear (0), so a known finding is not re-reported every run;
(ii) named-bucket coverage of the diverging stream is **99.7 %**, with the 0.3 % residue
deliberately left unbucketed as the fail-open audit pile (a genuine "one stack finalises,
the other doesn't" divergence must never be silently absorbed); and (iii) **no new bug and
no auth bypass** — a dedicated audit of the two suspicious residual classes showed they
are exactly the *known* wolfSSH service-name laxity (RFC 4252 §5, fixed upstream) and a
benign harness claim-emission-timing artifact, and a 30,000-objective
unauthorized-acceptance sweep (12,196 phase-3 acceptances across both stacks) returned
**0 acceptances of an unauthorized credential** on either PUT. The load-bearing
guarantee for "real bugs are not drowned" is the *online* oracle (Claim 1b: honest seeds
0-diff; §2b(iv) re-surfaces the real divergence when its shadow is disabled); the offline
triager then confirms the campaign residue is exhaustively benign/known.

---

### B3. Claim 3 — the code added specifically for DDYF (beyond DYF) is small

**Statement.** Integrating a protocol for DDYF reuses almost everything from standard
DYF (notably the same Mapper: messages, term constructors, seeds, harnesses). The
*DDYF-specific* additions are modest.

For context, TLS's DDYF-specific support is ≈ **1 kLoC** (≈2/3 boilerplate, ≈1/3
annotations + decryption recipes + PUT-config APIs), and TLS is one of the largest
protocols. Measured for SSH on this branch (the *shared*, one-time framework cost —
reused by every protocol, not part of this per-protocol claim — is §B0 above):

**SSH-specific DDYF integration** — the per-protocol cost this claim is about. The
`transcript.rs` (non-test) and `message.rs` figures are exact; the `protocol.rs` and
`fn_crypto.rs` figures are **estimated subsets** — those files are 1342 and 1515 lines
*total* and mostly ordinary Mapper code (term constructors, message building) that a
DYF-only integration would need anyway, and there is no DYF-only baseline to `git diff`
against, so the DDYF-specific portion is scoped by hand:

| component | where | ≈ LoC |
|---|---|---|
| differential oracle hooks + shadow predicates + §7.1 renumber pass | `protocol.rs` (subset of 1342) | ~410 *(est.)* |
| decrypted-transcript alignment + custom comparison | `ssh/transcript.rs` (non-test) | **179** *(exact)* |
| decryption recipes + key derivation + session-id/exchange-hash claim | `ssh/fn_crypto.rs` (12 fns, subset of 1515) | ~150 *(est.)* |
| knowledge annotations (`#[comparable_ignore]`/`_synthetic`) | `ssh/message.rs` | **12 sites** *(exact)* |

**≈ 700–750 LoC total (estimated)**, *below* TLS's ~1 kLoC — matching the expectation of the paper [A] that
non-TLS protocols need less. For scale, sshpuffin's Rust source is ≈ 11.3 kLoC, so the
DDYF-specific delta is well under 10% of the crate; the rest (the Mapper: message
model, framing, term constructors, seeds, C harnesses) is standard DYF a DYF-only SSH
integration would need anyway. DDYF also *removes* work relative to security-property
fuzzing: no protocol-specific security policy or checker is written.

**C-harness alignment (per-PUT).** Separately from the Rust above, each PUT needs a thin C
harness. For TLS the DDYF-specific *behaviour-alignment* delta was ≈200 LoC added on top of
a pre-existing ≈1–1.5 kLoC DYF harness. SSH shows **comparable effort**: the two SSH
harnesses are `sshpuffin/harness/{libssh,wolfssh}/src/put.c` (**1073** and **779** LoC), of
which the DDYF-alignment portion is ≈**200–250 LoC per PUT** — dominated by security-state
**claim emission** for the differential oracle (`emit_handshake_claim`/`emit_phase_claim`),
plus the embedded-identical RSA host key (to remove benign crypto divergence) and the
shared authorization allow-list (`include/puffin/ssh_authorized_creds.h`, 127 LoC, written
once for both PUTs); the remaining ≈800–900 LoC/PUT is the DYF-baseline harness (socket and
session lifecycle, non-blocking I/O, the pump loop, message-capture callbacks) that a
DYF-only integration would need anyway. Each additional PUT *version* costs **0 to a
handful of lines** — the libssh harness spans 0.8.x / 0.10.4 / 0.11.4 through 9
`#if LIBSSH_VERSION_INT >= …` guards (≈2–3 lines/version). Caveat: unlike TLS (where the
DYF harness pre-existed and the ≈200 was a `git diff`), the SSH harnesses were written
fresh, so this per-PUT alignment split is a categorical estimate, not a diff.

---

## Reference

[A] Gouville, Tom, Lucca Hirschi, and Steve Kremer. "DDYF: Differential Dolev-Yao Fuzzing of Cryptographic Protocols." 2027 IEEE Symposium on Security and Privacy (S&P). IEEE, 2027.
