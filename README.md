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
non-ASAN-instrumented `libssh0114` (libssh 0.11.4) and `wolfssh` (wolfSSH 1.5.0)
vendors — and the fuzzer:

```sh
# REPRODUCIBILITY STEPS
just mk_vendor libssh  libssh0114     # -> vendor/libssh0114
just mk_vendor wolfssh wolfssh        # -> vendor/wolfssh
cargo build -p sshpuffin --release    # -> target/release/sshpuffin
target/release/sshpuffin seed         # dumps the honest corpus to ./seeds (11 traces)
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
ASAN_OPTIONS=detect_leaks=0 target/release/sshpuffin differential-execute libssh0114 wolfssh ./seeds/seed_client_attacker_pubkey_aesgcm.trace
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
  ASAN_OPTIONS=detect_leaks=0 target/release/sshpuffin differential-execute libssh0114 wolfssh "$t"
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
  ASAN_OPTIONS=detect_leaks=0 target/release/sshpuffin differential-execute libssh0114 wolfssh /tmp/eval_probes/$t.trace
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
  target/release/sshpuffin -c 0-3 differential-experiment libssh0114 wolfssh -t ddyf_eval
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
ASAN_OPTIONS=detect_leaks=0 target/release/sshpuffin differential-execute libssh0114 wolfssh seeds/seed_client_attacker_forwarding.trace
#   -> No differences
# shadow OFF: set the env var and re-run the SAME binary — no rebuild, no source edit
SSHPUFFIN_SHADOW_KNOWN_BUGS=0 ASAN_OPTIONS=detect_leaks=0 target/release/sshpuffin differential-execute libssh0114 wolfssh seeds/seed_client_attacker_forwarding.trace
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
| `tcpip-forward` REQUEST_SUCCESS echoes the bound port | wolfSSH, RFC 4254 §7.1 | reported by us, acknowledged by vendor; [wolfSSL/wolfssh#1246](https://github.com/wolfSSL/wolfssh/issues/1246); live on master |
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

## Reference

[A] Gouville, Tom, Lucca Hirschi, and Steve Kremer. "DDYF: Differential Dolev-Yao Fuzzing of Cryptographic Protocols." 2027 IEEE Symposium on Security and Privacy (S&P). IEEE, 2027.
