# TLS Library Version Fingerprinting — Quick Start

Learn, from differential fuzzing, a deterministic decision tree that identifies **which version of
a TLS library** a remote server runs — by replaying a handful of short, fuzzer-discovered probe
traces over a plain TCP socket and reading only the wire-observable response (no decryption, no ML,
no fuzzing at deployment time).

Supported PUTs: **OpenSSL 3.x** (61 versions → **11** clusters) and **WolfSSL 5.x** (26 versions →
**16** clusters). The paper narrates only the **40** most recent OpenSSL versions (3.1.0–3.6.2); it
does not discuss the 21 OpenSSL 3.0.x versions (over those 40 the model is still 11 clusters).

For the full reference (layout, prober internals, `--fingerprinting` mode & controls, archive URLs
+ checksums) see [`README_fingerprinting.md`](README_fingerprinting.md) and
[`DEVELOPER.md`](DEVELOPER.md).

## Setup

Enter the dev shell first, then bootstrap inside it:

```
nix-shell ./shell.nix                       # drops you into the dev shell
# If NIX_PATH is empty / nix-shell warns about <nixpkgs>, pin it explicitly:
#   nix-shell -I nixpkgs=https://github.com/NixOS/nixpkgs/archive/nixos-23.11.tar.gz ./shell.nix
./evaluation-ddyf/fingerprinting/setup.sh   # build the prober + vendored servers (long; idempotent)
```

Inspecting the committed `reference/<put>/report.md` needs none of the above.

## Identify a live target

```
# Start a local test server (terminal 1)
python3 serve.py --put openssl --version 3.6.2 --port 4433

# Identify it (terminal 2)
python3 fingerprint_probe.py --host 127.0.0.1 --port 4433 --put openssl wolfssl --json
```

The prober connects, walks the decision tree with at most 4 short probes, and reports the version
cluster — never triggering a crash or memory violation.

## Reproduce the committed results

The prober env is **per PUT** (OpenSSL answers immediately; WolfSSL needs an I/O pause + longer
timeout so its slower distinguishing flights are not truncated — see `README_fingerprinting.md`).

### 1. Validate the committed decision tree (no campaigns needed)

```
# OpenSSL — 11 clusters
PUFFIN_TCP_IO_SLEEP_MS=0   python3 run_fingerprint.py --put openssl --stages validate,report --timeout 12
# WolfSSL — 16 clusters
PUFFIN_TCP_IO_SLEEP_MS=150 python3 run_fingerprint.py --put wolfssl  --stages validate,report --timeout 15
```

### 2. Rebuild the decision tree from the mined probe set

`probes_full/` (the raw mined corpus) is **not** committed — restore it from the published archives
(step 4) or re-mine (step 3) first; then:

```
PUFFIN_TCP_IO_SLEEP_MS=0   python3 run_fingerprint.py --put openssl --stages tree,validate,report --timeout 12
PUFFIN_TCP_IO_SLEEP_MS=150 python3 run_fingerprint.py --put wolfssl  --stages tree,validate,report --timeout 15
```

### 3. Full rebuild from fuzzing campaigns

```
# Stage 0: differential campaigns per adjacent version pair (pass --fingerprinting via
# --client-attacker-only so the corpus is fingerprinting-only)
python3 run_campaigns.py --put openssl --client-attacker-only --timeout 1h --jobs 20 --cores 0-19
# Stages 1–5: mine -> matrix -> tree -> validate -> report
PUFFIN_TCP_IO_SLEEP_MS=0 python3 run_fingerprint.py --put openssl \
    --stages mine,matrix,tree,validate,report --jobs 15
```

### 4. Rebuild from published experiment archives (no long campaigns)

The campaigns' objective traces are published as a single ZIP containing two tarballs:
**<https://members.loria.fr/LHirschi/data/fingerprinting_traces.zip>**
(`openssl_objectives.tar.gz`, `wolfssl_all_objectives.tar.gz`).

```
wget https://members.loria.fr/LHirschi/data/fingerprinting_traces.zip
unzip fingerprinting_traces.zip
mkdir -p ~/ddyf_experiments
tar -xf wolfssl_all_objectives.tar.gz -C ~/ddyf_experiments     # or openssl_objectives.tar.gz
PUFFIN_TCP_IO_SLEEP_MS=150 python3 run_fingerprint.py --put wolfssl \
    --experiments-dir ~/ddyf_experiments --stages mine,matrix,tree,validate,report --jobs 24
```
