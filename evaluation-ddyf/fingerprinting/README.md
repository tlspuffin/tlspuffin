# TLS Library Version Fingerprinting

Automatically build a decision tree that identifies **which version of a TLS library** a remote server runs — using a handful of fuzzer-discovered probe traces over a plain TCP socket, no decryption needed.

Supported PUTs: **OpenSSL 3.x** (61 versions → 11 clusters) and **WolfSSL 5.x** (26 versions → 14 clusters).

See [README_fingerprinting.md](README_fingerprinting.md) for full methodology and details.

## Setup

From a fresh clone, enter the nix dev shell first, then bootstrap:

```sh
git clone <repo> && cd <repo>
nix-shell ./shell.nix                       # drops you into the dev shell
# If your NIX_PATH is empty / nix-shell warns about <nixpkgs>, pin nixpkgs explicitly:
#   nix-shell -I nixpkgs=https://github.com/NixOS/nixpkgs/archive/nixos-23.11.tar.gz ./shell.nix
./evaluation-ddyf/fingerprinting/setup.sh   # builds all vendored servers + tlspuffin
```

You can also build a subset by setting variables with e.g. `PUTS=openssl` or `VERSIONS_OPENSSL="3.6.2" VERSIONS_WOLFSSL="5.9.1"`.

## Reproduce results

All commands run from the `evaluation-ddyf/fingerprinting/` directory.

## Identify a live target

```sh
# Start a local test server (terminal 1)
python3 serve.py --put openssl --version 3.6.2 --port 4433

# Identify it (terminal 2)
python3 fingerprint_probe.py --host 127.0.0.1 --port 4433 --put openssl wolfssl --json
# or via the driver, against any real endpoint:
python3 run_fingerprint.py identify --host example.com --port 443 --put openssl wolfssl
```

## Rebuild and validate results


### 1. Validate the committed decision tree

Walk the committed decision trees against live servers.

```sh
# OpenSSL — 11 clusters, 60/61 recognised
PUFFIN_TCP_IO_SLEEP_MS=0   python3 run_fingerprint.py --put openssl --stages validate,report --timeout 12

# WolfSSL — 12 clusters, 26/26 recognised
PUFFIN_TCP_IO_SLEEP_MS=150 python3 run_fingerprint.py --put wolfssl  --stages validate,report --timeout 15
```

### 2. Rebuild the decision tree (from committed probes)

Re-induce the tree from the committed probe set in `reference/<put>/probes_full/` — no campaigns needed:

```sh
PUFFIN_TCP_IO_SLEEP_MS=0   python3 run_fingerprint.py --put openssl --stages tree,validate,report --timeout 12
PUFFIN_TCP_IO_SLEEP_MS=150 python3 run_fingerprint.py --put wolfssl  --stages tree,validate,report --timeout 15
```

### 3. Full rebuild from fuzzing campaigns

Run campaigns then mine probes, rebuild tree, validate:

```sh
# Stage 0: run differential campaigns per adjacent version pair
python3 run_campaigns.py --put openssl --timeout 1h --jobs 20 --cores 0-19

# Stages 1–5: mine → matrix → tree → validate → report
PUFFIN_TCP_IO_SLEEP_MS=0 python3 run_fingerprint.py --put openssl \
    --stages mine,matrix,tree,validate,report --jobs 15
```

### 4. Rebuild from published experiment archives (no need to run long campaigns)

Download the objective archives, then run from stage 1:

```sh
mkdir -p ~/ddyf_experiments
tar -xf wolfssl_lastnight_objectives.tar.gz -C ~/ddyf_experiments

PUFFIN_TCP_IO_SLEEP_MS=150 python3 run_fingerprint.py --put wolfssl \
    --stages mine,matrix,tree,validate,report \
    --experiments-dir ~/ddyf_experiments --timeout 15 --jobs 12
```

See [README_fingerprinting.md](README_fingerprinting.md) for archive URLs, sha256 checksums, and OpenSSL equivalents.
