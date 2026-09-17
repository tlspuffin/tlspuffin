# DDYF

> **Protocol-agnostic artifact — TLS is the worked example.** This README (and most of the
> reproduction scripts it lists) are written for the **TLS** experiments in the DDYF paper [A]
> (OpenSSL / LibreSSL / … driven by `tlspuffin`). The DDYF workflow is identical for any
> protocol; for another protocol substitute the names in the table below. For the **SSH**
> instantiation specifically (libssh vs wolfSSH, driven by `sshpuffin`), the authoritative
> entry point is [`SSH_EVALUATION.md`](SSH_EVALUATION.md), with the SSH triaging
> tooling under [`ssh/`](ssh/) and the (shared, protocol-agnostic) LLM-triaging prompt suite
> under [`prompts-triaging/`](prompts-triaging/) (see its `START_HERE.md` § Protocol
> configuration for the full placeholder map).
>
> | this README says … | means (placeholder) | TLS (here) | SSH |
> |---|---|---|---|
> | `tlspuffin` | `<puffin>` fuzzer binary | `tlspuffin` | `sshpuffin` |
> | `openssl340` / `libressl421` | `<put1>` / `<put2>` | OpenSSL / LibreSSL / wolfSSL | `libssh0114` / `wolfssh` |
> | `sort_objectives_ossl_*.py` | `<triaging_script>` | `tls/sort_objectives_ossl_*.py` | `ssh/sort_objectives_libssh_wolfssh.py` |
> | TLS RFCs | security spec | TLS 1.2 / 1.3 | RFC 4251–4254, 8308, 8332 |
>
> Layout: `diff_analyzer.py` (shared bucket engine), `phase0_produce_metadata.sh` (parametric
> Phase-0 producer) and `prompts-triaging/` are protocol-independent; `tls/` and `ssh/` hold
> the per-protocol triaging scripts and TLS reference tooling.

This is the companion artifact for the DDYF paper [A]. We provide in this artifact:
 - the code of Dpuffin: our implementation of DDYF, a differential fuzzer for cryptographic protocols, which is based on the DY fuzzer puffin
 - various scripts to reproduce the experiments presented in Section 5

## Prerequisites

All experiments with DDYF where done on Linux and may not work on other operating systems.

To ensure reproducibility, we use [Nix](https://nixos.org/) to manage dependencies.
All experiments should be run inside a [Nix shell](https://nixos.wiki/wiki/Development_environment_with_nix-shell) environment:
```bash
nix-shell ./shell.nix
```

To make sure that all scripts are executable, run:
```bash
chmod +x ./evaluation-ddyf/*sh
```



Most scripts contain variables such as `TIMEOUT`, `CORES`, `RUNS` that can be edited. Default values correspond to the parameters used in the paper [A]. 
Python triaging scripts (`sort_objectives_ossl_wolf.py`, `ablatation_study_sort.py`, `find_known_cve.py`) contain a `PARALLELISM` variable to select how much files should be triaged in parallel (recommended maximum is 2x core count).

If not running in a nix-shell (highly discouraged), make sure to have at least `cargo`, `Python 3`, `autoconf`, `automake`, `just`, `cmake`, and `clang` installed on your computer. Also run the following environment variable export in your terminal before running the fuzzer:

```bash
export LIBAFL_EDGES_MAP_SIZE=262144
```

## Running a differential fuzzing campaign

Build the desired PUTs (for example for OpenSSL 3.4.0 and WolfSSL 5.8.0):
```bash
chmod +x ./tools/mk_vendor # if mk_vendor is not executable
./tools/mk_vendor make openssl:openssl340
./tools/mk_vendor make wolfssl:wolfssl580
```

Build the fuzzer for the PUTs that have been built with `./tools/mk_vendor`:
```bash
cargo build --release --bin tlspuffin --features cputs
```

If you want to build the fuzzer with an other set of PUTs, run `cargo clean` before starting a new build.

Generate the seed traces with:
```bash
./target/release/tlspuffin seed --differential
```

Launch a fuzzing campaign, here between OpenSSL 3.4.0 and WolfSSL 5.8.0 with an experiment name "my_experiment":
```bash
./target/release/tlspuffin differential-experiment openssl340 wolfssl580 -t "my_experiment" 
```

The results (corpus, objectives, metadata and logging) will be stored in a new folder located in `./experiments/`. Stop the campaign at any time with `CTRL+C`.

To run the triaging script on the results:
```bash
# this script only works for campaigns between OpenSSL and WolfSSL
python -m DDYF.sort_objectives_ossl_wolf path_to_experiment/objective

# list the content of the buckets
./evaluation-ddyf/list_buckets.sh path_to_experiment/objective
```

## Executing one trace with differential fuzzing

To execute one trace (for example `path_to_trace`) on both OpenSSL 3.4.0 and WolfSSL 5.8.0 and display the differences:
```bash
./target/release/tlspuffin differential-execute openssl340 wolfssl580 path_to_trace
```

You can also see the details of an execution on one PUT (here WolfSSL 5.8.0) with:
```bash
./target/release/tlspuffin --put wolfssl580 display-execute -tckp path_to_trace
```
where
- `-t`: Show the terms computed at each input step
- `-c`: Show the claims emitted at each input step
- `-k`: Show the knowledges gathered at each output step
- `-p`: Evaluate the post execution terms used in differential fuzzing

## CVE reproduction benchmark

Run the fuzzing campaigns using `reproducing_cves.sh` script after activation the Nix shell environment.

You can edit the `TIMEOUT`, `RUNS` and `CORES` variables to setup the duration, number of campaigns and cores per campaigns.
Note that a shorter time decreases the chances of finding any CVEs, the recommended value is 5h.

```bash
./evaluation-ddyf/reproducing_cves.sh
```

Generate a CSV file of all the traces triggering CVEs :

```bash
./evaluation-ddyf/listing_reproduced_cves.sh
```

This should create a `cve_list.csv` file.


Analyze the file:

> Due to an incompatibility between the Python version provided with the nix-shell and the pandas library, do not execute the following commands inside the nix environment and instead execute it directly with your system's python (make sure to use a version >= 3.12)
```bash
python -m venv DDYF/.venv
source DDYF/.venv/bin/activate
pip install pandas
python -m DDYF.cves_stats
```


## Measuring performances

To measure the performances of DDYF run:

```bash
./evaluation-ddyf/perf_bench_DDYF.sh 
```

To measure the original performances of Puffin: clone the original puffin repo `https[://]github[.]com/tlspuffin/tlspuffin` and run in the main branch:

```bash
./evaluation-ddyf/perf_bench_puffin.sh 
```


## Ablation study

After running a differential fuzzing campaign, run:

```bash
./evaluation-ddyf/ablation_study.sh path/to/objectives
```

This will produce 5 files: `ablation-all.txt`, `ablation-no-status.txt`, `ablation-no-knowledges.txt`, `ablation-no-decryption.txt` and `ablation-no-claims.txt`. Each file contains 3 lines:

```txt
non triaged : XXX # traces that could be detected with component deactivated
objective/no_errors : XXX # traces that could not be detected
total: XXX # total number of traces
```

## Fingerprinting experiment

To run the fingerprinting experiment, run:

```bash
./evaluation-ddyf/fingerprinting_exp.sh
```

This will produce 3 folders in your `./experiments` directory for each pair of PUTs between WolfSSL 5.0.0, 5.1.0, and 5.2.0.


---

## Reference

[A] Gouville, Tom, Lucca Hirschi, and Steve Kremer. "DDYF: Differential Dolev-Yao Fuzzing of Cryptographic Protocols." 2027 IEEE Symposium on Security and Privacy (S&P). IEEE, 2027.
