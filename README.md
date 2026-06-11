# DDYF

This is the companion artifact for the paper "DDYF: Differential Dolev-Yao Fuzzing of Cryptographic Protocols". We provide in this artifact:
 - the code of Dpuffin: our implementation of DDYF, a differential fuzzer for cryptographic protocols, which is based on the DY fuzzer puffin
 - various scripts to reproduce the experiments presented in Section 5

The code provided in this repository is a fork from (https[://]github[.]com/tlspuffin/tlspuffin) and is provided under the same licenses.

> For more information about the usage of the puffin fuzzer you can find its original documentation at https[://]tlspuffin[.]github[.]io/docs/overview/

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



Most scripts contain variables such as `TIMEOUT`, `CORES`, `RUNS` that can be edited. Default values correspond to the parameters used in the paper. 
Python triaging scripts (`sort_objectives_ossl_wolf.py`, `ablatation_study_sort.py`, `find_known_cve.py`) contain a `PARALLELISM` variable to select how much files should be triaged in parallel (recommended maximum is 2x core count).

If not running in a nix-shell (highly discouraged), make sure to have at least `cargo`, `Python 3`, `autoconf`, `automake`, `just`, `cmake`, and `clang` installed on your computer. Also run the following environment variable export in your terminal before running the fuzzer:

```bash
export LIBAFL_EDGES_MAP_SIZE=262144
```


> DDYF can produce a lot of objectives/metadata files (> 4M for 24h runs), make sure that your filesystem can support this much files in one directory


> Do not run multiple experiments in the same directory at the same time to prevent them from interfering

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
# variants exist for OpenSSL vs LibreSSL and OpenSSL vs BoringSSL
python -m evaluation-ddyf.sort_objectives_ossl_wolf path_to_experiment/objective

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

You can edit the `TIMEOUT` and `CORE_PER_EXP` variables to setup the duration, number of campaigns and cores per campaigns.
Note that a shorter time decreases the chances of finding any CVEs, the recommended value is 5h with a recent CPU.

```bash
# Run experiments 1 through 50
./evaluation-ddyf/reproducing_cve.sh 1 50
```

Generate a CSV file of all the traces triggering CVEs :

```bash
./evaluation-ddyf/listing_reproduced_cves.sh
```

This should create a `cve_list.csv` file.


Analyze the file:

> Due to an incompatibility between the Python version provided with the nix-shell and the pandas library, do not execute the following commands inside the nix environment and instead execute it directly with your system's python (make sure to use a version >= 3.12)
```bash
python -m venv evaluation-ddyf/.venv
source evaluation-ddyf/.venv/bin/activate
pip install pandas
python -m evaluation-ddyf.cves_stats cve_list.csv
```


## Measuring performances

To measure the performances of DDYF run:

```bash
./evaluation-ddyf/perf_bench.sh 
```

This will run 5 1h experiments 10 times (to account for variability):
- Classical DY fuzzing on OpenSSL
- Classical DY fuzzing on wolfSSL
- DDYF fuzzing on OpenSSL vs OpenSSL
- DDYF fuzzing on wolfSSL vs wolfSSL
- DDYF fuzzing on OpenSSL vs wolfSSL

The result will be written to `results_perfs.csv` with the result of every run.

To have a summary with mean execution per second and standard deviation run:

```bash
python -m venv evaluation-ddyf/.venv
source evaluation-ddyf/.venv/bin/activate
pip install pandas
python -m evaluation-ddyf.perfs_stats results_perfs.csv
```

## Ablation study

After running a differential fuzzing campaign, run:

```bash
./evaluation-ddyf/ablation_study.sh path/to/objectives
```

This will produce an `ablation.csv` file containing the result for each experiment listing the number of traces that are still found and the number of traces lost during when disabling the feature.

## Per bucket ablation study

You can run a per bucket ablation study using

```bash
./evaluation-ddyf/ablation_study_per_buckets.sh path/to/objectives
```

This will create an `ablation_per_bucket.csv` file containing the result of the each experiment per buckets.

You can view a summary of the results using the following Python script:


```bash
python -m venv evaluation-ddyf/.venv
source evaluation-ddyf/.venv/bin/activate
pip install pandas
python -m evaluation-ddyf.ablation_study_stats ablation_per_bucket.csv
```

This script will give a summary of the number of buckets lost per set of enabled/disabled DDYF features.

## Triaging from scratch with LLM

You can use LLM to do a complete triaging and analysis of a campaign's objectives.

The entry point for starting an LLM based triaging is the `evaluation-ddyf/prompts-v3/START_HERE.md` file that will explain the whole triaging procedure. The ORCHESTRATOR and AUDITOR prompts are expecting OpenSSL vs LibreSSL campaign but you can specify which PUT were used in the campaign to guide the LLMs.

> This LLM triaging has been tested with Anthropic's Claude code (Sonnet 4.6 and Opus 4.8), GitHub Copilot (Sonnet 4.6) and Gemini 3.x.
> The .md files explicitly reference Claude but you can use those prompts with other LLMs
