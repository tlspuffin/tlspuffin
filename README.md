# DDYF

This is the companion artifact for the paper "DDYF: Differential Dolev-Yao Fuzzing of Cryptographic Protocols". We provide in this artifact:

- The code of our implementation of DDYF, a differential fuzzer for cryptographic protocols, which is based on the Puffin DY fuzzer
- Various scripts to reproduce the experiments and claims presented in Section 5

**This artifact only reproduces experiment related to TLS, we provide a second artifact to reproduce SSH related experiments**

> Experiments presented in the paper were run on a machine with 48 AMD EPYC 9275F cores (96 threads) with hyperthreading enabled and 768 GiB of RAM. The machine was running Debian GNU/Linux 13.7 (trixie) with kernel 6.12. Expect some variability in the results when running on a different machine.

## Scaled down experiments

Most experiments reported in the paper use fuzzing campaigns of 24h and 48h, reproducing the exact results of the paper in less than 24h is thus impossible. To back up our claims **we provide scaled down experiments and relaxed claims that run in the allowed time.** For each claim an associated experiment is provided, if the full experiments needs more than 24h, use the experiment provided in the **Scaled down experiment** subsection of the claim. 

**We recommend using the Docker container** to reproduce the experiments on a machine with at least 32 cores. **Do not use the same containers for experiments running concurrently.**

The following table describes the order in which to run the experiments and which Docker container should be reused for multiple experiments to avoid the need to do new campaigns to generate data.

| Claim   | Experiment name           | Runtime | Core number | Run after                                               |
| ------- | ------------------------- | ------- | ----------- | ------------------------------------------------------- |
| Claim 1 | Reproducing CVEs          | ~18h    | 16          | new container                                           |
| Claim 2 | Stability of the findings | 8h      | 16          | new container, runs the campaigns of Claims 2, 3, and 4 |
| Claim 3 | Deduplication statistics  | < 1min  | 1           | Claim 2 container, reuse one campaign                   |
| Claim 4 | Ablation study            | ~5h     | 20          | Claim 2 container, reuse one campaign                   |
| Claim 5 | Performance measurements  | ~5h     | 10          | new container                                           |
| Claim 6 | Counting ignored fields   | < 1s    | 1           | new container                                           |


## Prerequisites

All experiments with DDYF were done on Linux and may not work on other operating systems.

> DDYF can produce a lot of objectives/metadata files (> 4M for 24h runs), make sure that your filesystem can support this many files in one directory

> Do not run multiple experiments in the same directory/docker container at the same time to prevent them from interfering

Most scripts contain variables such as `TIMEOUT`, `CORES`, `RUNS` that can be edited. Default values correspond to the parameters used in the paper.

The scripts running fuzzing campaigns (`reproducing_cve_parallel.sh`, `reproducing_cve.sh`, `perf_bench.sh`, `triaging_std_dev.sh`) take the duration of a campaign as their last argument, so it can be shortened for a trial run without editing them.

Python triaging scripts (`sort_objectives_ossl_wolf.py`, `ablation_study_sort.py`, `find_known_cves.py`) contain a `PARALLELISM` variable to select how many files should be triaged in parallel (recommended maximum is 2x core count).

`sort_objectives_ossl_wolf.py` also reads the `DDYF_FIRST_PUT`, `DDYF_SECOND_PUT` and
`DDYF_PARALLELISM` environment variables, which override those constants. This is what
lets the same buckets be applied to a campaign run against another version of a PUT.

### Running experiments with Nix

To ensure reproducibility, we use [Nix](https://nixos.org/) to manage dependencies. You can also skip to the next section to use Docker instead of Nix.
All experiments should be run inside a [Nix shell](https://nixos.wiki/wiki/Development_environment_with_nix-shell) environment:

```bash
nix-shell ./shell.nix
```

The scripts are committed with the executable bit set and use `#!/usr/bin/env bash`,
so they run as-is inside and outside the Nix shell. If the permissions were lost while
extracting an archive of this artifact, restore them with:

```bash
chmod +x ./evaluation-ddyf/*sh
```

### Using Docker instead of Nix

A [Dockerfile](../Dockerfile) is provided as an alternative to installing Nix. The image
contains this repository in `/ddyf`, the Nix shell of [shell.nix](../shell.nix) already
built with the pinned Rust toolchain. Build it from the top level of the repository:

```bash
docker build -t ddyf .
```

Every command is run inside the Nix shell, either interactively or one at a time:

```bash
# interactive shell, in /ddyf
docker run --rm -it ddyf

# a single command
docker run --rm ddyf cargo build --release --bin tlspuffin --features cputs
```

The image ships the toolchain but neither the PUTs nor a compiled fuzzer, so build them in
the container first. Mounting `/ddyf/experiments` is what makes the results of a campaign
survive the container:

```bash
docker run --rm -it -v "$PWD/experiments:/ddyf/experiments" ddyf

# then, inside the container
# you can run a differential fuzzing campaign
./tools/mk_vendor make openssl:openssl340
./tools/mk_vendor make wolfssl:wolfssl580
cargo build --release --bin tlspuffin --features cputs
./target/release/tlspuffin differential-experiment openssl340 wolfssl580 -t "my_experiment"
```

> `--rm` deletes the container on exit, and with it the PUTs and the fuzzer built inside.
> To keep them across several sessions, name the container and reopen it:
>
> ```bash
> docker run -it --name ddyf-run -v "$PWD/experiments:/ddyf/experiments" ddyf
> docker exec -it ddyf-run /usr/local/bin/ddyf-shell
> ```
>
> `docker exec` bypasses the entrypoint, so it must call `ddyf-shell` explicitly to get
> the Nix environment.

> Only `/ddyf/experiments` is mounted, but the summary files of Claims 1, 4 and 5
> (`cve_list.csv`, `results_perfs.csv`, `ablation.csv`, `ablation_per_bucket.csv` and
> `dedup.png`) and the `cve_logs/` and `perf_logs/` folders are written next to them in
> `/ddyf`. Copy them into `/ddyf/experiments` before leaving the container, or mount a
> second volume for them.

### Running bare-metal (without Nix or Docker)

If not running in a nix-shell or Docker (highly discouraged), make sure to have at least `cargo`, `Python 3`, `autoconf`, `automake`, `just`, `cmake`, and `clang` installed on your computer. Also run the following environment variable export in your terminal before running the fuzzer:

```bash
export LIBAFL_EDGES_MAP_SIZE=262144
```

## Running a differential fuzzing campaign

Build the desired PUTs (for example for OpenSSL 3.4.0 and WolfSSL 5.8.0):

```bash
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

## Claim 1: reproducing CVEs

> DDYF can detect 5 known CVEs affecting WolfSSL: CVE-2022-25638, CVE-2022-25640, CVE-2023-3724, CVE-2023-6937 and CVE-2024-5814

| CVE        | DDYF | Prop. | Time To Find (Min.) | Time To Find (Mean) | Time To Find (Std. dev.) |
| ---------- | ---- | ----- | ------------------- | ------------------- | ------------------------ |
| 2022-25638 | ✓    | 66%   | 59s                 | 2328s               | 2724s                    |
| 2022-25640 | ✓    | 100%  | <1s                 | 38s                 | 35s                      |
| 2023-3724  | ✓    | 100%  | <1s                 | 2s                  | 1.2s                     |
| 2023-6937  | ✓    | 28%   | 420s                | 7130s               | 5151s                    |
| 2024-5814  | ✓    | 100%  | <1s                 | 8.5s                | 9.5s                     |

### Full experiment (> 24h)

> The campaigns of this experiment run OpenSSL 3.4.0 against wolfSSL 5.1.0 (`openssl340`
> vs `wolfssl510`), the version affected by the five CVEs, and not the wolfSSL 5.8.0 used
> by the other experiments.

> The experiment used to produce the results of Table 1 of the paper is a set of 50 campaigns, each running for 5h on 8 cores.
> Running the whole experiment takes 50h of wall clock time on a machine with 40 cores, plus the triaging of each campaign.

Use `reproducing_cve_parallel.sh` to run the benchmark: it builds the PUTs and the
fuzzer, generates the seed traces, runs the campaigns in parallel, triages the objectives
of each of them and lists the reproduced CVEs at the end.

All the following commands run the same 50 campaigns, but with different parallelization strategies. The default is 5 workers of 8 cores running 10 campaigns each, for a total of 50 campaigns and 50h of wall clock time on a 40-core machine.

```bash
# 50 campaigns: 5 workers of 8 cores running 10 campaigns each, from core 0, 5h each, 50h total runtime on a 40-core machine
./evaluation-ddyf/reproducing_cve_parallel.sh

# 50 campaigns: 1 worker of 8 cores running 50 campaigns, from core 0, 5h each, 250h total runtime on a 8-core machine
./evaluation-ddyf/reproducing_cve_parallel.sh 0 8 1 50

# 50 campaigns: 10 workers of 8 cores running 5 campaigns each, from core 0, 5h each, 25h total runtime on a 80-core machine
./evaluation-ddyf/reproducing_cve_parallel.sh 0 8 10 5
```

The arguments are `FIRST_CORE CORE_PER_EXP NB_WORKERS RUNS_PER_WORKER TIMEOUT`, defaulting
to `0 8 5 10 5h`: 50 campaigns split in 5 groups of 10 campaigns each, with each group running for 5h on 8 cores each, as in the paper. Note that a shorter
`TIMEOUT` decreases the chances of finding CVEs.

Each worker logs to `cve_logs/worker<N>.log`. Once every campaign is over, the reproduced
CVEs are written to `cve_list.csv` and summarised on the standard output:

```
CVE                     campaigns     traces
CVE-2022-25640                  1          1
CVE-2023-3724                   3          4
```

The CSV file of all the traces triggering CVEs can be regenerated at any time from the
content of `experiments/` with:

```bash
./evaluation-ddyf/listing_reproduced_cves.sh
```

Analyze the file:

```bash
python -m evaluation-ddyf.cves_stats cve_list.csv
```

### Scaled down experiment (< 24h)

We propose a scaled down version of the experiment that can be run in less than 24h on a 40-core machine. It runs 24 campaigns of 3h each, which is enough to reproduce CVE-2022-25640, CVE-2023-3724 and CVE-2024-5814 with a high probability and CVE-2022-25638 and CVE-2023-6937 with a lower probability. The following command runs the 24 campaigns in parallel on 4 workers of 4 cores each, for a total of 18h of wall clock time using 16-cores:

```bash
# 24 campaigns: 4 workers of 4 cores running 6 campaigns each, from core 0, 3h each
./evaluation-ddyf/reproducing_cve_parallel.sh 0 4 4 6 3h
```

## Claim 2: Stability of the findings across campaigns

> DDYF is able to reliably find the same bugs and differences across multiple campaigns

### Full experiment (> 24h)

`triaging_std_dev.sh` measures how reproducible the findings are from one campaign to the
next: it runs several independent OpenSSL 3.4.0 vs wolfSSL 5.8.0 campaigns in parallel,
triages each of them with `sort_objectives_ossl_wolf.py`, and reports the mean and the
standard deviation of the bucket counts over the campaigns.

```bash
# 5 campaigns of 24h on 8 cores each, all at once, starting at core 0 (uses cores 0-39)
./evaluation-ddyf/triaging_std_dev.sh 0 8 5 1 24h
```

The arguments are `FIRST_CORE CORE_PER_EXP NB_WORKERS RUNS_PER_WORKER TIMEOUT`, defaulting
to `0 8 5 1 24h` — the duration of the effectiveness campaigns of the paper. The
`NB_WORKERS` workers run at the same time, each running its `RUNS_PER_WORKER` campaigns one
after the other, so the wall clock is `RUNS_PER_WORKER` times `TIMEOUT` plus the triaging of
each campaign.

> The script starts by running `cargo clean` and by removing `objective/`, `seeds/`,
> `corpus/`, `log/`, the content of `experiments/` and the `pipe_*` fifos: the results of a
> previous run must be moved away beforehand.

Each campaign logs to `experiments/logs/campaign<N>.log`. Once they are all over, the raw
per-campaign counts are written to `experiments/logs/triaging_stats.csv` (one line per
campaign: number of empty and non-empty buckets, total objectives, objectives left
untriaged and their proportion), and a summary is written to `experiments/logs/summary.md`
and printed on the standard output:

```
## Aggregated over 3 campaigns

| Metric | Mean | Std dev | Min | Max |
| --- | ---: | ---: | ---: | ---: |
| Empty buckets | 43.33 | 4.04 | 41.00 | 48.00 |
| Non-empty buckets | 102.67 | 4.04 | 98.00 | 105.00 |
| Total objectives | 25750.67 | 12203.90 | 11659.00 | 32859.00 |
| Non triaged | 77.67 | 38.28 | 37.00 | 113.00 |
| Non triaged (%) | 0.30 | 0.05 | 0.25 | 0.34 |
```

### Scaled down experiment (< 24h)

Run the same script with 8 campaigns of 4h instead of 24h. The campaigns are the ones
Claims 3 and 4 need as well, so this is the first thing to run in that container:

```bash
# 8 campaigns of 4h: 4 workers of 4 cores running 2 campaigns each, from core 16 (16-31)
./evaluation-ddyf/triaging_std_dev.sh 16 4 4 2 4h
```


Then `triaging_std_dev_reduced.sh` turns the buckets of those campaigns into the stability
statistics.

```bash
# analyse every campaign found in experiments/
./evaluation-ddyf/triaging_std_dev_reduced.sh
```

The script should output which bucket (corresponding to a bug or behavior) are populated and < 1% of the total number of traces should be left non triaged (i.e. not in a bucket).
Keep in minde that the campaigns are only 4h long instead of 24h in the paper experiment so all buckets won't be populated.


## Claim 3: Deduplication statistics

> The Differential Objective Oracle skips the objectives whose set of differences and PUT
> statuses is identical to one already recorded for the same corpus trace (Section 4.1.6 of
> the paper). This is what keeps the number of objectives manageable: on 24h
> OpenSSL vs wolfSSL campaign we record around 95% of duplicates.

### Full experiment (> 24h)

Every campaign records its statistics in `log/stats.json`, inside its experiment folder:
the size of the corpus, the number of objectives kept, the number of duplicates skipped
and the execution speed. `plot_stats_json.py` turns them into the graphs of Figure 4:

Run a differential fuzzing campaign to produce a `stats.json` file

```bash
./tools/mk_vendor make openssl:openssl340
./tools/mk_vendor make wolfssl:wolfssl580
cargo build --release --bin tlspuffin --features cputs
./target/release/tlspuffin seed --differential
timeout 24h ./target/release/tlspuffin --cores 0-7 differential-experiment openssl340 wolfssl580 -t "dedup_experiment"

# find the experiment folder
EXP_FOLDER=$(ls experiments | grep dedup_experiment)

python -m evaluation-ddyf.plot_stats_json "experiments/$EXP_FOLDER/log/stats.json" -o dedup.png
```

The figure in `dedup.png` has 4 panels, all against the elapsed time of the campaign:

| panel                   | what it shows                                                                     |
| ----------------------- | --------------------------------------------------------------------------------- |
| Objectives & duplicates | objectives kept (`objective_size`) against duplicates skipped (`duplicates`)      |
| Corpus                  | size of the corpus (`corpus_size`)                                                |
| Duplicates proportion   | `duplicates / (objective_size + duplicates)`, which grows as the corpus saturates |
| Execution speed         | executions per second (`exec_per_sec`)                                            |

### Scaled down experiment (< 24h)

To avoid launching a new fuzzing campaign, this reuse the campaigns from Claim 2, juste use one of the existing campaigns in the objective folder.

```bash
# in the container of Claim 2, once ./evaluation-ddyf/triaging_std_dev.sh is over
EXP_FOLDER=$(ls experiments | grep 'test1--')

python -m evaluation-ddyf.plot_stats_json "experiments/$EXP_FOLDER/log/stats.json" -o dedup.png
```

The deduplication proportion (see `dedup.png`) is expected to be above 90% after 4h, which demonstrate the impact of the deduplication on the number of objectives kept.

Running a campaign of its own works too :

```bash
## Run a differential fuzzing campaign to produce a stats.json file
./tools/mk_vendor make openssl:openssl340
./tools/mk_vendor make wolfssl:wolfssl580
cargo build --release --bin tlspuffin --features cputs
./target/release/tlspuffin seed --differential
timeout 4h ./target/release/tlspuffin --cores 0-7 differential-experiment openssl340 wolfssl580 -t "dedup_experiment"

# find the experiment folder
EXP_FOLDER=$(ls experiments | grep dedup_experiment)

python -m evaluation-ddyf.plot_stats_json "experiments/$EXP_FOLDER/log/stats.json" -o dedup.png
```

## Claim 4: Ablation study

> With the exception of the decryption, all components of DDYF (claims, knowledge and status comparison) contributes to the difference detection.

### Full experiment (> 24h)

Run a 24h-48h differential fuzzing campaign then run the ablation study script:

```bash
./evaluation-ddyf/ablation_study.sh path_to_experiment/objective
```

This will produce an `ablation.csv` file containing the result for each experiment listing the number of traces that are still found and the number of traces lost when disabling the feature.

Results will be displayed at the end of the script.

#### Per bucket ablation study

You can run a per bucket ablation study using

```bash
./evaluation-ddyf/ablation_study_per_buckets.sh path_to_experiment/objective
```

This will create an `ablation_per_bucket.csv` file containing the result of each experiment per bucket.

You can view a summary of the results using the following Python script:

```bash
python -m evaluation-ddyf.ablation_study_stats ablation_per_bucket.csv
```

This script will give a summary of the number of buckets lost per set of enabled/disabled DDYF features.

#### Ablation study on the RFC violation buckets

Table 2 of the paper reports the ablation both on all the traces and on the subset of
traces belonging to an RFC violation bucket. The `rfc_violations_<put>.sh` scripts build
that subset, by copying the RFC violation buckets of a triaged campaign into
`objective_ablation_study/`. They use relative paths, so they have to be run from the
experiment folder itself:

```bash
# from the folder of a triaged campaign against wolfSSL
# (variants exist for LibreSSL and BoringSSL)
cd path_to_experiment
/path/to/evaluation-ddyf/rfc_violations_wolfssl.sh
cd -

./evaluation-ddyf/ablation_study_per_buckets.sh path_to_experiment/objective_ablation_study
```

Each script lists the buckets identified for the campaign of the paper against that PUT.
A campaign of your own produces its own buckets, so the lists have to be adapted to the
output of your triaging.

### Scaled down experiment (< 24h)

To avoid doing a new campaign from scratch, reuse one of the campaigns of Claim 2, in the
same container. The ablation starts by emptying the buckets of the folder it is given, so
it is run on a copy made of hard links, which costs no disk space and leaves the triaging
of Claim 2 intact. Each of the two ablation scripts needs its own copy, since the first one
flattens the buckets of the folder it is given:

```bash
EXP_FOLDER=$(ls experiments | grep 'test1--')
cp -al "experiments/$EXP_FOLDER/objective" "experiments/$EXP_FOLDER/objective_ablation"
cp -al "experiments/$EXP_FOLDER/objective" "experiments/$EXP_FOLDER/objective_ablation_buckets"

# ablation study on all traces
./evaluation-ddyf/ablation_study.sh "experiments/$EXP_FOLDER/objective_ablation"

# ablation study done per bucket
./evaluation-ddyf/ablation_study_per_buckets.sh "experiments/$EXP_FOLDER/objective_ablation_buckets"
```

This should show that apart from the decryption component, all other components increase the detection of the discrepancies on TLS implementations.

## Claim 5: Performance measurements

> The performance of DDYF is roughly half of the performance of classical DY fuzzing due to executing two PUT for each trace, as shown in Table 3 of the paper.

### Full experiment (< 24h)

To measure the performance of DDYF run:

```bash
# 10 workers of 1 run each, on 10 cores: 5h of wall clock time
./evaluation-ddyf/perf_bench.sh 0 10 1 1h

# same experiment on one core: 10 sequential runs, as in the paper, 50h of wall clock time
./evaluation-ddyf/perf_bench.sh 0 1 10 1h
```

The arguments are `FIRST_CORE NB_WORKERS RUNS_PER_WORKER TIMEOUT`, defaulting to
`0 1 10 1h`. A campaign always runs on a single core, each
worker takes one core (`FIRST_CORE` + its index) and its own broker port, and writes its
measurements to `perf_logs/worker<N>.csv`; they are merged into `results_perfs.csv` once
every worker is over.

Each run executes 5 different campaigns of `TIMEOUT` each (1h by default), which is why a
run of the default benchmark takes 5h:

- Classical DY fuzzing on OpenSSL
- Classical DY fuzzing on wolfSSL
- DDYF fuzzing on OpenSSL vs OpenSSL
- DDYF fuzzing on wolfSSL vs wolfSSL
- DDYF fuzzing on OpenSSL vs wolfSSL

The result will be written to `results_perfs.csv` with the result of every run.

> Note that the workers still share the memory bandwidth and the caches of the machine, so
> concurrent measurements are not perfectly isolated from each other. The figures of Table 3
> were obtained with the sequential default; use it for numbers meant to be compared to the
> paper, and the parallel form to get a result quickly.

To have a summary with mean execution per second and standard deviation run:

```bash
python -m evaluation-ddyf.perfs_stats results_perfs.csv
```

## Claim 6: Counting the fields ignored by the oracle

> Our TLS differential oracle ignores 24 fields out of 145 supported TLS fields (Section 4.2.1)

### Full experiment (< 24h)

`count_fields.sh` counts the TLS structures and fields of the `tlspuffin` term algebra, and how many of those fields are black-listed:

```bash
./evaluation-ddyf/count_fields.sh
```

```
Number of TLS types: 46
Number of TLS struct fields: 145
Number of ignored TLS struct fields: 24
```

The counting rules are the `count_tls_types.yml`, `count_tls_fields.yml` and
`count_tls_ignored_fields.yml` files next to the script, applied to `tlspuffin/src/tls`
with [ast-grep](https://ast-grep.github.io/), which the Nix shell provides.

## Triaging from scratch with LLM

You can use LLM to do a complete triaging and analysis of a campaign's objectives.

The entry point for starting an LLM based triaging is the `evaluation-ddyf/prompts-v3/START_HERE.md` file that will explain the whole triaging procedure. The ORCHESTRATOR and AUDITOR prompts are expecting OpenSSL vs LibreSSL campaign but you can specify which PUT were used in the campaign to guide the LLMs.

> This LLM triaging has been tested with Anthropic's Claude code (Sonnet 4.6 and Opus 4.8), GitHub Copilot (Sonnet 4.6) and Gemini 3.x.
> The .md files explicitly reference Claude but you can use those prompts with other LLMs
