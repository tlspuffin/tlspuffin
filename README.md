# DDYF


The code provided in this repository is a fork from tlspuffin (`https[://]github[.]com/tlspuffin/tlspuffin`) and is provided under the same licenses.

## Prerequisites

All experiments with DDYF where done on Linux, any other operating system may not work.

To ensure reproductibility, experiments should be run inside a [Nix shell](https://nixos.wiki/wiki/Development_environment_with_nix-shell) environment:

```bash
nix-shell ./shell.nix
```

If not running in a nix-shell (highly discouraged), to be able to use the tools provided in this repository make sure to have at least `Cargo`, `Python 3`, `autoconf`, `automake`, `just`, `cmake`, and `clang` installed on your computer. And run the following environment variable export in your terminal before compiling the fuzzer:

```bash
export LIBAFL_EDGES_MAP_SIZE=262144
```

Most script contains variables such as `TIMEOUT`, `CORES`, `RUNS` that can be edited. Default values corresponds to the parameters used in the paper.

To make sure that all scripts are executable :
```bash
chmod +x ./DDYF/*sh
```

Python triaging scripts (`sort_objectives_ossl_wolf.py`, `ablatation_study_sort.py`, `find_known_cve.py`) contains a `PARALLELISM` variable to select how much files should be triaged in parallel (recommended maximum 2x core count).

> For more information about the usage of the puffin fuzzer you can find its original documentation at `https[://]tlspuffin[.]github[.]io/docs/overview/`

## Running a differential fuzzing campaign

Build the desired PUTs (e.g. OpenSSL 3.4.0 and wolfSSL 5.8.0)
```bash
chmod +x ./tools/mk_vendor # if mk_vendor is not executable
./tools/mk_vendor make openssl:openssl340
./tools/mk_vendor make wolfssl:wolfssl580
```

Build the fuzzer:
```bash
cargo build --release --bin tlspuffin --features cputs
```

If you want to build the fuzzer with an other set of PUT, run `cargo clean` before starting a new build.

Generate the seeds:
```bash
./target/release/tlspuffin seed --differential
```

Run the campaign:

```bash
./target/release/tlspuffin differential-experiment openssl340 wolfssl580 -t "my_experiment" 
```

The results will be in the experiments folder.

To run the triaging script on the results:

```bash
# this script only works for campaigns between OpenSSL and WolfSSL
python -m DDYF.sort_objectives_ossl_wolf path_to_experiment/objective

# list the content of the buckets
./DDYF/list_buckets.sh path_to_experiment/objective
```

## Executing one trace with differential fuzzing

```bash
./target/release/tlspuffin differential-execute openssl340 wolfssl580 path/to/trace
```

You can also see the details of an execution on one PUT with:

```bash
./target/release/tlspuffin --put wolfssl580 display-execute -tckp path/to/trace
```

where
- `-t`: Show the terms computed at each input step
- `-c`: Show the claims emitted at each input step
- `-k`: Show the knowledges gathered at each output step
- `-p`: Evaluate the post execution terms used in differential fuzzing

## CVE reproduction benchmark

Run the fuzzing campaigns using `reproducing_cves.sh` script after activation the Nix shell environment.

You can edit the `TIMEOUT`, `RUNS` and `CORES` variables to setup the duration, number of campaigns and cores per campaigns.
Note that a shorter time decreases the chances of finding any CVEs, the recommanded value is 5h.

```bash
./DDYF/reproducing_cves.sh
```

Generate a CSV file of all the traces triggering CVEs :

```bash
./DDYF/listing_reproduced_cves.sh
```

This should create a `cve_list.csv` file.


Analyze the file:

```bash
python -m venv DDYF/.venv
source DDYF/.venv/bin/activate
pip install pandas
python -m DDYF.cves_stats
```


## Measuring performances

To measure the performances of DDYF run:

```bash
./DDYF/perf_bench_DDYF.sh 
```

To measure the original performances of Puffin clone the original Puffin repo `https[://]github[.]com/tlspuffin/tlspuffin` and run in main branch

```bash
./DDYF/perf_bench_puffin.sh 
```


## Ablation study

After running a differential fuzzing campaign

```bash
./DDYF/ablation_study.sh path/to/objectives
```

This will produce 5 files: `ablation-all.txt`, `ablation-no-status.txt`, `ablation-no-knowledges.txt`, `ablation-no-decryption.txt` and `ablation-no-claims.txt`. Each file contains 3 lines:

```txt
non triaged : XXX # traces that could be detected with component deactivated
objective/no_errors : XXX # traces that could not be detected
total: XXX # total number of traces
```

## Fingerprinting experiment

To run the fingerprinting experiment run:

```bash
./DDYF/fingerprinting_exp.sh
```

This will produce 3 folders in your experiments directory for each pair of PUTs between wolfSSL 5.0.0, 5.1.0 and 5.2.0.

