# DDYF

To ensure reproductibility, all experiments should be run inside a Nix shell environment:

```bash
nix-shell shell.nix
```

Most script contains variables such as `TIMEOUT`, `CORES`, `RUNS` that can be edited. Default values corresponds to the parameters used in the paper.

Python triaging scripts (`sort_objectives_ossl_wolf.py`, `ablatation_study_sort.py`, `find_known_cve.py`) contains a `PARALLELISM` variable to select how much files should be triaged in parallel (recommended maximum 2x core count).

> For more information about the usage of the puffin fuzzer you can find its original documentation at `https[://]tlspuffin[.]github[.]io/docs/overview/`

## Running a differential fuzzing campaign

Build the desired PUTs (e.g. OpenSSL 3.4.0 and wolfSSL 5.8.0)
```bash
./tools/mk_vendor make openssl:openssl340
./tools/mk_vendor make wolfssl:wolfssl580
```

Build the fuzzer:
```bash
cargo build --release --bin tlspuffin --features cputs
```

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
./DDYF/list_buckets path_to_experiment/objective
```

## Executing one trace with differential fuzzing

```bash
./target/release/tlspuffin differential-execute put1 put2 path/to/trace
```

## CVE reproduction benchmark

Run the fuzzing campaigns using `reproducing_cves.sh` script after activation the Nix shell environment.

You can edit the `TIMEOUT`, `RUNS` and `CORES` variables to setup the duration, number of campaigns and cores per campaigns.

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

