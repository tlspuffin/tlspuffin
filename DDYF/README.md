# DDYF experiments

To ensure reproductibility, all experiments should be run inside a Nix shell environment:

```bash
nix-shell shell.nix
```

## CVE reproduction benchmark

Run the fuzzing campaigns using `reproducing_cves.sh` script after activation the Nix shell environment.

You can edit the `TIMEOUT`, `RUNS` and `CORES` variable to setup the duration, number of campaigns and cores per campaigns.

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

```bash
./DDYF/perf_bench.sh 
```
