# Phase 0 — Static Data Producer

> **Protocol-agnostic methodology — TLS is the worked example.** The concrete names in this file (`openssl340`/`libressl421`, `tlspuffin`, TLS error strings / RFCs) are the running **TLS example**. For another protocol, substitute the placeholders defined in `START_HERE.md` § Protocol configuration — e.g. SSH: `libssh0114`/`wolfssh150`, `sshpuffin`, RFC 4251-4254. The triaging script is `<triaging_script>` (`$TRIAGING_SCRIPT` in commands): `tls/sort_objectives_ossl_wolf.py` or `ssh/sort_objectives_libssh_wolfssh.py`, under `evaluation-ddyf/`.


**Role:** Data production agent. You generate metadata logs for every trace. No analysis, no classification, no code writing — only running commands and saving output files.

**Model:** Haiku-class or equivalent (low capability). This phase is pure I/O.

**Parallelism:** Run as many traces in parallel as the machine allows. Use `xargs -P N` or a shell loop with `&`. Suggested: `PARALLELISM=20`.

---

## What to produce

For every trace file `T` found under `./objective/` (any subdirectory), produce three log files **plus one JSON diff cache**, all **in the same directory as the trace**:

| Output file | Command |
|---|---|
| `metadata_diff_T.log` | `./target/release/tlspuffin differential-execute openssl340 libressl421 T -S` |
| `metadata_diff_T.json` | `./target/release/tlspuffin differential-execute --json openssl340 libressl421 T` |
| `metadata_openssl340_T.log` | `./target/release/tlspuffin --put openssl340 display-execute T -tckp --uniformise` |
| `metadata_libressl421_T.log` | `./target/release/tlspuffin --put libressl421 display-execute T -tckp --uniformise` |

`--uniformise` runs each PUT under the differential's uniformised configuration, as the objective was produced (`PUFFIN_TRIAGE_UNIFORMISE=1`, the script's default; `0` reproduces older, non-uniformised logs). For the three `.log` files, capture both stdout and stderr (`> log 2>&1`). For the `.json` cache, capture **stdout only** (`> file 2>/dev/null`) — the triaging script parses it as JSON, so stderr must not pollute it.

---

## Run the script

Run `evaluation-ddyf/phase0_produce_metadata.sh` from the repository root. It takes the binary and
the two PUTs from the environment (its defaults are the SSH campaign's: `target/release/sshpuffin`,
`libssh0114`, `wolfssh150`), skips the traces whose four files exist, and prints the count of each
kind at the end. For the TLS worked example:

```bash
PUFFIN_PATH=./target/release/tlspuffin FIRST_PUT=openssl340 SECOND_PUT=libressl421 PARALLELISM=20 \
  ./evaluation-ddyf/phase0_produce_metadata.sh
```

Do not write your own copy of the script: the classifier relies on the files it writes (names, the
`--json` cache on stdout only, `--uniformise` per-PUT logs).

---

## Verification

After the script completes, verify coverage:

```bash
# Count traces
N_TRACES=$(find ./objective -name "*.trace" -not -name ".*" | wc -l)   # skip LibAFL hidden sidecars

# Count log triplets (each trace should have 3 logs)
N_DIFF=$(find ./objective -name "metadata_diff_*.log" | wc -l)
N_JSON=$(find ./objective -name "metadata_diff_*.json" | wc -l)
N_OSSL=$(find ./objective -name "metadata_openssl340_*.log" | wc -l)
N_LIBRE=$(find ./objective -name "metadata_libressl421_*.log" | wc -l)

echo "Traces: $N_TRACES"
echo "Diff logs: $N_DIFF / $N_TRACES"
echo "Diff JSON cache: $N_JSON / $N_TRACES"
echo "OpenSSL logs: $N_OSSL / $N_TRACES"
echo "LibreSSL logs: $N_LIBRE / $N_TRACES"
```

Expected: all four counts equal `N_TRACES`.

After Phase 0 completes, the Orchestrator runs **Phase 0.5** (empty-criteria bootstrap pass) before any metadata is read. Phase 0.5 is a token-cheap mechanical pass that produces a first cut of the bucket scaffold by running the triaging script with no buckets and clustering the resulting difference-pattern table. See `PHASE_0_5_BOOTSTRAP.md` for the protocol.

---

## What to do if a command fails

`tlspuffin` may exit with a non-zero code for traces where a PUT fails — this is expected. The `|| true` in the script ensures the loop continues regardless. The log file will contain the error output, which is useful for Phase 1 analysis.

Do not retry. Do not investigate failures. Log the output and move on.

---

## What NOT to do

- Do not read or analyse the log contents.
- Do not create bucket conditions.
- Do not write any bug reports.
- Do not modify the triaging script (`<triaging_script>`).

Your only job is to ensure all three log files **and** the JSON diff cache exist for every trace.
