# Puffin Coverage System

A unified, modular system for measuring ground-truth source coverage, performing differential analysis,
and visualizing the progress of fuzzing campaigns for Puffin-based protocol fuzzers.

## Features

- **Single-Run Analysis:** Measure branch, line, and function coverage for any individual corpus.
- **Differential Analysis:** Compare two corpora side-by-side to see exactly which code paths were gained or lost.
- **Coverage Growth Curve:** Automatic visualization of branch coverage progress across all runs (Chart.js).
- **Line-by-Line File Views:** Each source file gets an interactive view with VS Code-style minimap, coverage stats (Lines / Branches / Functions with absolute counts and ratios), and a clickable "Path" button to copy the corpus path to the clipboard.
- **Master Dashboard Hub:** Auto-discovers all runs and diffs; lets you launch new computations and remove stale reports directly from the browser.
- **Interactive Server:** `puffin_server.py` provides REST endpoints (`/api/delete`, `/api/compute`) for in-browser report management.
- **Smart Caching:** JSON coverage data is reused if already computed; use `--force` to bypass.

---

## 1. Setup & Build

Coverage measurement requires the PUT (Program Under Test) and the Puffin binary to be built with
`gcov` instrumentation. Always use `--release` mode for realistic performance.

### For OPC UA (open62541)

```bash
# 1. Build the gcov-instrumented vendor library
./tools/mk_vendor make open62541:open62541-gcov --force

# 2. Build the binary (gcov + watch-vendor features required)
LIBAFL_EDGES_MAP_SIZE=262144 cargo build --release -p opcuapuffin --features gcov,watch-vendor
```

> **PUT name for OPC UA:** `open62541` (NOT `open62541-gcov`; the gcov suffix is only for the vendor build step)

### For TLS (OpenSSL 3.4.0)

```bash
# 1. Build the gcov-instrumented vendor library
./tools/mk_vendor make openssl:openssl340-gcov --force

# 2. Build the binary (gcov + cputs + watch-vendor features required)
cargo build --release -p tlspuffin --features gcov,cputs,watch-vendor
```

> **PUT name for TLS:** `openssl340-gcov` (the full versioned name is required for TLS)

> **Note:** The `watch-vendor` feature ensures the fuzzer binary is recompiled if vendor files change.

---

## 2. Using the CLI

The `tools/puffin_report.py` script manages the full lifecycle: execute traces → extract JSON coverage
→ render HTML reports → update the master hub. **Always run from the project root.**

### Run a Single Campaign

Measures coverage for one corpus directory and adds it to the master hub.

```bash
<<<<<<< HEAD
# TLS (must specify the full gcov PUT name)
./tools/puffin_report.py run tls experiments/my_campaign/corpus --put openssl340-gcov

# OPC UA (uses the base PUT name, not open62541-gcov)
./tools/puffin_report.py run opcua experiments/my_campaign/corpus --put open62541

# Give it a custom name shown in the hub (optional)
./tools/puffin_report.py run tls experiments/my_campaign/corpus --put openssl340-gcov --name "my_run"

# Force a full re-execution ignoring cached data
./tools/puffin_report.py run tls experiments/my_campaign/corpus --put openssl340-gcov --force
=======
# Example for TLS (Requires explicit -gcov PUT name)
./tools/puffin_report.py run tls experiments/my_campaign/corpus --put openssl340-gcov

# Example for OPC UA (Always uses the base PUT name)
./tools/puffin_report.py run opcua experiments/my_campaign/corpus --put open62541
>>>>>>> cff765a0a (minor)
```

### Run a Differential Analysis

Compares two corpora (A → B). Produces individual reports for both AND an interactive differential dashboard.

```bash
<<<<<<< HEAD
# TLS: compare seeds vs fuzzing results
./tools/puffin_report.py diff tls experiments/tls_seeds experiments/my_campaign/corpus \
    --put openssl340-gcov --name seeds_vs_campaign

# OPC UA: compare seeds vs fuzzing results
./tools/puffin_report.py diff opcua experiments/opcua_seeds experiments/my_campaign/corpus \
    --put open62541 --name seeds_vs_campaign
=======
# Example for TLS
./tools/puffin_report.py diff tls seeds experiments/my_campaign/corpus --put openssl340-gcov

# Example for OPC UA
./tools/puffin_report.py diff opcua seeds_opcua experiments/my_campaign/corpus --put open62541
>>>>>>> cff765a0a (minor)
```

### All CLI Options

```
usage: puffin_report.py [-h] [--put PUT] [--force] [--name NAME]
                        {run,diff} {opcua,tls} dirs [dirs ...]

positional arguments:
  {run,diff}    Mode: single run or differential analysis
  {opcua,tls}   Protocol to analyse
  dirs          For 'run': one corpus path. For 'diff': two paths (A then B)

optional arguments:
  --put PUT     PUT (Program Under Test) name for the gcov-instrumented binary.
                Default: open62541 (opcua) / openssl340-gcov (tls)
  --name NAME   Human-readable name for the report in the hub
  --force       Force re-execution of traces even if coverage.json already exists
```

---

## 3. Viewing Results in the Browser

### Option A – Interactive Server (recommended)

Start the Puffin interactive server, which supports in-browser deletion and compute launch:

```bash
python3 tools/puffin_server.py 8890
```

Then open:
- **http://localhost:8890/coverage-hub-tls/index.html**
- **http://localhost:8890/coverage-hub-opcua/index.html**

### Option B – Read-only Static Server

For read-only browsing without the management features:

```bash
python3 -m http.server 8890
```

> ⚠️ The "Remove" and "Compute Cov" buttons in the hub **require** `puffin_server.py`.

---

## 4. Using the Hub (Interactive Features)

### + Compute Cov Button

Located at the top-right of the master hub. Opens a modal where you can:

- **Mode:** Select *Individual Run* (single path) or *Differential Analysis* (A vs B).
- **Path A / Path B:** Absolute paths on the server to the corpus directories.
- **Name:** Optional human-readable label for the report.
- **PUT Override:** Override the default PUT name (leave blank to use the protocol default).
- **Force:** Tick to bypass all caches and re-execute from scratch.

After clicking *Launch Compute*, the job runs in the background inside `nix-shell`. Watch the terminal
for live progress. Reload the hub when done.

### Remove Button

Every row in the Individual Campaigns and Differential Analysis tables has a **Remove** button.
Clicking it prompts for confirmation, then deletes the report's data folder and regenerates the hub.

### Path Button

Next to the README link in every individual report header is a **Path** label. Clicking it copies the
absolute path of the corpus to your clipboard and shows a brief "copied!" confirmation.

---

## 5. Output Structure

```
coverage-hub-<protocol>/
├── index.html                    # Master hub dashboard
├── runs/
│   └── <name>/
│       ├── index.html            # Campaign overview table
│       ├── metadata.json         # Stored coverage %, corpus path, timestamp
│       ├── coverage.json         # Raw gcovr JSON (cached, reused unless --force)
│       ├── gcov/index.html       # Rendered gcovr HTML report
│       └── files/
│           └── <file>.html       # Per-source-file line view with stats
└── diffs/
    └── <name>/
        ├── diff_summary.html     # Differential table (sortable columns)
        ├── metadata.json         # Stored delta %, paths, timestamp
        ├── corpus_a.json         # gcovr JSON for corpus A (cached)
        ├── corpus_b.json         # gcovr JSON for corpus B (cached)
        ├── report_a/             # Full individual report for corpus A
        └── report_b/             # Full individual report for corpus B
```

---

## 6. Technical Architecture

| File | Role |
|---|---|
| `tools/puffin_coverage.py` | **Core Engine.** `PuffinEngine` executes traces and drives `gcovr`. `UIComponents` renders all shared HTML/CSS/JS (tables, minimap, file views, sorting). |
| `tools/puffin_report.py` | **Orchestrator.** `PuffinReporter` manages the high-level workflow: loading data, calling the engine, persisting metadata, generating the master hub. |
| `tools/puffin_server.py` | **Interactive Server.** Extends Python's `SimpleHTTPRequestHandler` with two REST POST endpoints: `/api/delete` (remove a report folder and regenerate hub) and `/api/compute` (launch a new coverage job asynchronously inside `nix-shell`). |

---

## 7. Sorting & Column Details

All tables are sortable by clicking any column header (↑ / ↓). The JavaScript parser handles:

| Cell content | Parsed as |
|---|---|
| `10.0%` | Float percentage |
| `10% → 20%` | Float of the **target** (right-hand) value |
| `12 / 48` | Float of the **numerator** (covered count) |
| Plain numbers | Float directly |

---

## 8. Coverage Metrics Explained

- **Lines:** Percentage of *executable* source lines reached (blank lines, comments, and pure braces excluded).
- **Branches:** Percentage of branch paths taken (each `if`, `else`, loop condition counts as 2 branches: taken / not-taken).
- **Functions:** Percentage of functions called at least once.
- **Absolute Delta:** The change in total branch coverage % (e.g., `+1.0%` = 1 more percent of the whole file covered).
- **Relative Delta:** Growth relative to the baseline (e.g., `+100%` means coverage doubled from the baseline). Displayed as `+∞` when the baseline was 0%.
- **GCOV Transition:** Baseline % → Target % (e.g., `43.4% → 42.1%`). All metrics are derived from compiler-level GCOV counters — not fuzzer approximations.

---

## 9. Customizing Coverage Filters

Filters control which source files appear in reports. They are centralised in `tools/puffin_coverage.py`
in the `PROTOCOLS` dictionary and are passed directly to `gcovr --exclude`.

```python
PROTOCOLS = {
    "opcua": {
        "excludes": [".*tests.*", ".*examples.*", ".*/puffin/.*", ...],
    },
    "tls": {
        "excludes": [".*wolf.*", ".*test.*", ".*/puffin/.*", ...],
    }
}
```

To add or remove filters:
1. Edit the `excludes` list in `tools/puffin_coverage.py`.
2. Re-run with `--force` to apply the new filters to existing data.

---

## 10. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `PUT not found: open62541-gcov` | Wrong PUT name for OPC UA | Use `--put open62541` |
| 0.0% coverage on a diff report | Path A/B doesn't exist or has no `.trace` files | Check the path; verify the corpus was generated correctly |
| 404 on a file view | Report was deleted while hub still references it | Click *Remove* on the hub row and recompute |
| "Remove" / "Compute Cov" buttons don't work | Running plain `http.server` | Restart with `python3 tools/puffin_server.py 8890` |
| Stale percentages in hub | Cached `coverage.json` | Re-run with `--force` |
