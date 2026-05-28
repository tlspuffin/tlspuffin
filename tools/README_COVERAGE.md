# Puffin Coverage System

A unified, modular system for measuring ground-truth source coverage, performing differential analysis, and visualizing the progress of fuzzing campaigns for Puffin-based protocol fuzzers.

## Features
- **Unified Reporting:** Single campaign analysis and differential analysis share a common infrastructure.
- **Coverage Growth Curve:** Automatic visualization of branch coverage progress using Chart.js.
- **Differential Analysis:** Compare two corpora (e.g., Seeds vs. Fuzzing results) to see exactly which code paths were gained or lost.
- **Interactive Reports:** Line-by-line coverage views with a VS Code-style clickable minimap for rapid navigation to deltas.
- **Master Dashboard:** An automated hub that discovers and indexes all experiments.
- **Artifact Management:** All temporary GCOV artifacts are stored in `tmp/coverage/` to keep your project root clean.

## 1. Setup & Build

Coverage measurement requires the PUT (Program Under Test) and the Puffin binary to be built with `gcov` instrumentation. We recommend using `--release` mode for performance.

### For OPC UA (open62541):
1. **Build Vendor:**
   ```bash
   ./tools/mk_vendor make open62541:open62541-gcov --force
   ```
2. **Build Binary:**
   ```bash
   LIBAFL_EDGES_MAP_SIZE=262144 cargo build --release -p opcuapuffin --features gcov,watch-vendor
   ```

### For TLS (OpenSSL/BoringSSL/etc.):
1. **Build Vendor:**
   ```bash
   ./tools/mk_vendor make openssl:openssl340-gcov --force
   ```
2. **Build Binary:**
   ```bash
   cargo build --release -p tlspuffin --features gcov,cputs,watch-vendor
   ```
   *Note: The `watch-vendor` feature (now standard in `dev`) ensures the fuzzer is recompiled if vendor files change.*

## 2. Using the Reporting System

The `tools/puffin_report.py` script manages the entire lifecycle of execution, extraction, and visualization. **Always run this script from the project root.**

### Run a Single Campaign
Measures coverage for a single directory and adds it to the master hub.
```bash
# Usage: ./tools/puffin_report.py run <protocol> <corpus_dir> [--put <name>] [--force]
./tools/puffin_report.py run tls experiments/my_campaign/corpus --put openssl340-gcov
```

### Run a Differential Analysis
Compares two corpora (A and B). This automatically generates individual reports for both AND a differential dashboard.
```bash
# Usage: ./tools/puffin_report.py diff <protocol> <dir_a> <dir_b> [--put <name>] [--force]
./tools/puffin_report.py diff tls seeds experiments/my_campaign/corpus --put openssl340-gcov
```

### View the Master Hub
The system maintains a centralized hub at `./coverage-hub-<protocol>/index.html`. It automatically discovers all runs and plots the coverage growth curve.

## 3. Viewing Results

Start an HTTP server in the project root to view the interactive reports:
```bash
python3 -m http.server 8890
```
Then navigate to:
**http://localhost:8890/coverage-hub-opcua/index.html**

## 4. Technical Architecture

- **`tools/puffin_coverage.py`**: The **Core Engine**. Handles execution logic, `gcovr` JSON extraction, and shared UI components (CSS, Page Wrappers, Minimap).
- **`tools/puffin_report.py`**: The **Orchestrator**. Manages the high-level workflow, metadata persistence, and master dashboard generation.

## 5. Tips & Troubleshooting
- **Artifact Cleanup:** If you want to clear intermediate files, you can safely delete `tmp/coverage/`.
- **JSON Reuse:** The script automatically reuses existing `coverage.json` files to speed up re-generation. Use `--force` to re-execute traces.
- **Protocol Support:** Currently supports `opcua` and `tls`.

- **Absolute Delta:** The change in total branch coverage percentage (e.g., +1.0% means 1% more of the entire file is covered).
- **Relative Delta:** The growth or reduction relative to the baseline coverage. *Note: If the baseline coverage is 0.0%, any new coverage is displayed as +100%.*
- **Ground-Truth (GCOV):** All metrics are derived from high-fidelity compiler-level counters, providing a precise measurement compared to fuzzer approximations.

## 6. Customizing Coverage Filters

To ensure the reports focus strictly on the library under test (the PUT), the system filters out fuzzer infrastructure and test code.

### How it works
Filtering is **centralized** in `tools/puffin_coverage.py` within the `PROTOCOLS` dictionary. These filters are passed directly to `gcovr`. Because the script aggregates data from the resulting filtered JSON, **the Hub percentages and the Detailed GCOV reports will always be perfectly consistent.**

### How to adapt filters
1. Open `tools/puffin_coverage.py`.
2. Locate the `excludes` list for your protocol:
   ```python
   "excludes": [".*tests.*", ".*examples.*", ".*/puffin/.*", ...]
   ```
3. Add or remove regex patterns as needed.
4. Re-run your report with the **`--force`** flag to apply the new filters to existing data:
   ```bash
   ./tools/puffin_report.py run opcua <dir> --force
   ```
