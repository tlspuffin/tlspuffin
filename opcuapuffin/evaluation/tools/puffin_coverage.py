#!/usr/bin/env python3
"""
puffin_coverage.py - Core Engine for Puffin Coverage Analysis

This module provides two public classes:

  PuffinEngine   - Wraps the low-level toolchain (gcov-instrumented binary +
                   gcovr) to execute traces and extract coverage data.

  UIComponents   - Renders all shared HTML/CSS/JS artefacts: page wrappers,
                   sortable tables, minimaps, and per-file line views.

IMPORTANT – Protocol notes:
  - OPC UA  PUT name: "open62541"        (NOT "open62541-gcov")
  - TLS     PUT name: "openssl340-gcov"  (full versioned, gcov suffix required)

See tools/README_COVERAGE.md for full documentation.
"""

import os
import subprocess
import json
import csv
import glob
from pathlib import Path
import html as html_lib

# ---------------------------------------------------------------------------
# PROTOCOL PRESETS
# ---------------------------------------------------------------------------
# Each entry maps a short protocol key to the runtime configuration used by
# PuffinEngine.  Adjust 'excludes' to filter out files you do NOT want to
# appear in the coverage reports.  Patterns are passed to gcovr as --exclude.
#
# Notes on PUT (Program Under Test) names:
#   - opcua: the runtime --put value must be "open62541" (the base name).
#            "open62541-gcov" is only the vendor *build* target, not the PUT.
#   - tls:   the runtime --put value must be "openssl340-gcov" because the
#            TLS binary is built with multiple PUTs and the gcov one is
#            explicitly versioned.
# ---------------------------------------------------------------------------
PROTOCOLS = {
    "opcua": {
        # PUT name passed to `opcuapuffin --put <vendor>`
        "vendor": "open62541",
        # Path to the gcov-instrumented binary (relative to project root)
        "binary": "./target/release/opcuapuffin",
        # gcovr --exclude patterns: keep only open62541 vendor source
        "excludes": [
            ".*tests.*", ".*examples.*", ".*doc.*", ".*deps.*",
            ".*tools.*", ".*/puffin/.*", ".*/opcuapuffin/.*", ".*/crates/.*"
        ]
    },
    "tls": {
        # PUT name passed to `tlspuffin --put <vendor>`
        "vendor": "openssl340-gcov",
        # Path to the gcov-instrumented binary (relative to project root)
        "binary": "./target/release/tlspuffin",
        # gcovr --exclude patterns: keep only OpenSSL vendor source
        "excludes": [
            ".*wolf.*", ".*test.*", ".*apps.*", ".*include.*",
            ".*engine.*", ".*fuzz.*", ".*/puffin/.*", ".*/tlspuffin/.*",
            ".*/crates/.*"
        ]
    }
}


class PuffinEngine:
    """
    Low-level coverage engine.

    Responsibilities:
      - Execute corpus traces against the gcov-instrumented binary.
      - Invoke gcovr to extract JSON and HTML coverage reports.
      - Provide static helpers to aggregate file-level statistics.

    Usage:
      engine = PuffinEngine("tls")
      engine.clean_gcda()
      engine.execute_corpus("experiments/my_campaign/corpus")
      data = engine.extract_json("coverage-hub-tls/runs/my/coverage.json")
      engine.extract_html("coverage-hub-tls/runs/my/gcov/")
    """

    def __init__(self, protocol_name="opcua", vendor_override=None):
        """
        Args:
            protocol_name:   One of the keys in PROTOCOLS ("opcua" or "tls").
            vendor_override: If set, overrides the default PUT name (vendor).
                             Useful when testing a non-standard PUT variant.
        """
        if protocol_name not in PROTOCOLS:
            raise ValueError(
                f"Unknown protocol: {protocol_name}. Choose from {list(PROTOCOLS.keys())}"
            )
        self.protocol_name = protocol_name
        self.config = PROTOCOLS[protocol_name].copy()

        # Allow callers to override the PUT name (e.g. to use wolfssl-gcov)
        if vendor_override:
            self.config["vendor"] = vendor_override

        # llvm-cov gcov is required because Rust emits LLVM-format .gcno files
        self.config["gcov_exe"] = "llvm-cov gcov"

        # Temporary directory for fuzzer logs and intermediate gcov artefacts
        self.temp_dir = Path("tmp/coverage")
        self.temp_dir.mkdir(parents=True, exist_ok=True)

        # gcovr is always run from the project root so that relative source
        # paths in .gcno/.gcda files resolve correctly
        self.project_root = Path(".")

    def run_cmd(self, cmd, check=True, env=None, cwd=None):
        """
        Run a shell command, optionally capturing errors.

        Args:
            cmd:   Shell command string.
            check: If True, raise CalledProcessError on non-zero exit.
            env:   Optional environment variable overrides.
            cwd:   Working directory (defaults to current directory).
        """
        my_env = os.environ.copy()
        if env:
            my_env.update(env)
        res = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, env=my_env, cwd=cwd
        )
        if check and res.returncode != 0:
            print(f"Error running: {cmd}\nExit Code: {res.returncode}\n{res.stderr}")
            res.check_returncode()
        return res

    def clean_gcda(self):
        """
        Delete all .gcda files in the project tree.

        Must be called before each corpus execution to ensure that the
        coverage counters reflect only the current run and not previous ones.
        """
        print("  Cleaning old coverage data...")
        self.run_cmd("find . -name '*.gcda' -delete")

    def execute_corpus(self, corpus_dir, index=0, count=1000000):
        """
        Execute traces from a corpus directory using the PUT binary.

        The binary replays each .trace file and writes GCDA coverage counters
        to disk.  Output is redirected to a log file in tmp/coverage/.

        Args:
            corpus_dir: Path to the corpus directory (can be absolute or
                        relative to the project root).
            index:      Starting index (passed to --index).  Default 0.
            count:      Maximum number of traces to execute.  Default 1_000_000.
        """
        log_file = self.temp_dir / f"fuzzer_exec_{index}.log"
        print(
            f"  Executing {corpus_dir} [idx:{index}, count:{count}] "
            f"using PUT '{self.config['vendor']}'..."
        )
        print(f"  Log: {log_file}")
        # The binary must be on PATH or compiled; it is always invoked relative
        # to the project root so that relative corpus paths still resolve.
        cmd = (
            f"{self.config['binary']} --put {self.config['vendor']} "
            f"execute --index {index} -n {count} {corpus_dir} "
            f"> {log_file} 2>&1"
        )
        self.run_cmd(cmd)

    def extract_json(self, output_path):
        """
        Run gcovr in JSON mode and return the parsed coverage data.

        The JSON is written to output_path (created if missing) and also
        returned as a Python dict for immediate use.

        Args:
            output_path: Destination path for the coverage JSON file.

        Returns:
            dict: Parsed gcovr JSON object.
        """
        output_path = Path(output_path).absolute()
        output_path.parent.mkdir(parents=True, exist_ok=True)

        print(f"  Extracting JSON coverage to {output_path}...")
        exclude_args = " ".join([f'-e "{x}"' for x in self.config['excludes']])

        # --gcov-ignore-parse-errors prevents gcovr from aborting on stale
        # or mismatched .gcno/.gcda pairs that can appear after rebuilds.
        cmd = (
            f'gcovr -r "{self.project_root}" "{self.project_root}" '
            f'--gcov-executable "{self.config["gcov_exe"]}" '
            f'{exclude_args} --gcov-ignore-parse-errors '
            f'--json "{output_path}"'
        )
        self.run_cmd(cmd)

        with open(output_path) as f:
            return json.load(f)

    def extract_html(self, output_dir, force=False):
        """
        Run gcovr in HTML-details mode to produce the standard GCOV report.

        The report is skipped if index.html already exists, unless force=True.
        HTML is self-contained (all CSS/JS inlined) so it can be served
        directly from the hub without external dependencies.

        Args:
            output_dir: Directory where gcovr should write index.html.
            force:      If True, regenerate even if the report already exists.
        """
        output_dir = Path(output_dir).absolute()
        index_file = output_dir / "index.html"

        if not force and index_file.exists():
            print(f"  Reusing existing HTML coverage report at {index_file}")
            return

        output_dir.mkdir(parents=True, exist_ok=True)
        print(f"  Extracting HTML coverage to {index_file}...")
        exclude_args = " ".join([f'-e "{x}"' for x in self.config['excludes']])

        # -j 1 avoids occasional race conditions in gcovr's parallel writer.
        # --html-self-contained ensures the file is portable (no external deps).
        cmd = (
            f'gcovr -j 1 -r "{self.project_root}" "{self.project_root}" '
            f'--gcov-executable "{self.config["gcov_exe"]}" '
            f'{exclude_args} --gcov-ignore-parse-errors '
            f'--html-details --html-self-contained -o "{index_file}"'
        )
        try:
            self.run_cmd(cmd)
        except Exception as e:
            print(f"  Warning: Detailed HTML report generation failed: {e}")
            print("  The Hub and JSON data will still be available.")

    def extract_summary(self):
        """
        Run gcovr in JSON-summary mode and return the total branch coverage %.

        Useful for a lightweight check without writing files.

        Returns:
            float: Branch coverage percentage (0.0 – 100.0).
        """
        exclude_args = " ".join([f'-e "{x}"' for x in self.config['excludes']])
        cmd = (
            f'gcovr -r "{self.project_root}" "{self.project_root}" '
            f'--gcov-executable "{self.config["gcov_exe"]}" '
            f'{exclude_args} --json-summary-pretty'
        )
        res = self.run_cmd(cmd)
        try:
            data = json.loads(res.stdout)
            return data.get('branch_percent', 0.0)
        except Exception:
            return 0.0

    @staticmethod
    def calculate_file_stats(file_entry):
        """
        Aggregate line, branch, and function coverage stats from one gcovr
        file entry (i.e. one element of the 'files' array in coverage.json).

        Metrics:
          Lines    – only *executable* lines are counted (gcovr/noncode=False).
          Branches – each branch direction (taken / not-taken) is one unit.
          Functions – each named function is one unit.

        Args:
            file_entry: A dict with keys 'lines', 'functions' (from gcovr JSON).

        Returns:
            dict with keys:
              l_per, l_cov, l_total   – line coverage
              b_per, b_cov, b_total   – branch coverage
              f_per, f_cov, f_total   – function coverage
              lines                   – the raw line list (for file views)
        """
        lines = file_entry.get('lines', [])

        # Exclude non-code lines (blank lines, comments, preprocessor-only)
        executable = [l for l in lines if not l.get('gcovr/noncode', False)]
        l_total = len(executable)
        l_cov = len([l for l in executable if l.get('count', 0) > 0])

        # Each line can have multiple branches (e.g. both arms of an if-else)
        branch_total = 0
        branch_covered = 0
        for l in lines:
            branches = l.get('branches', [])
            branch_total += len(branches)
            branch_covered += len([b for b in branches if b.get('count', 0) > 0])

        # Functions are top-level entries in the gcovr JSON
        funcs = file_entry.get('functions', [])
        f_total = len(funcs)
        f_cov = len([f for f in funcs if f.get('execution_count', 0) > 0])

        return {
            'l_per':   (l_cov / l_total * 100) if l_total > 0 else 0,
            'l_cov':   l_cov,
            'l_total': l_total,
            'b_per':   (branch_covered / branch_total * 100) if branch_total > 0 else 0,
            'b_total': branch_total,
            'b_cov':   branch_covered,
            'f_per':   (f_cov / f_total * 100) if f_total > 0 else 0,
            'f_cov':   f_cov,
            'f_total': f_total,
            'lines':   lines,
        }


# ---------------------------------------------------------------------------
# UI COMPONENTS
# ---------------------------------------------------------------------------

class UIComponents:
    """
    Shared HTML/CSS/JS rendering helpers.

    All methods are static so they can be called without instantiation.
    They produce self-contained HTML fragments that are assembled by
    PuffinReporter into the final report pages.
    """

    @staticmethod
    def get_common_css():
        """Return the shared stylesheet used by all report pages."""
        return """
            body { font-family: sans-serif; background: #f8f9fa; margin: 0; }
            /* Sticky header bar: file name, back link, stats, diff nav */
            .header { position: sticky; top: 0; background: white; padding: 10px 20px;
                      border-bottom: 1px solid #ddd; z-index: 50; display: flex;
                      align-items: center; gap: 20px; font-size: 13px; }
            .pos { color: #1a7f37; font-weight: bold; }
            .neg { color: #cf222e; font-weight: bold; }
            table { border-collapse: collapse; width: 100%; background: white; font-size: 12px; }
            th, td { padding: 10px; text-align: left; border-bottom: 1px solid #eee; }
            th { background: #f1f3f5; }
            /* Monospace code view used in per-file pages */
            .code-view { font-family: monospace; white-space: pre; padding: 0; margin-right: 30px; }
            .line-container { display: flex; scroll-margin-top: 60px; }
            .line-num { width: 50px; text-align: right; padding-right: 10px;
                        color: #999; border-right: 1px solid #ddd; margin-right: 10px; }
            /* Hub dashboard cards */
            .card { background: white; padding: 20px; border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.05); margin-bottom: 30px; }
            h2 { border-bottom: 2px solid #007bff; padding-bottom: 5px; }
            .chart-container { height: 300px; margin-bottom: 40px; }
            /* Fixed right-side minimap (like VS Code) */
            .minimap { position: fixed; right: 0; top: 0; width: 25px; height: 100vh; cursor: crosshair; }
            .main-content { padding-right: 30px; }
            /* Line highlighting colours */
            .line-container.cov-both { background-color: #e6ffed; }  /* covered */
            .line-container.cov-none { background-color: #ffeef0; }  /* not covered */
            .line-container.cov-new  { background-color: #2ea44f; color: white; }  /* newly covered (diff) */
            .line-container.cov-lost { background-color: #cf222e; color: white; }  /* coverage lost (diff) */
            /* Navigation and action buttons */
            .nav-btn { background: #007bff; color: white; border: none; padding: 4px 12px;
                       border-radius: 4px; cursor: pointer; font-size: 12px; font-weight: bold; }
            .nav-btn:hover { background: #0056b3; }
            .nav-btn:disabled { background: #ccc; cursor: not-allowed; }
            /* Mini progress bars used in per-file stats header */
            .progress-bg { background: #eee; width: 100px; height: 12px; border-radius: 6px;
                           display: inline-block; vertical-align: middle; }
            .progress-fg { height: 100%; border-radius: 6px; background: #2ea44f; }
            /* Sortable column headers */
            th.sortable { cursor: pointer; position: relative; padding-right: 20px; }
            th.sortable::after { content: '↕'; position: absolute; right: 5px;
                                 color: #999; font-size: 10px; top: 50%; transform: translateY(-50%); }
            th.sortable.asc::after  { content: '▲'; color: #000; }
            th.sortable.desc::after { content: '▼'; color: #000; }
        """

    @staticmethod
    def get_sort_js():
        """
        Return the JavaScript block that powers column sorting on all tables.

        Parsing rules (applied in order):
          1. Transition cells (e.g. "10% → 20%") → sort by the right-hand value.
          2. Fraction cells (e.g. "12 / 48")     → sort by the numerator.
          3. Everything else                      → parse as a float.
        """
        return """
        <script>
        function sortTable(table, col, asc) {
            const tbody = table.tBodies[0];
            const rows = Array.from(tbody.querySelectorAll('tr'));
            const dirModifier = asc ? 1 : -1;

            rows.sort((a, b) => {
                let aText = a.querySelector(`td:nth-child(${col + 1})`).textContent.trim();
                let bText = b.querySelector(`td:nth-child(${col + 1})`).textContent.trim();

                // Transition cells: "43.4% → 42.1%" → sort by right-hand (target) value
                if (aText.includes('→')) aText = aText.split('→')[1];
                if (bText.includes('→')) bText = bText.split('→')[1];

                // Fraction cells: "12 / 48" → sort by numerator (covered count)
                if (aText.includes('/')) aText = aText.split('/')[0];
                if (bText.includes('/')) bText = bText.split('/')[0];

                // Strip everything except digits, minus, and decimal point
                let aVal = parseFloat(aText.replace(/[^0-9.-]+/g, ""));
                let bVal = parseFloat(bText.replace(/[^0-9.-]+/g, ""));

                if (!isNaN(aVal) && !isNaN(bVal)) {
                    if (aVal === bVal) return 0;
                    return aVal > bVal ? (1 * dirModifier) : (-1 * dirModifier);
                }
                // Fall back to lexicographic sort for non-numeric columns
                if (aText === bText) return 0;
                return aText > bText ? (1 * dirModifier) : (-1 * dirModifier);
            });

            while (tbody.firstChild) { tbody.removeChild(tbody.firstChild); }
            tbody.append(...rows);

            // Update sort indicator arrows
            table.querySelectorAll('th.sortable').forEach(th => th.classList.remove('asc', 'desc'));
            table.querySelector(`th:nth-child(${col + 1})`).classList.toggle('asc', asc);
            table.querySelector(`th:nth-child(${col + 1})`).classList.toggle('desc', !asc);
        }

        document.addEventListener('DOMContentLoaded', () => {
            document.querySelectorAll('th.sortable').forEach(headerCell => {
                headerCell.addEventListener('click', () => {
                    const tableElement = headerCell.parentElement.parentElement.parentElement;
                    const headerIndex = Array.prototype.indexOf.call(
                        headerCell.parentElement.children, headerCell
                    );
                    const currentIsAscending = headerCell.classList.contains('asc');
                    sortTable(tableElement, headerIndex, !currentIsAscending);
                });
            });
            // Call initNav() if the diff navigation script defined it
            if (typeof initNav === "function") initNav();
        });
        </script>
        """

    @staticmethod
    def page_wrapper(title, content, head_extra=""):
        """
        Wrap content in a full HTML document with shared CSS and sort JS.

        Args:
            title:      <title> tag content.
            content:    Body HTML string.
            head_extra: Additional <head> content (e.g. Chart.js script tag,
                        inline modal CSS for the hub dashboard).
        """
        return (
            f'<!DOCTYPE html><html><head><meta charset="UTF-8"><title>{title}</title>\n'
            f'<style>{UIComponents.get_common_css()}</style>{head_extra}</head>\n'
            f'<body>{content}{UIComponents.get_sort_js()}</body></html>'
        )

    @staticmethod
    def generate_minimap_html(code_lines, cov1, cov2=None):
        """
        Generate the VS Code-style minimap: a thin vertical strip on the right
        edge of the page where coloured pixels represent covered/uncovered lines.

        In single mode:  green = covered, nothing for uncovered.
        In diff mode:    green = newly covered, red = coverage lost.

        Args:
            code_lines: List of raw source lines (used for total height).
            cov1:       {line_number: count} dict for corpus A (or single run).
            cov2:       {line_number: count} dict for corpus B (diff mode only).

        Returns:
            str: HTML fragment of absolutely positioned <div> elements.
        """
        html = ""
        total = len(code_lines)
        if total == 0:
            return ""

        for i in range(total):
            ln = i + 1
            c1 = cov1.get(ln, 0)

            if cov2 is not None:  # Diff mode: show only changed lines
                c2 = cov2.get(ln, 0)
                if c1 == 0 and c2 > 0:
                    color = "#2ea44f"   # newly covered → green
                elif c1 > 0 and c2 == 0:
                    color = "#cf222e"   # coverage lost → red
                else:
                    continue            # unchanged → invisible
            else:                   # Single mode: show covered lines only
                color = "#2ea44f" if c1 > 0 else None
                if not color:
                    continue

            top_pct = (i / total) * 100
            html += (
                f'<div style="position:absolute; top:{top_pct}%; left:0; '
                f'width:100%; height:2px; background:{color};"></div>'
            )
        return html

    @staticmethod
    def generate_file_view(fname, s1_entry, s2_entry=None, base_rel=".."):
        """
        Generate a full HTML page showing line-by-line coverage for one file.

        Supports two modes:
          Single mode (s2_entry=None):
            - Green background = covered line.
            - Red background   = not covered.
            - Header shows Lines / Branches / Functions stats with progress bars.

          Diff mode (s2_entry provided):
            - Bright green = line newly covered in B (was 0 in A).
            - Bright red   = line lost coverage in B (was >0 in A).
            - Header shows Abs Delta and Rel Delta for the file.
            - PREV / NEXT navigation buttons jump between changed lines.

        Args:
            fname:     Absolute path to the source file on disk.
            s1_entry:  gcovr file entry dict (keys: 'lines', 'functions') for
                       corpus A (or the single run).  A bare list of lines is
                       also accepted for backwards compatibility.
            s2_entry:  gcovr file entry dict for corpus B (diff mode only).
            base_rel:  Relative path from the file view back to its parent
                       directory (used for the ← back link).

        Returns:
            str: Full self-contained HTML page as a string.
        """
        try:
            with open(fname, 'r') as f:
                code_lines = f.readlines()
        except Exception:
            return f"Could not read file {fname}"

        # Accept both a full entry dict and a bare list of lines (legacy)
        s1_lines = s1_entry.get('lines', []) if isinstance(s1_entry, dict) else s1_entry
        s2_lines = s2_entry.get('lines', []) if isinstance(s2_entry, dict) else (s2_entry or [])

        # Build line → hit-count lookup tables for fast access
        cov1 = {l['line_number']: l['count'] for l in s1_lines}
        cov2 = {l['line_number']: l['count'] for l in s2_lines}

        total_code = len([l for l in s1_lines if not l.get('gcovr/noncode', False)])

        minimap_html = UIComponents.generate_minimap_html(
            code_lines, cov1, cov2 if s2_lines else None
        )

        # Collect line numbers where coverage changed (for diff navigation)
        changes = []
        if s2_lines:
            for i in range(len(code_lines)):
                ln = i + 1
                gained = cov1.get(ln, 0) == 0 and cov2.get(ln, 0) > 0
                lost   = cov1.get(ln, 0) > 0  and cov2.get(ln, 0) == 0
                if gained or lost:
                    changes.append(ln)

        # PREV / NEXT navigation buttons (diff mode only)
        nav_html = ""
        if s2_lines and changes:
            nav_html = f"""
                <div style="display: flex; gap: 5px; align-items: center; margin-left: 20px;">
                    <button class="nav-btn" onclick="prevDiff()">PREV</button>
                    <span id="diff-count"
                          style="font-size: 11px; min-width: 60px; text-align: center; color: #444;">
                        0 / {len(changes)}
                    </span>
                    <button class="nav-btn" onclick="nextDiff()">NEXT</button>
                </div>
                <script>
                    const changes = {json.dumps(changes)};
                    let currentIdx = -1;
                    function initNav() {{ /* called by sort JS on DOMContentLoaded */ }}
                    function scroll() {{
                        const ln = changes[currentIdx];
                        document.getElementById('line-' + ln)
                                .scrollIntoView({{ behavior: 'smooth', block: 'center' }});
                        document.getElementById('diff-count').innerText =
                            (currentIdx + 1) + " / " + changes.length;
                    }}
                    function nextDiff() {{
                        if (currentIdx < changes.length - 1) {{ currentIdx++; scroll(); }}
                    }}
                    function prevDiff() {{
                        if (currentIdx > 0) {{ currentIdx--; scroll(); }}
                    }}
                </script>
            """

        # Build the sticky header stats block
        back_link = f"{base_rel}/diff_summary.html" if s2_lines else f"{base_rel}/index.html"

        if s2_lines:
            # Diff mode: show absolute and relative line-coverage deltas,
            # plus the per-file branch coverage transition (A% → B%).
            c1_cnt = len([ln for ln, c in cov1.items() if c > 0])
            c2_cnt = len([ln for ln, c in cov2.items() if c > 0])
            abs_delta = (c2_cnt - c1_cnt) / total_code * 100 if total_code > 0 else 0
            rel_delta = (
                (c2_cnt - c1_cnt) / c1_cnt * 100
                if c1_cnt > 0
                else (float('inf') if c2_cnt > 0 else 0)
            )
            rel_str = "+&infin;" if rel_delta == float('inf') else f"{rel_delta:+.2f}%"

            # Compute branch coverage % for A and B from the entry dicts
            sa = PuffinEngine.calculate_file_stats(s1_entry) if isinstance(s1_entry, dict) else {'b_per': 0.0}
            sb = PuffinEngine.calculate_file_stats(s2_entry) if isinstance(s2_entry, dict) else {'b_per': 0.0}
            transition_cls = 'pos' if sb['b_per'] >= sa['b_per'] else 'neg'

            stats_info = f"""
                <div style="margin-left: 20px; display: flex; gap: 20px; font-size: 11px; align-items: center;">
                    <span style="font-size: 13px; font-weight: bold; color: #333;">
                        {sa['b_per']:.1f}% &rarr;
                        <span class="{transition_cls}">{sb['b_per']:.1f}%</span>
                        <small style="font-weight:normal; color:#666; margin-left:4px;">(branch)</small>
                    </span>
                    <span><b>Abs Delta:</b>
                        <span class="{'pos' if abs_delta >= 0 else 'neg'}">{abs_delta:+.2f}%</span>
                    </span>
                    <span><b>Rel Delta:</b>
                        <span class="{'pos' if rel_delta >= 0 else 'neg'}">{rel_str}</span>
                    </span>
                    <span style="color:#666;">({total_code} code lines)</span>
                </div>
            """

        elif isinstance(s1_entry, dict):
            # Single mode: show Lines / Branches / Functions with progress bars
            stats = PuffinEngine.calculate_file_stats(s1_entry)
            stats_info = f"""
                <div style="margin-left: 20px; display: flex; gap: 20px; font-size: 12px; align-items: center;">
                    <div style="display:flex; flex-direction:column; gap:2px;">
                        <span><b>Lines:</b> {stats['l_per']:.1f}%
                            <small style="color:#666">({stats['l_cov']} / {stats['l_total']})</small>
                        </span>
                        <div class="progress-bg" style="width:100%;">
                            <div class="progress-fg" style="width: {stats['l_per']}%; height:4px;"></div>
                        </div>
                    </div>
                    <div style="display:flex; flex-direction:column; gap:2px;">
                        <span><b>Branches:</b> {stats['b_per']:.1f}%
                            <small style="color:#666">({stats['b_cov']} / {stats['b_total']})</small>
                        </span>
                        <div class="progress-bg" style="width:100%;">
                            <div class="progress-fg" style="width: {stats['b_per']}%; height:4px;"></div>
                        </div>
                    </div>
                    <div style="display:flex; flex-direction:column; gap:2px;">
                        <span><b>Functions:</b> {stats['f_per']:.1f}%
                            <small style="color:#666">({stats['f_cov']} / {stats['f_total']})</small>
                        </span>
                        <div class="progress-bg" style="width:100%;">
                            <div class="progress-fg" style="width: {stats['f_per']}%; height:4px;"></div>
                        </div>
                    </div>
                </div>
            """
        else:
            stats_info = f'<span style="color:#666; margin-left:15px;">({total_code} code lines)</span>'

        header = f"""
            <div class="header">
                <a href="{back_link}"
                   style="position: relative; z-index: 1000; padding: 4px 8px;
                          background: #e0e0e0; border-radius: 4px; text-decoration: none;
                          color: black; font-weight: bold;">&larr; back</a>
                <div style="flex-grow:1; font-weight:bold; margin-left:10px;">
                    {fname}
                    <small style="color:#888; font-weight:normal; margin-left:10px;">
                        Ground-Truth (GCOV)
                    </small>
                </div>
                {nav_html}
                {stats_info}
            </div>
        """

        # Scrollable minimap on the right edge
        body = (
            f'<div class="minimap" style="background:#f6f8fa; border-left:1px solid #ddd;" '
            f'onclick="window.scrollTo(0, (event.clientY / window.innerHeight) * '
            f'document.documentElement.scrollHeight)">'
            f'{minimap_html}</div>'
        )
        body += f'<div class="main-content">{header}<div class="code-view">'

        # Render each source line with the appropriate CSS class
        for i, line in enumerate(code_lines):
            ln = i + 1
            c1, c2 = cov1.get(ln, 0), cov2.get(ln, 0)
            prefix = " "

            if s2_lines:
                # Diff mode colouring
                if   c1 == 0 and c2 > 0: css = "cov-new";  prefix = "+"
                elif c1 > 0 and c2 == 0: css = "cov-lost"; prefix = "-"
                elif c1 > 0:             css = "cov-both"
                else:                    css = "cov-none"
            else:
                # Single mode colouring
                css = "cov-both" if c1 > 0 else "cov-none"

            # Assign an id so PREV/NEXT navigation can scroll to changed lines
            id_attr = f' id="line-{ln}"' if ln in changes else ""
            body += (
                f'<div class="line-container {css}"{id_attr}>'
                f'<div class="line-num">{ln}</div>'
                f'{prefix} {html_lib.escape(line.rstrip())}</div>'
            )

        return UIComponents.page_wrapper(fname, body + "</div></div>")
