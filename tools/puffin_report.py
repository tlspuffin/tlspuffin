#!/usr/bin/env python3
"""
puffin_report.py - Unified Puffin Coverage Reporting Orchestrator

This is the top-level script for measuring and visualising coverage for
Puffin-based protocol fuzzers (TLS / OPC UA).  It drives the full pipeline:

  1. Execute corpus traces against the gcov-instrumented binary.
  2. Extract JSON coverage data via gcovr.
  3. Render per-file HTML views (line-by-line, with minimap + stats header).
  4. Generate campaign index pages and the master hub dashboard.
  5. For differential analysis: compare two corpora and produce a delta table.

Entry point (CLI):
  ./tools/puffin_report.py run  {opcua|tls} <corpus>              [options]
  ./tools/puffin_report.py diff {opcua|tls} <corpus_A> <corpus_B> [options]

Options:
  --put  <name>   Override the default PUT name (see README_COVERAGE.md §1).
  --name <label>  Human-readable name shown in the hub.
  --force         Re-execute traces even if coverage.json already exists.

Output layout:
  coverage-hub-<protocol>/
  ├── index.html             ← Master hub (+ Compute Cov button, charts)
  ├── runs/<name>/           ← Single-run report
  │   ├── index.html
  │   ├── metadata.json
  │   ├── coverage.json      ← Cached gcovr JSON (reused unless --force)
  │   ├── gcov/              ← Rendered gcovr HTML report
  │   └── files/             ← Per-source-file line views
  └── diffs/<name>/          ← Differential report
      ├── diff_summary.html
      ├── diff.json          ← Cached diff data
      ├── corpus_a.json      ← Cached gcovr JSON for A
      ├── corpus_b.json      ← Cached gcovr JSON for B
      ├── report_a/          ← Full individual report for A
      ├── report_b/          ← Full individual report for B
      └── files/             ← Per-file diff views

Always run from the project root.
See tools/README_COVERAGE.md for full documentation.
"""

import sys
import os
import json
from pathlib import Path
from puffin_coverage import PuffinEngine, UIComponents


class PuffinReporter:
    """
    High-level orchestrator for Puffin coverage reporting.

    One instance corresponds to one protocol hub (e.g. all TLS reports live
    under coverage-hub-tls/).  It holds the lists of discovered single runs
    and diff runs that are rendered into the master dashboard.
    """

    def __init__(self, protocol="opcua", output_root="./puffin-coverage-reports",
                 vendor_override=None):
        """
        Args:
            protocol:        "opcua" or "tls".
            output_root:     Root directory for all generated reports.
                             Conventionally "./coverage-hub-<protocol>".
            vendor_override: If set, overrides the default PUT name for the
                             coverage engine (e.g. to use a non-standard vendor).
        """
        self.protocol = protocol
        self.engine = PuffinEngine(protocol, vendor_override=vendor_override)
        self.root = Path(output_root)
        self.root.mkdir(parents=True, exist_ok=True)
        # Populated by discover_runs() and kept in sync by run_single/run_diff
        self.single_runs = []
        self.diff_runs = []

    # ------------------------------------------------------------------
    # Corpus metadata helpers
    # ------------------------------------------------------------------

    def get_corpus_info(self, corpus_dir):
        """
        Extract rich metadata from a corpus directory for display in report headers.

        Inspects the corpus directory and its parent experiment folder to gather:
          - Number of .trace files (fuzzer-generated inputs).
          - Campaign duration (oldest → newest trace timestamp).
          - Core count (from info.*.gz files in the sibling log/ directory).
          - README content (from the parent directory's README.md, if any).
          - A clickable "Path" button that copies the absolute corpus path to
            the clipboard with a 2-second "copied!" confirmation message.

        Args:
            corpus_dir: Path to the corpus directory (str or Path).

        Returns:
            (meta_html, readme_html): Two HTML fragments for embedding in headers.
              meta_html   — inline span with trace count, duration, core count.
              readme_html — collapsible README viewer + Path copy button.
        """
        corpus_path = Path(corpus_dir)
        traces = list(corpus_path.glob("*.trace"))
        num_traces = len(traces)

        # --- Duration ---
        # Compute wall-clock duration of the fuzzing campaign from file timestamps.
        # Uses the oldest and newest .trace files as start/end anchors.
        duration_str = ""
        if num_traces > 1:
            try:
                times = sorted([t.stat().st_mtime for t in traces])
                duration_sec = times[-1] - times[0]
                hours, remainder = divmod(int(duration_sec), 3600)
                minutes, seconds = divmod(remainder, 60)
                if hours > 0:
                    duration_str = f"{hours}h {minutes}m"
                else:
                    duration_str = f"{minutes}m {seconds}s"
            except Exception:
                pass  # Non-critical; omit duration if timestamps are unavailable

        # --- Core count ---
        # LibAFL writes one info.*.gz file per fuzzer core in the log/ directory.
        cores_str = ""
        log_dir = corpus_path.parent / "log"
        if log_dir.exists():
            num_cores = len(list(log_dir.glob("info.*.gz")))
            if num_cores > 0:
                cores_str = f" | {num_cores} cores"

        # --- README ---
        # Display the experiment's README.md in a collapsible dropdown.
        # Guard against accidentally showing the project-root README.
        readme_path = corpus_path.parent / "README.md"
        root_readme = Path.cwd().absolute() / "README.md"

        if readme_path.exists() and readme_path.resolve() != root_readme.resolve():
            with open(readme_path, "r") as f:
                content = f.read()
            # Basic HTML escaping — the README content is pre-formatted so we
            # wrap it in <pre> rather than rendering Markdown.
            content = content.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            readme_html = f"""
            <details style="font-size: 11px; position: relative; display: inline-block;">
                <summary style="cursor: pointer; font-weight: bold; color: #007bff;">View README</summary>
                <div style="position: absolute; top: 100%; left: 0; z-index: 100; width: 600px;
                            margin-top: 5px; background: white; border: 1px solid #ddd;
                            border-radius: 4px; box-shadow: 0 4px 12px rgba(0,0,0,0.15);">
                    <pre style="white-space: pre-wrap; word-wrap: break-word; font-size: 10px;
                                color: #333; margin: 0; padding: 10px; max-height: 400px;
                                overflow-y: auto;">{content}</pre>
                </div>
            </details>
            """
        else:
            readme_html = """<span style="color: #888; font-style: italic; font-size: 11px;">(no readme)</span>"""

        # --- Path copy button ---
        # Clicking "Path" copies the absolute corpus path to the clipboard and
        # shows a transient "copied!" confirmation that fades out after 2 s.
        # We escape backslashes and quotes so the path is safe inside an onclick
        # attribute string.
        abs_path = str(corpus_path.absolute()).replace('\\', '\\\\').replace('"', '\\"')
        readme_html += f"""
        <span style="font-size: 11px; margin-left: 8px; cursor: pointer; color: #007bff;
                     font-weight: bold; display: inline-flex; align-items: center;"
              onclick="navigator.clipboard.writeText('{abs_path}');
                       const msg = this.nextElementSibling;
                       msg.style.opacity = 1;
                       setTimeout(()=>msg.style.opacity = 0, 2000);">Path</span>
        <span style="font-size: 10px; color: #28a745; margin-left: 5px; opacity: 0;
                     transition: opacity 0.3s ease; pointer-events: none;">copied!</span>
        """

        duration_display = f" | {duration_str}" if duration_str else ""
        meta_html = (
            f'<span style="color:#666; font-size:11px;">'
            f'({num_traces} traces{duration_display}{cores_str})</span>'
        )

        return meta_html, readme_html

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    def save_report(self, name, json_data, out_dir, corpus_path, force=False):
        """
        Render a complete campaign report from gcovr JSON data.

        Produces:
          - out_dir/gcov/         Standard gcovr HTML report (skipped if exists
                                  and force=False).
          - out_dir/files/        Per-file line-by-line views with stats header
                                  and VS Code-style minimap.
          - out_dir/index.html    Campaign overview: branch coverage bar chart,
                                  link to gcovr report, sortable file table.
          - out_dir/metadata.json Lightweight record used by discover_runs().

        Args:
            name:        Human-readable label for this campaign.
            json_data:   Parsed gcovr JSON dict (from PuffinEngine.extract_json).
            out_dir:     Destination directory (created if missing).
            corpus_path: Path to the corpus (embedded in metadata and header).
            force:       If True, regenerate the gcovr HTML even if it exists.
        """
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        # Step 1 — Standard gcovr HTML report
        # This is the high-fidelity rendered report produced by gcovr itself.
        # It is separate from our custom per-file views.
        self.engine.extract_html(out_dir / "gcov", force=force)

        # Step 2 — Aggregate branch coverage across all files for metadata
        t_b, c_b = 0, 0
        for f_entry in json_data['files']:
            stats = self.engine.calculate_file_stats(f_entry)
            t_b += stats['b_total']
            c_b += stats['b_cov']
        b_per = (c_b / t_b * 100) if t_b > 0 else 0

        # Persist lightweight metadata so discover_runs() can rebuild the hub
        # without re-reading the full (large) coverage.json.
        metadata = {
            "name": name,
            "corpus_path": str(corpus_path),
            "total_branch_coverage": b_per,
            "timestamp": os.path.getmtime(out_dir),
        }
        with open(out_dir / "metadata.json", "w") as f:
            json.dump(metadata, f)

        # Step 3 — Per-file line views and campaign index table
        file_views_dir = out_dir / "files"
        file_views_dir.mkdir(exist_ok=True)

        rows = ""
        for f_entry in json_data['files']:
            fname = f_entry['file']
            stats = self.engine.calculate_file_stats(f_entry)
            # Flatten the file path into a safe filename (/ → _, . → _)
            safe_name = fname.replace('/', '_').replace('.', '_') + ".html"

            # Generate the interactive line-by-line file view (single mode)
            html = UIComponents.generate_file_view(fname, f_entry, base_rel="..")
            with open(file_views_dir / safe_name, 'w') as f:
                f.write(html)

            link = f"files/{safe_name}"
            rows += f"""<tr>
                <td><a href='{link}'>{fname}</a></td>
                <td>
                    <div class="progress-bg"><div class="progress-fg" style="width: {stats['b_per']}%"></div></div>
                    <span style="margin-left:10px;">{stats['b_per']:.1f}%</span>
                </td>
                <td><small style="color:#666">{stats['b_cov']} / {stats['b_total']}</small></td>
             </tr>"""

        # Step 4 — Campaign index page (overview with link to gcovr + file table)
        meta_html, readme_html = self.get_corpus_info(corpus_path)
        # hub_rel correctly resolves to the right depth whether this is a
        # top-level run (runs/<name>/) or a diff sub-report (diffs/<name>/report_a/).
        hub_rel = os.path.relpath(self.root, out_dir)
        content = f"""<h1>Campaign: {name}</h1>
        <div class="header">
            <a href="{hub_rel}/index.html"
               style="position: relative; z-index: 1000; padding: 4px 8px;
                      background: #e0e0e0; border-radius: 4px; text-decoration: none;
                      color: black; font-weight: bold;">&larr; hub</a>
            <div style="display:flex; align-items:center; gap:10px;">
                <span>{corpus_path}</span>
                {meta_html}
                {readme_html}
            </div>
            <span class="pos" style="margin-left:auto;">
                Ground-Truth (GCOV) Branch Coverage: {b_per:.2f}%
            </span>
        </div>
        <div class="card" style="margin-top: 20px;">
            <h2>Detailed Coverage Report</h2>
            <p>The high-fidelity GCOV report is available here:</p>
            <a href="gcov/index.html" style="font-size: 1.2em; font-weight: bold;">
                View Detailed GCOV HTML Report
            </a>
        </div>
        <table><thead><tr>
            <th class="sortable">File</th>
            <th class="sortable">GCOV Branch Coverage</th>
            <th class="sortable">Details (Branches)</th>
        </tr></thead><tbody>{rows}</tbody></table>"""

        with open(out_dir / "index.html", "w") as f:
            f.write(UIComponents.page_wrapper(name, content))

    # ------------------------------------------------------------------
    # Hub discovery
    # ------------------------------------------------------------------

    def discover_runs(self):
        """
        Rebuild self.single_runs and self.diff_runs by scanning the filesystem.

        Single runs are discovered from:
          runs/*/metadata.json                  (top-level single runs)
          diffs/*/report_*/metadata.json         (sub-reports inside diffs)

        Diff runs are discovered from:
          diffs/*/diff.json

        De-duplication: if two metadata.json files resolve to the same corpus
        path, only the first one (by glob order) is included. This avoids
        showing the same corpus twice when it appears in both a standalone run
        and as a diff sub-report.

        Runs are sorted by timestamp (oldest first) for the growth curve chart.
        """
        seen_paths = set()
        self.single_runs = []

        meta_paths = (
            list(self.root.glob("runs/*/metadata.json"))
            + list(self.root.glob("diffs/*/report_*/metadata.json"))
        )

        for meta_path in meta_paths:
            with open(meta_path) as f:
                m = json.load(f)

            # Normalise the corpus path for de-duplication
            try:
                cpath = Path(m['corpus_path']).resolve()
            except Exception:
                cpath = m['corpus_path']

            if cpath in seen_paths:
                continue
            seen_paths.add(cpath)

            # For diff sub-reports, derive a cleaner display name from the corpus
            # path rather than using the internal "<diff_name>_A" label.
            display_name = m['name']
            if "diffs" in meta_path.parts:
                raw_name = Path(m['corpus_path']).name
                parent_name = Path(m['corpus_path']).parent.name
                # Use "experiment_dir/corpus" form for generic directory names
                if raw_name in ["corpus", "seeds"] and parent_name and parent_name != "experiments":
                    display_name = f"{parent_name}/{raw_name}"
                else:
                    display_name = raw_name

            self.single_runs.append({
                "name": display_name,
                "path": m['corpus_path'],
                "coverage": m['total_branch_coverage'],
                "timestamp": m['timestamp'],
                "report": str((meta_path.parent / "index.html").relative_to(self.root)),
            })

        # Sort chronologically so the Coverage Growth Curve makes sense
        self.single_runs.sort(key=lambda x: x['timestamp'])

        # Discover differential analyses from their stored diff.json files
        self.diff_runs = []
        for d_json in self.root.glob("diffs/*/diff.json"):
            with open(d_json) as f:
                d = json.load(f)
            self.diff_runs.append({
                "name": d['name'],
                "a": d['a'],
                "b": d['b'],
                "data": d['data'],
                "abs_delta": d.get('total_abs_delta', 0),
                "rel_delta": d.get('total_rel_delta', 0),
                "a_per": d.get('a_per', 0),
                "b_per": d.get('b_per', 0),
                "report": str((d_json.parent / "diff_summary.html").relative_to(self.root)),
            })

    # ------------------------------------------------------------------
    # Single-run pipeline
    # ------------------------------------------------------------------

    def run_single(self, name, corpus_dir, force=False):
        """
        Full pipeline for a single corpus: execute → extract JSON → render.

        The coverage.json is reused from a previous run if it exists and
        force=False, skipping the slow trace-execution step.

        Args:
            name:       Label for the report (used as directory name under runs/).
            corpus_dir: Path to the corpus directory.
            force:      If True, re-execute traces and overwrite the cached JSON.
        """
        out_dir = self.root / "runs" / name
        out_dir.mkdir(parents=True, exist_ok=True)
        json_path = out_dir / "coverage.json"

        if not force and json_path.exists():
            print(f"  Reusing existing coverage data from {json_path}")
            with open(json_path) as f:
                data = json.load(f)
        else:
            self.engine.clean_gcda()
            self.engine.execute_corpus(corpus_dir)
            data = self.engine.extract_json(json_path)

        self.save_report(name, data, out_dir, corpus_dir, force=force)

    # ------------------------------------------------------------------
    # Differential analysis pipeline
    # ------------------------------------------------------------------

    def run_diff(self, name, dir_a, dir_b, force=False):
        """
        Full pipeline for a differential analysis: run A + B, diff, render.

        Steps:
          1. Execute and extract JSON for corpus A (into corpus_a.json).
          2. Execute and extract JSON for corpus B (into corpus_b.json).
          3. Save individual reports for both (report_a/, report_b/).
          4. Compute per-file branch coverage deltas.
          5. Render per-file diff views (line-level colour diff + minimap).
          6. Persist diff.json (reused by generate_master_dashboard).
          7. Append to self.diff_runs (picked up when hub is regenerated).

        Only files where |abs_delta| > 0.01% are included in the diff table
        to avoid noise from floating-point rounding.

        Args:
            name:   Label for the diff report.
            dir_a:  Path to corpus A (baseline).
            dir_b:  Path to corpus B (target/comparison).
            force:  If True, re-execute and overwrite cached JSON for both corpora.
        """
        out_dir = self.root / "diffs" / name
        out_dir.mkdir(parents=True, exist_ok=True)

        # --- Execute A and B ---
        res = []
        for d, suffix in [(dir_a, "a"), (dir_b, "b")]:
            json_path = out_dir / f"corpus_{suffix}.json"
            if not force and json_path.exists():
                print(f"  Reusing existing data for corpus {suffix} from {json_path}")
                with open(json_path) as f:
                    j = json.load(f)
            else:
                self.engine.clean_gcda()
                self.engine.execute_corpus(d)
                j = self.engine.extract_json(json_path)

            # Also render a full individual report for each sub-corpus
            self.save_report(
                f"{name}_{suffix.upper()}", j,
                out_dir / f"report_{suffix}", d, force=force
            )
            res.append(j)

        # --- Compute per-file deltas ---
        ja, jb = res
        files_a = {f['file']: f for f in ja['files']}
        files_b = {f['file']: f for f in jb['files']}

        diff_data = []
        file_diffs = out_dir / "files"
        file_diffs.mkdir(exist_ok=True)

        for fname in sorted(set(files_a.keys()) | set(files_b.keys())):
            fa = files_a.get(fname, {})
            fb = files_b.get(fname, {})
            sa = self.engine.calculate_file_stats(fa)
            sb = self.engine.calculate_file_stats(fb)

            delta = sb['b_per'] - sa['b_per']
            if abs(delta) <= 0.01:
                continue  # Skip negligible differences (floating-point noise)

            # Relative delta: how much did coverage grow relative to the baseline?
            # Displayed as +∞ when the baseline was 0% (any new coverage = infinite growth).
            if sa['b_per'] > 0:
                rel_delta = (sb['b_per'] - sa['b_per']) / sa['b_per'] * 100
            else:
                rel_delta = float('inf') if sb['b_per'] > 0 else 0.0

            # Render the line-by-line diff view for this file
            safe_name = fname.replace('/', '_').replace('.', '_') + ".html"
            html = UIComponents.generate_file_view(fname, fa, fb, base_rel="../..")
            with open(file_diffs / safe_name, 'w') as f:
                f.write(html)

            diff_data.append({
                "file": fname,
                "abs_delta": delta,
                "rel_delta": rel_delta,
                "from": sa['b_per'],
                "to": sb['b_per'],
                "link": "files/" + safe_name,
            })

        # --- Overall corpus-level coverage percentages ---
        total_a_cov, total_a_branches = 0, 0
        total_b_cov, total_b_branches = 0, 0
        for f_entry in ja['files']:
            s = self.engine.calculate_file_stats(f_entry)
            total_a_cov += s['b_cov']
            total_a_branches += s['b_total']
        for f_entry in jb['files']:
            s = self.engine.calculate_file_stats(f_entry)
            total_b_cov += s['b_cov']
            total_b_branches += s['b_total']

        a_per = (total_a_cov / total_a_branches * 100) if total_a_branches > 0 else 0
        b_per = (total_b_cov / total_b_branches * 100) if total_b_branches > 0 else 0
        total_abs_delta = b_per - a_per
        total_rel_delta = (
            (b_per - a_per) / a_per * 100
            if a_per > 0
            else (float('inf') if b_per > 0 else 0.0)
        )

        # Persist diff data so the hub can regenerate diff_summary.html without
        # re-running the coverage engine.
        with open(out_dir / "diff.json", "w") as f:
            json.dump({
                "name": name, "a": dir_a, "b": dir_b,
                "data": diff_data,
                "total_abs_delta": total_abs_delta,
                "total_rel_delta": total_rel_delta,
                "a_per": a_per, "b_per": b_per,
            }, f)

        self.diff_runs.append({
            "name": name, "a": dir_a, "b": dir_b,
            "data": diff_data,
            "abs_delta": total_abs_delta,
            "rel_delta": total_rel_delta,
            "report": "diffs/" + name + "/diff_summary.html",
        })

    # ------------------------------------------------------------------
    # Master dashboard
    # ------------------------------------------------------------------

    def generate_master_dashboard(self):
        """
        Generate (or regenerate) the master hub index.html.

        Calls discover_runs() to rebuild the run/diff lists from the filesystem,
        then renders:
          - A Coverage Growth Curve (Chart.js line chart over single runs).
          - An Individual Campaigns table (sortable, with view/remove buttons).
          - A Differential Analysis table (sortable, with view delta/remove).
          - The "Compute Cov" modal for launching new jobs from the browser.

        This method is also called automatically after every delete operation
        from the server so the hub stays consistent with the filesystem.
        """
        self.discover_runs()
        labels = [r['name'] for r in self.single_runs]
        data = [round(r['coverage'], 2) for r in self.single_runs]

        # Add 10 pp of headroom above the highest value, capped at 100%
        max_val = max(data) if data else 0
        y_max = min(100, max_val + 10)

        chart_js = f"""
            const ctx = document.getElementById('growthChart').getContext('2d');
            new Chart(ctx, {{
                type: 'line',
                data: {{ labels: {json.dumps(labels)}, datasets: [{{
                    label: 'Ground-Truth Branch Coverage (GCOV) %',
                    data: {json.dumps(data)},
                    borderColor: '#007bff',
                    backgroundColor: 'rgba(0, 123, 255, 0.1)',
                    fill: true, tension: 0.1
                }}] }},
                options: {{
                    responsive: true, maintainAspectRatio: false,
                    scales: {{ y: {{ beginAtZero: true, max: {y_max} }} }}
                }}
            }});"""

        # Extra <head> content: Chart.js, modal CSS, and all interactive JS
        head = """<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
        /* Modal overlay for the Compute Cov dialog */
        .modal { display: none; position: fixed; z-index: 2000; left: 0; top: 0;
                 width: 100%; height: 100%; overflow: auto; background-color: rgba(0,0,0,0.5); }
        .modal-content { background-color: #fefefe; margin: 10% auto; padding: 20px;
                         border: 1px solid #888; width: 50%; border-radius: 8px;
                         font-family: sans-serif; box-sizing: border-box; }
        .close { color: #aaa; float: right; font-size: 28px; font-weight: bold; cursor: pointer; }
        .close:hover { color: black; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: bold; }
        .form-group input, .form-group select { width: 100%; padding: 8px;
            box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; }
        .form-group input[type="checkbox"] { width: auto; }
        </style>
        <script>
        // --- Remove report ---
        // Calls POST /api/delete (requires puffin_server.py, not plain http.server).
        function deleteReport(targetPath, protocol) {
            if (confirm("Are you sure you want to completely remove this report and its data folder?")) {
                fetch('/api/delete', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target: targetPath, protocol: protocol })
                }).then(res => res.json()).then(data => {
                    if (data.success) { location.reload(); }
                    else { alert("Failed to delete. Make sure you are running tools/puffin_server.py instead of http.server"); }
                }).catch(err => {
                    alert("Error: Server does not support deletion. Please restart with: python3 tools/puffin_server.py 8890");
                });
            }
        }

        // --- Compute Cov modal ---
        function openComputeModal()  { document.getElementById('computeModal').style.display = 'block'; }
        function closeComputeModal() { document.getElementById('computeModal').style.display = 'none'; }

        // Show/hide Path B field depending on whether diff mode is selected
        function toggleDiff() {
            const mode = document.getElementById('computeMode').value;
            document.getElementById('pathBGroup').style.display = (mode === 'diff') ? 'block' : 'none';
            document.getElementById('pathB').required = (mode === 'diff');
        }

        // Submit the compute form → POST /api/compute → background nix-shell job
        function submitCompute(event) {
            event.preventDefault();
            const payload = {
                protocol:     document.getElementById('computeProtocol').value,
                mode:         document.getElementById('computeMode').value,
                path_a:       document.getElementById('pathA').value,
                path_b:       document.getElementById('pathB').value,
                name:         document.getElementById('computeName').value,
                put_override: document.getElementById('computePut').value,
                force:        document.getElementById('computeForce').checked
            };
            fetch('/api/compute', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            }).then(res => res.json()).then(data => {
                if (data.success) { alert(data.message); closeComputeModal(); }
                else { alert("Error: " + data.error); }
            }).catch(err => alert("Failed. Are you running puffin_server.py?"));
        }
        </script>"""

        # --- Hub page content ---
        content = f"""<div style="display:flex; justify-content:space-between; align-items:center;">
            <h1>Puffin Coverage Master Hub ({self.protocol.upper()})</h1>
            <button class="nav-btn"
                    style="background:#28a745; font-size:16px; padding:10px 20px;
                           color:white; border:none; border-radius:4px; cursor:pointer;"
                    onclick="openComputeModal()">+ Compute Cov</button>
        </div>

        <!-- Compute Cov modal dialog -->
        <div id="computeModal" class="modal">
          <div class="modal-content">
            <span class="close" onclick="closeComputeModal()">&times;</span>
            <h2>Compute New Coverage</h2>
            <form onsubmit="submitCompute(event)">
              <!-- Protocol is pre-filled from the hub context (tls or opcua) -->
              <input type="hidden" id="computeProtocol" value="{self.protocol}">
              <div class="form-group">
                <label>Mode</label>
                <select id="computeMode" onchange="toggleDiff()">
                  <option value="run">Individual Run (Single Path)</option>
                  <option value="diff">Differential Analysis (Path A vs Path B)</option>
                </select>
              </div>
              <div class="form-group">
                <label>Path (or Path A) [Absolute path on server]</label>
                <input type="text" id="pathA" required placeholder="/absolute/path/to/corpus">
              </div>
              <div class="form-group" id="pathBGroup" style="display:none;">
                <label>Path B [Absolute path on server]</label>
                <input type="text" id="pathB" placeholder="/absolute/path/to/target/corpus">
              </div>
              <div class="form-group">
                <label>Name (Optional)</label>
                <input type="text" id="computeName" placeholder="my_experiment">
              </div>
              <div class="form-group">
                <label>PUT Override (Optional — leave blank for default)</label>
                <input type="text" id="computePut"
                       placeholder="e.g. openssl340-gcov or open62541">
              </div>
              <div class="form-group">
                <label><input type="checkbox" id="computeForce">
                  Force completely fresh run (ignore caches)</label>
              </div>
              <button type="submit"
                      style="background:#28a745; color:white; padding:10px 15px;
                             border:none; border-radius:4px; cursor:pointer; font-size:14px;">
                Launch Compute
              </button>
            </form>
          </div>
        </div>

        <div class="card"><h2>Coverage Growth Curve</h2>
            <div class="chart-container"><canvas id="growthChart"></canvas></div>
        </div>
        <script>{chart_js}</script>

        <div class="card"><h2>Individual Campaigns</h2>
        <table><thead><tr>
            <th>Name</th><th>Coverage</th><th>Path</th><th>Action</th>
        </tr></thead><tbody>"""

        for r in self.single_runs:
            target_dir = str(self.root / Path(r['report']).parent)
            content += (
                f"<tr><td>{r['name']}</td>"
                f"<td><b>{r['coverage']:.2f}%</b></td>"
                f"<td><small>{r['path']}</small></td>"
                f"<td>"
                f"<a href='{r['report']}' class='nav-btn' style='text-decoration:none;'>view</a> "
                f"<button class='nav-btn' style='background:#dc3545; margin-left:5px;' "
                f"onclick=\"deleteReport('{target_dir}', '{self.protocol}')\">remove</button>"
                f"</td></tr>"
            )

        content += (
            "</tbody></table></div>"
            '<div class="card"><h2>Differential Analysis</h2>'
            '<table><thead><tr>'
            '<th>Name</th><th>A &rarr; B</th>'
            '<th class="sortable">Abs Delta</th>'
            '<th class="sortable">Rel Delta</th>'
            '<th class="sortable">Coverage Transition</th>'
            '<th>Action</th>'
            '</tr></thead><tbody>'
        )

        for d in self.diff_runs:
            # Write the diff_summary.html for this diff (reuses cached diff.json data)
            summary_path = self.root / d['report']
            summary_path.parent.mkdir(parents=True, exist_ok=True)
            self._write_diff_summary(d, summary_path)

            cls_abs = "pos" if d['abs_delta'] > 0 else ("neg" if d['abs_delta'] < 0 else "")
            cls_rel = "pos" if d['rel_delta'] > 0 else ("neg" if d['rel_delta'] < 0 else "")
            rel_str = "+&infin;" if d['rel_delta'] == float('inf') else f"{d['rel_delta']:+.2f}%"
            target_dir = str(self.root / Path(d['report']).parent)
            content += f"""<tr>
                <td>{d['name']}</td>
                <td><small>{d['a']} &rarr; {d['b']}</small></td>
                <td class='{cls_abs}'>{d['abs_delta']:+.2f}%</td>
                <td class='{cls_rel}'>{rel_str}</td>
                <td>{d.get('a_per', 0.0):.2f}% &rarr; {d.get('b_per', 0.0):.2f}%</td>
                <td>
                    <a href='{d['report']}' class='nav-btn' style='text-decoration:none;'>view delta</a>
                    <button class='nav-btn' style='background:#dc3545; margin-left:5px;'
                            onclick="deleteReport('{target_dir}', '{self.protocol}')">remove</button>
                </td>
            </tr>"""

        content += "</tbody></table></div>"

        with open(self.root / "index.html", "w") as f:
            f.write(UIComponents.page_wrapper("Puffin Hub", content, head))

    # ------------------------------------------------------------------
    # Diff summary page
    # ------------------------------------------------------------------

    def _write_diff_summary(self, d, path):
        """
        Render the diff_summary.html page for one differential analysis.

        The page shows:
          - A sticky header with corpus A/B metadata (paths, traces, README, Path button)
            and the overall branch coverage transition (X% → Y%) + Abs/Rel deltas.
          - A sortable table of files with per-file Abs Delta, Rel Delta, and
            GCOV Transition (from% → to%), linked to the per-file diff view.
          - A legend explaining the metric definitions.

        Rows are sorted by |abs_delta| descending so the most impactful files
        appear at the top by default.

        Args:
            d:    Diff dict with keys: name, a, b, data, abs_delta, rel_delta,
                  a_per, b_per (as stored in diff.json / self.diff_runs).
            path: Destination path for the HTML file.
        """
        # Build the per-file table rows (sorted by absolute impact)
        rows = ""
        for f in sorted(d['data'], key=lambda x: abs(x['abs_delta']), reverse=True):
            cls_abs = "pos" if f['abs_delta'] > 0 else ("neg" if f['abs_delta'] < 0 else "")
            cls_rel = "pos" if f['rel_delta'] > 0 else ("neg" if f['rel_delta'] < 0 else "")
            rel_str = "+&infin;" if f['rel_delta'] == float('inf') else f"{f['rel_delta']:+.2f}%"
            rows += f"""<tr>
                <td><a href='{f['link']}'>{f['file']}</a></td>
                <td class='{cls_abs}'>{f['abs_delta']:+.2f}%</td>
                <td class='{cls_rel}'>{rel_str}</td>
                <td>{f['from']:.1f}% &rarr; {f['to']:.1f}%</td>
            </tr>"""

        # Overall delta classes and strings for the header
        cls_abs = "pos" if d['abs_delta'] > 0 else ("neg" if d['abs_delta'] < 0 else "")
        cls_rel = "pos" if d['rel_delta'] > 0 else ("neg" if d['rel_delta'] < 0 else "")
        rel_str_total = (
            "+&infin;" if d['rel_delta'] == float('inf')
            else f"{d['rel_delta']:+.2f}%"
        )

        # Fetch corpus metadata (trace counts, duration, README, Path button)
        meta_a, readme_a = self.get_corpus_info(d['a'])
        meta_b, readme_b = self.get_corpus_info(d['b'])

        content = f"""<h1>Delta: {d['name']}</h1>
        <div class="header">
            <a href="../../index.html"
               style="position: relative; z-index: 1000; padding: 4px 8px;
                      background: #e0e0e0; border-radius: 4px; text-decoration: none;
                      color: black; font-weight: bold;">&larr; hub</a>
            <!-- Left: corpus A and B metadata rows -->
            <div style="display:flex; flex-direction:column; gap:8px;">
                <div style="display:flex; align-items:center; gap:10px;">
                    <b>A:</b> <span>{d['a']}</span> {meta_a}
                    {readme_a.replace('View README', 'View README (A)')}
                </div>
                <div style="display:flex; align-items:center; gap:10px;">
                    <b>B:</b> <span>{d['b']}</span> {meta_b}
                    {readme_b.replace('View README', 'View README (B)')}
                </div>
            </div>
            <!-- Right: overall coverage transition + delta summary (column layout
                 so height matches the two-row left column naturally) -->
            <div style="margin-left:auto; display:flex; flex-direction:column;
                        gap:6px; align-items:flex-end; font-size:13px; white-space:nowrap;">
                <span style="font-weight:bold;">
                    {d.get('a_per', 0.0):.1f}% &rarr;
                    <span class="{'pos' if d['abs_delta'] >= 0 else 'neg'}">{d.get('b_per', 0.0):.1f}%</span>
                    <span style="font-weight:normal; color:#888; margin-left:2px;">(branch)</span>
                </span>
                <span style="color:#555;">
                    Abs: <b class="{cls_abs}">{d['abs_delta']:+.2f}%</b>
                    &nbsp;&nbsp;Rel: <b class="{cls_rel}">{rel_str_total}</b>
                </span>
            </div>
        </div>
        <table>
            <thead>
                <tr>
                    <th class="sortable">File</th>
                    <th class="sortable">Absolute Delta</th>
                    <th class="sortable">Relative Delta (vs Baseline)</th>
                    <th class="sortable">GCOV Transition</th>
                </tr>
            </thead>
            <tbody>{rows}</tbody>
        </table>
        <div style="margin-top: 20px; font-size: 11px; color: #666; line-height: 1.6;">
            <b>Absolute Delta:</b> Change in branch coverage % (e.g. +1.0% = 1 pp more covered).<br>
            <b>Relative Delta:</b> Growth relative to baseline (e.g. +100% = coverage doubled).<br>
            <b>GCOV Transition:</b> Baseline (A) → Target (B) branch coverage for this file.
        </div>"""

        with open(path, "w") as f:
            f.write(UIComponents.page_wrapper(f"Delta: {d['name']}", content))


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description=(
            "Puffin Coverage Reporting System\n\n"
            "Measures ground-truth GCOV branch coverage for Puffin fuzzer corpora\n"
            "and renders interactive HTML reports in coverage-hub-<protocol>/.\n\n"
            "Always run from the project root.\n"
            "See tools/README_COVERAGE.md for full documentation."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "mode", choices=["run", "diff"],
        help="'run' = single corpus; 'diff' = compare two corpora"
    )
    parser.add_argument(
        "protocol", choices=["opcua", "tls"],
        help="Protocol fuzzer to use"
    )
    parser.add_argument(
        "dirs", nargs="+",
        help="Corpus path(s): one for 'run', two (A then B) for 'diff'"
    )
    parser.add_argument(
        "--put",
        help=(
            "PUT (Program Under Test) name for the gcov binary.\n"
            "Default: open62541 (opcua) / openssl340-gcov (tls).\n"
            "NOTE: for OPC UA use 'open62541', NOT 'open62541-gcov'."
        )
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Re-execute traces even if coverage.json already exists"
    )
    parser.add_argument(
        "--name",
        help="Human-readable label for the report (shown in the hub)"
    )

    args = parser.parse_args()

    # Validate argument counts
    if args.mode == "run" and len(args.dirs) != 1:
        parser.error("Mode 'run' requires exactly one corpus directory.")
    if args.mode == "diff" and len(args.dirs) != 2:
        parser.error("Mode 'diff' requires exactly two corpus directories.")

    reporter = PuffinReporter(
        args.protocol,
        f"./coverage-hub-{args.protocol}",
        vendor_override=args.put
    )

    if args.mode == "run":
        name = args.name or Path(args.dirs[0]).name or "run"
        reporter.run_single(name, args.dirs[0], force=args.force)

    elif args.mode == "diff":
        name = args.name or f"{Path(args.dirs[0]).name}_vs_{Path(args.dirs[1]).name}"
        reporter.run_diff(name, args.dirs[0], args.dirs[1], force=args.force)

    reporter.generate_master_dashboard()

    print(f"\n[SUCCESS] Reporting complete for protocol: {args.protocol}")
    print(f"Master Hub: {reporter.root}/index.html")
    print(f"\nTo view and interact with the reports, run:")
    print(f"  python3 tools/puffin_server.py 8890")
    print(f"Then navigate to:")
    print(f"  http://localhost:8890/coverage-hub-{args.protocol}/index.html")
