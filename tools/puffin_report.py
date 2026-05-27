#!/usr/bin/env python3
"""
puffin_report.py - Unified Puffin Coverage Reporting System
Handles: Single campaign analysis, Differential analysis, and Master Dashboard generation.
"""

import sys
import os
import json
from pathlib import Path
from puffin_coverage import PuffinEngine, UIComponents

class PuffinReporter:
    def __init__(self, protocol="opcua", output_root="./puffin-coverage-reports", vendor_override=None):
        self.protocol = protocol
        self.engine = PuffinEngine(protocol, vendor_override=vendor_override)
        self.root = Path(output_root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.single_runs = []
        self.diff_runs = []

    def save_report(self, name, json_data, out_dir, corpus_path, force=False):
        """Generates a campaign index and detailed gcovr HTML reports."""
        out_dir.mkdir(parents=True, exist_ok=True)

        # 1. Generate the standard gcovr HTML report (nicely rendered)
        self.engine.extract_html(out_dir / "gcov", force=force)

        # 2. Extract stats for metadata and hub
        t_b, c_b = 0, 0
        for f_entry in json_data['files']:
            stats = self.engine.calculate_file_stats(f_entry)
            t_b += stats['b_total']
            c_b += stats['b_cov']

        b_per = (c_b / t_b * 100) if t_b > 0 else 0

        metadata = {
            "name": name, "corpus_path": str(corpus_path),
            "total_branch_coverage": b_per, "timestamp": os.path.getmtime(out_dir)
        }
        with open(out_dir / "metadata.json", "w") as f: json.dump(metadata, f)

        # 3. Generate a simplified hub-friendly index that redirects/links to gcov
        content = f"""<h1>Campaign: {name}</h1>
        <div class="header">
            <a href="../../index.html">&larr; hub</a> <span>{corpus_path}</span>
            <span class="pos" style="margin-left:20px;">Ground-Truth (GCOV) Branch Coverage: {b_per:.2f}%</span>
        </div>
        <div class="card">
            <h2>Detailed Coverage Report</h2>
            <p>The high-fidelity GCOV report is available here:</p>
            <a href="gcov/index.html" style="font-size: 1.2em; font-weight: bold;">View Detailed GCOV HTML Report</a>
        </div>"""
        with open(out_dir / "index.html", "w") as f: f.write(UIComponents.page_wrapper(name, content))

    def discover_runs(self):
        """Reconstructs single and diff run lists from the filesystem."""
        self.single_runs = []
        for meta_path in self.root.glob("**/metadata.json"):
            with open(meta_path) as f: m = json.load(f)
            self.single_runs.append({
                "name": m['name'], "path": m['corpus_path'], "coverage": m['total_branch_coverage'],
                "timestamp": m['timestamp'], "report": str((meta_path.parent / "index.html").relative_to(self.root))
            })
        self.single_runs.sort(key=lambda x: x['timestamp'])

        self.diff_runs = []
        for d_json in self.root.glob("diffs/*/diff.json"):
            with open(d_json) as f: d = json.load(f)
            self.diff_runs.append({
                "name": d['name'], "a": d['a'], "b": d['b'], "data": d['data'],
                "abs_delta": d.get('total_abs_delta', 0), "rel_delta": d.get('total_rel_delta', 0),
                "report": str((d_json.parent / "diff_summary.html").relative_to(self.root))
            })

    def run_single(self, name, corpus_dir, force=False):
        out_dir = self.root / "runs" / name
        out_dir.mkdir(parents=True, exist_ok=True)
        json_path = out_dir / "coverage.json"
        
        if not force and json_path.exists():
            print(f"  Reusing existing coverage data from {json_path}")
            with open(json_path) as f: data = json.load(f)
        else:
            self.engine.clean_gcda()
            self.engine.execute_corpus(corpus_dir)
            data = self.engine.extract_json(json_path)
            
        self.save_report(name, data, out_dir, corpus_dir, force=force)

    def run_diff(self, name, dir_a, dir_b, force=False):
        out_dir = self.root / "diffs" / name
        out_dir.mkdir(parents=True, exist_ok=True)
        
        # Execute A and B
        res = []
        for d, suffix in [(dir_a, "a"), (dir_b, "b")]:
            json_path = out_dir / f"corpus_{suffix}.json"
            if not force and json_path.exists():
                print(f"  Reusing existing data for corpus {suffix} from {json_path}")
                with open(json_path) as f: j = json.load(f)
            else:
                self.engine.clean_gcda()
                self.engine.execute_corpus(d)
                j = self.engine.extract_json(json_path)
            
            self.save_report(f"{name}_{suffix.upper()}", j, out_dir / f"report_{suffix}", d, force=force)
            res.append(j)
        
        # Diff Logic
        ja, jb = res
        files_a = {f['file']: f for f in ja['files']}
        files_b = {f['file']: f for f in jb['files']}
        
        diff_data = []
        file_diffs = out_dir / "files"
        file_diffs.mkdir(exist_ok=True)
        
        for fname in sorted(set(files_a.keys()) | set(files_b.keys())):
            fa, fb = files_a.get(fname, {}), files_b.get(fname, {})
            sa, sb = self.engine.calculate_file_stats(fa), self.engine.calculate_file_stats(fb)
            
            delta = sb['b_per'] - sa['b_per']
            if abs(delta) > 0.01:
                # Calculate relative delta: (New - Old) / Old
                if sa['b_per'] > 0:
                    rel_delta = (sb['b_per'] - sa['b_per']) / sa['b_per'] * 100
                else:
                    rel_delta = 100.0 if sb['b_per'] > 0 else 0.0
                
                safe_name = fname.replace('/', '_').replace('.', '_') + ".html"
                html = UIComponents.generate_file_view(fname, fa.get('lines', []), fb.get('lines', []))
                with open(file_diffs / safe_name, 'w') as f: f.write(html)
                diff_data.append({
                    "file": fname, 
                    "abs_delta": delta, 
                    "rel_delta": rel_delta,
                    "from": sa['b_per'], 
                    "to": sb['b_per'], 
                    "link": "files/" + safe_name
                })
        
        # Calculate overall corpus deltas
        total_a_cov, total_a_branches = 0, 0
        total_b_cov, total_b_branches = 0, 0
        for f_entry in ja['files']:
            s = self.engine.calculate_file_stats(f_entry)
            total_a_cov += s['b_cov']; total_a_branches += s['b_total']
        for f_entry in jb['files']:
            s = self.engine.calculate_file_stats(f_entry)
            total_b_cov += s['b_cov']; total_b_branches += s['b_total']
            
        a_per = (total_a_cov / total_a_branches * 100) if total_a_branches > 0 else 0
        b_per = (total_b_cov / total_b_branches * 100) if total_b_branches > 0 else 0
        total_abs_delta = b_per - a_per
        total_rel_delta = (b_per - a_per) / a_per * 100 if a_per > 0 else (100 if b_per > 0 else 0)

        with open(out_dir / "diff.json", "w") as f:
            json.dump({
                "name": name, "a": dir_a, "b": dir_b, "data": diff_data,
                "total_abs_delta": total_abs_delta, "total_rel_delta": total_rel_delta,
                "a_per": a_per, "b_per": b_per
            }, f)

        self.diff_runs.append({
            "name": name, "a": dir_a, "b": dir_b, "data": diff_data,
            "abs_delta": total_abs_delta, "rel_delta": total_rel_delta,
            "report": "diffs/" + name + "/diff_summary.html"
        })

    def generate_master_dashboard(self):
        self.discover_runs()
        labels = [r['name'] for r in self.single_runs]
        data = [round(r['coverage'], 2) for r in self.single_runs]
        
        chart_js = f"""
            const ctx = document.getElementById('growthChart').getContext('2d');
            new Chart(ctx, {{
                type: 'line',
                data: {{ labels: {json.dumps(labels)}, datasets: [{{
                    label: 'Ground-Truth Branch Coverage (GCOV) %', data: {json.dumps(data)},
                    borderColor: '#007bff', backgroundColor: 'rgba(0, 123, 255, 0.1)', fill: true, tension: 0.1
                }}] }},
                options: {{ responsive: true, maintainAspectRatio: false, scales: {{ y: {{ beginAtZero: true, max: 100 }} }} }}
            }});"""

        content = f"""<h1>Puffin Coverage Master Hub ({self.protocol.upper()})</h1>
        <div class="card"><h2>Coverage Growth Curve</h2><div class="chart-container"><canvas id="growthChart"></canvas></div></div>
        <script>{chart_js}</script>
        <div class="card"><h2>Individual Campaigns</h2><table><thead><tr><th>Name</th><th>Coverage</th><th>Path</th><th>Action</th></tr></thead><tbody>"""
        for r in self.single_runs:
            content += f"<tr><td>{r['name']}</td><td><b>{r['coverage']:.2f}%</b></td><td><small>{r['path']}</small></td><td><a href='{r['report']}'>view</a></td></tr>"
        
        content += "</tbody></table></div><div class=\"card\"><h2>Differential Analysis</h2><table><thead><tr><th>Name</th><th>A &rarr; B</th><th>Abs Delta</th><th>Rel Delta</th><th>Action</th></tr></thead><tbody>"
        for d in self.diff_runs:
            summary_path = self.root / d['report']
            summary_path.parent.mkdir(parents=True, exist_ok=True)
            self._write_diff_summary(d, summary_path)
            cls_abs = "pos" if d['abs_delta'] > 0 else ("neg" if d['abs_delta'] < 0 else "")
            cls_rel = "pos" if d['rel_delta'] > 0 else ("neg" if d['rel_delta'] < 0 else "")
            content += f"""<tr>
                <td>{d['name']}</td>
                <td><small>{d['a']} &rarr; {d['b']}</small></td>
                <td class='{cls_abs}'>{d['abs_delta']:+.2f}%</td>
                <td class='{cls_rel}'>{d['rel_delta']:+.2f}%</td>
                <td><a href='{d['report']}'>view delta</a></td>
            </tr>"""
        
        content += "</tbody></table></div>"
        head = '<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>'
        with open(self.root / "index.html", "w") as f: f.write(UIComponents.page_wrapper("Puffin Hub", content, head))

    def _write_diff_summary(self, d, path):
        rows = ""
        for f in sorted(d['data'], key=lambda x: abs(x['abs_delta']), reverse=True):
            cls_abs = "pos" if f['abs_delta'] > 0 else ("neg" if f['abs_delta'] < 0 else "")
            cls_rel = "pos" if f['rel_delta'] > 0 else ("neg" if f['rel_delta'] < 0 else "")
            rows += f"""<tr>
                <td><a href='{f['link']}'>{f['file']}</a></td>
                <td class='{cls_abs}'>{f['abs_delta']:+.2f}%</td>
                <td class='{cls_rel}'>{f['rel_delta']:+.2f}%</td>
                <td>{f['from']:.1f}% &rarr; {f['to']:.1f}%</td>
            </tr>"""
        
        cls_abs = "pos" if d['abs_delta'] > 0 else ("neg" if d['abs_delta'] < 0 else "")
        cls_rel = "pos" if d['rel_delta'] > 0 else ("neg" if d['rel_delta'] < 0 else "")

        content = f"""<h1>Delta: {d['name']}</h1>
        <div class="header">
            <a href="../../index.html">&larr; hub</a> 
            <span>{d['a']} &rarr; {d['b']}</span>
            <div style="margin-left:auto; display:flex; gap:20px;">
                <span>Total Abs Delta: <b class="{cls_abs}">{d['abs_delta']:+.2f}%</b></span>
                <span>Total Rel Delta: <b class="{cls_rel}">{d['rel_delta']:+.2f}%</b></span>
            </div>
        </div>
        <table>
            <thead>
                <tr>
                    <th>File</th>
                    <th>Absolute Delta</th>
                    <th>Relative Delta (vs Baseline)</th>
                    <th>GCOV Transition</th>
                </tr>
            </thead>
            <tbody>{rows}</tbody>
        </table>
        <div style="margin-top: 20px; font-size: 11px; color: #666; line-height: 1.6;">
            <b>Absolute Delta:</b> The change in total branch coverage percentage (e.g., +1.0% means 1% more of the entire file is covered).<br>
            <b>Relative Delta:</b> The growth or reduction relative to the baseline coverage (e.g., +100% means coverage doubled).<br>
            <b>GCOV Transition:</b> The actual coverage shift from the baseline (Corpus A) to the target (Corpus B).
        </div>"""
        with open(path, "w") as f: f.write(UIComponents.page_wrapper(f"Delta: {d['name']}", content))

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Puffin Coverage Reporting System")
    parser.add_argument("mode", choices=["run", "diff"], help="Reporting mode")
    parser.add_argument("protocol", choices=["opcua", "tls"], help="Protocol to analyze")
    parser.add_argument("dirs", nargs="+", help="Corpus directories (1 for run, 2 for diff)")
    parser.add_argument("--put", help="Override the PUT name (e.g., openssl340_gcov)")
    parser.add_argument("--force", action="store_true", help="Force re-execution even if JSON exists")
    
    args = parser.parse_args()
    
    if args.mode == "run" and len(args.dirs) != 1:
        parser.error("Mode 'run' requires exactly one corpus directory.")
    if args.mode == "diff" and len(args.dirs) != 2:
        parser.error("Mode 'diff' requires exactly two corpus directories.")
        
    reporter = PuffinReporter(args.protocol, f"./coverage-hub-{args.protocol}", vendor_override=args.put)

    if args.mode == "run":
        reporter.run_single(Path(args.dirs[0]).name or "run", args.dirs[0], force=args.force)
    elif args.mode == "diff":
        name = f"{Path(args.dirs[0]).name}_vs_{Path(args.dirs[1]).name}"
        reporter.run_diff(name, args.dirs[0], args.dirs[1], force=args.force)
    
    reporter.generate_master_dashboard()

    print(f"\n[SUCCESS] Reporting complete for protocol: {args.protocol}")
    print(f"Master Hub: {reporter.root}/index.html")
    print(f"\nTo view the interactive reports, run:")
    print(f"  python3 -m http.server 8890")
    print(f"Then navigate to:")
    print(f"  http://localhost:8890/{reporter.root}/index.html")
