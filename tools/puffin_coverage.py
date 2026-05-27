#!/usr/bin/env python3
"""
puffin_coverage.py - Core Engine for Puffin Coverage Analysis
Shared logic for execution, extraction, and UI generation.
"""

import os
import subprocess
import json
import csv
import glob
from pathlib import Path
import html as html_lib

# --- PROTOCOL PRESETS ---
PROTOCOLS = {
    "opcua": {
        "vendor": "open62541",
        "binary": "./target/release/opcuapuffin",
        "excludes": [".*tests.*", ".*examples.*", ".*doc.*", ".*deps.*", ".*tools.*", ".*/puffin/.*", ".*/opcuapuffin/.*", ".*/crates/.*"]
    },
    "tls": {
        "vendor": "openssl340-gcov",
        "binary": "./target/release/tlspuffin",
        "excludes": [".*wolf.*", ".*test.*", ".*apps.*", ".*include.*", ".*engine.*", ".*fuzz.*", ".*/puffin/.*", ".*/tlspuffin/.*", ".*/crates/.*"]
    }
}

class PuffinEngine:
    def __init__(self, protocol_name="opcua", vendor_override=None):
        if protocol_name not in PROTOCOLS:
            raise ValueError(f"Unknown protocol: {protocol_name}. Choose from {list(PROTOCOLS.keys())}")
        self.protocol_name = protocol_name
        self.config = PROTOCOLS[protocol_name].copy()
        if vendor_override:
            self.config["vendor"] = vendor_override
        self.config["gcov_exe"] = "llvm-cov gcov"
        
        # Setup temporary directory for coverage artifacts
        self.temp_dir = Path("tmp/coverage")
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        # Use relative paths for better gcovr compatibility
        self.project_root = Path(".")

    def run_cmd(self, cmd, check=True, env=None, cwd=None):
        """Standardized command execution within the nix-shell."""
        my_env = os.environ.copy()
        if env: my_env.update(env)
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, env=my_env, cwd=cwd)
        if check and res.returncode != 0:
            print(f"Error running: {cmd}\nExit Code: {res.returncode}\n{res.stderr}")
            res.check_returncode()
        return res

    def clean_gcda(self):
        """Removes old coverage data to ensure a fresh measurement."""
        print("  Cleaning old coverage data...")
        self.run_cmd("find . -name '*.gcda' -delete")

    def execute_corpus(self, corpus_dir, index=0, count=1000000):
        """Runs the binary on a subset of the corpus."""
        log_file = self.temp_dir / f"fuzzer_exec_{index}.log"
        print(f"  Executing {corpus_dir} [idx:{index}, count:{count}] using PUT '{self.config['vendor']}'...")
        print(f"  Log: {log_file}")
        # Binaries are relative to project root
        cmd = f"{self.config['binary']} --put {self.config['vendor']} execute --index {index} -n {count} {corpus_dir} > {log_file} 2>&1"
        self.run_cmd(cmd)

    def extract_json(self, output_path):
        """Uses gcovr to produce a machine-readable JSON coverage report."""
        output_path = Path(output_path).absolute()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        print(f"  Extracting JSON coverage to {output_path}...")
        exclude_args = " ".join([f'-e "{x}"' for x in self.config['excludes']])
        
        # Run gcovr from the project root. Added ignore flags for stability.
        cmd = f'gcovr -r "{self.project_root}" "{self.project_root}" --gcov-executable "{self.config["gcov_exe"]}" {exclude_args} --gcov-ignore-parse-errors --json "{output_path}"'
        self.run_cmd(cmd)
        
        with open(output_path) as f:
            return json.load(f)

    def extract_html(self, output_dir, force=False):
        """Uses gcovr to produce detailed HTML reports."""
        output_dir = Path(output_dir).absolute()
        index_file = output_dir / "index.html"
        
        if not force and index_file.exists():
            print(f"  Reusing existing HTML coverage report at {index_file}")
            return

        output_dir.mkdir(parents=True, exist_ok=True)
        print(f"  Extracting HTML coverage to {index_file}...")
        exclude_args = " ".join([f'-e "{x}"' for x in self.config['excludes']])
        
        # Run gcovr from the project root. Added ignore flags and -j 1 for stability.
        cmd = f'gcovr -j 1 -r "{self.project_root}" "{self.project_root}" --gcov-executable "{self.config["gcov_exe"]}" {exclude_args} --gcov-ignore-parse-errors --html-details --html-self-contained -o "{index_file}"'
        try:
            self.run_cmd(cmd)
        except Exception as e:
            print(f"  Warning: Detailed HTML report generation failed: {e}")
            print(f"  The Hub and JSON data will still be available.")

    def extract_summary(self):
        """Uses gcovr to produce a JSON summary and returns the total branch coverage %."""
        exclude_args = " ".join([f'-e "{x}"' for x in self.config['excludes']])
        cmd = f'gcovr -r "{self.project_root}" "{self.project_root}" --gcov-executable "{self.config["gcov_exe"]}" {exclude_args} --json-summary-pretty'
        res = self.run_cmd(cmd)
        try:
            data = json.loads(res.stdout)
            return data.get('branch_percent', 0.0)
        except:
            return 0.0

    @staticmethod
    def calculate_file_stats(file_entry):
        """Aggregates line and branch stats from a gcovr file entry."""
        lines = file_entry.get('lines', [])
        l_total = len([l for l in lines if not l.get('gcovr/noncode', False)])
        l_cov = len([l for l in lines if l.get('count', 0) > 0 and not l.get('gcovr/noncode', False)])
        
        branch_total = 0
        branch_covered = 0
        for l in lines:
            branches = l.get('branches', [])
            branch_total += len(branches)
            branch_covered += len([b for b in branches if b.get('count', 0) > 0])
            
        return {
            'l_per': (l_cov/l_total*100) if l_total > 0 else 0,
            'b_per': (branch_covered/branch_total*100) if branch_total > 0 else 0,
            'b_total': branch_total,
            'b_cov': branch_covered,
            'lines': lines
        }

class UIComponents:
    """Shared HTML/CSS components for consistent reporting."""
    
    @staticmethod
    def get_common_css():
        return """
            body { font-family: sans-serif; background: #f8f9fa; margin: 0; }
            .header { position: sticky; top: 0; background: white; padding: 10px 20px; border-bottom: 1px solid #ddd; z-index: 50; display: flex; align-items: center; gap: 20px; font-size: 13px; }
            .pos { color: #1a7f37; font-weight: bold; }
            .neg { color: #cf222e; font-weight: bold; }
            table { border-collapse: collapse; width: 100%; background: white; font-size: 12px; }
            th, td { padding: 10px; text-align: left; border-bottom: 1px solid #eee; }
            th { background: #f1f3f5; }
            .code-view { font-family: monospace; white-space: pre; padding: 0; margin-right: 30px; }
            .line-container { display: flex; scroll-margin-top: 60px; }
            .line-num { width: 50px; text-align: right; padding-right: 10px; color: #999; border-right: 1px solid #ddd; margin-right: 10px; }
            .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); margin-bottom: 30px; }
            h2 { border-bottom: 2px solid #007bff; padding-bottom: 5px; }
            .chart-container { height: 300px; margin-bottom: 40px; }
            .minimap { position: fixed; right: 0; top: 0; width: 25px; height: 100vh; cursor: crosshair; }
            .main-content { padding-right: 30px; }
            .line-container.cov-both { background-color: #e6ffed; }
            .line-container.cov-none { background-color: #ffeef0; }
            .line-container.cov-new  { background-color: #2ea44f; color: white; }
            .line-container.cov-lost { background-color: #cf222e; color: white; }
            .nav-btn { background: #007bff; color: white; border: none; padding: 4px 12px; border-radius: 4px; cursor: pointer; font-size: 12px; font-weight: bold; }
            .nav-btn:hover { background: #0056b3; }
            .nav-btn:disabled { background: #ccc; cursor: not_allowed; }
            .progress-bg { background: #eee; width: 100px; height: 12px; border-radius: 6px; display: inline-block; vertical-align: middle; }
            .progress-fg { height: 100%; border-radius: 6px; background: #2ea44f; }
        """

    @staticmethod
    def page_wrapper(title, content, head_extra=""):
        return f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>{title}</title>
        <style>{UIComponents.get_common_css()}</style>{head_extra}</head>
        <body onload="initNav()">{content}</body></html>"""

    @staticmethod
    def generate_minimap_css(code_lines, cov1, cov2=None):
        """Generates the gradient CSS for the VS Code style minimap."""
        stops = []
        for i in range(len(code_lines)):
            ln = i + 1
            c1 = cov1.get(ln, 0)
            if cov2 is not None: # Diff mode
                c2 = cov2.get(ln, 0)
                if c1 == 0 and c2 > 0: color = "#2ea44f"
                elif c1 > 0 and c2 == 0: color = "#cf222e"
                elif c1 > 0 and c2 > 0: color = "#e6ffed"
                else: color = "#ffeef0"
            else: # Single mode
                color = "#e6ffed" if c1 > 0 else "#ffeef0"
            
            stops.append(f"{color} {i/len(code_lines)*100:.2f}%")
            stops.append(f"{color} {(i+1)/len(code_lines)*100:.2f}%")
        return f"linear-gradient(to bottom, {', '.join(stops)})"

    @staticmethod
    def generate_file_view(fname, s1_lines, s2_lines=None, base_rel=".."):
        """Generates a detailed line-by-line view (Single or Diff mode)."""
        try:
            with open(fname, 'r') as f: code_lines = f.readlines()
        except: return f"Could not read file {fname}"

        cov1 = {l['line_number']: l['count'] for l in s1_lines}
        cov2 = {l['line_number']: l['count'] for l in (s2_lines or [])}
        
        total_code = len([l for l in s1_lines if not l.get('gcovr/noncode', False)])
        new_covered = len([ln for ln, c in cov2.items() if c > 0 and cov1.get(ln, 0) == 0]) if s2_lines else 0
        lost_covered = len([ln for ln, c in cov1.items() if c > 0 and cov2.get(ln, 0) == 0]) if s2_lines else 0
        
        minimap_css = UIComponents.generate_minimap_css(code_lines, cov1, cov2 if s2_lines else None)
        
        changes = []
        if s2_lines:
            for i in range(len(code_lines)):
                ln = i + 1
                if (cov1.get(ln,0)==0 and cov2.get(ln,0)>0) or (cov1.get(ln,0)>0 and cov2.get(ln,0)==0):
                    changes.append(ln)

        nav_html = ""
        if s2_lines and changes:
            nav_html = f"""
                <div style="display: flex; gap: 5px; align-items: center; margin-left: 20px;">
                    <button class="nav-btn" onclick="prevDiff()">PREV</button>
                    <span id="diff-count" style="font-size: 11px; min-width: 60px; text-align: center; color: #444;">0 / {len(changes)}</span>
                    <button class="nav-btn" onclick="nextDiff()">NEXT</button>
                </div>
                <script>
                    const changes = {json.dumps(changes)};
                    let currentIdx = -1;
                    function initNav() {{ if(changes.length > 0) {{ /* ready */ }} }}
                    function scroll() {{
                        const ln = changes[currentIdx];
                        document.getElementById('line-' + ln).scrollIntoView({{ behavior: 'smooth', block: 'center' }});
                        document.getElementById('diff-count').innerText = (currentIdx + 1) + " / " + changes.length;
                    }}
                    function nextDiff() {{ if(currentIdx < changes.length - 1) {{ currentIdx++; scroll(); }} }}
                    function prevDiff() {{ if(currentIdx > 0) {{ currentIdx--; scroll(); }} }}
                </script>
            """

        # Calculate metrics for the header if in diff mode
        stats_info = f'<span style="color:#666; margin-left:15px;">({total_code} code lines)</span>'
        if s2_lines:
            c1_cnt = len([ln for ln, c in cov1.items() if c > 0])
            c2_cnt = len([ln for ln, c in cov2.items() if c > 0])
            abs_delta = (c2_cnt - c1_cnt) / total_code * 100 if total_code > 0 else 0
            rel_delta = (c2_cnt - c1_cnt) / c1_cnt * 100 if c1_cnt > 0 else (100 if c2_cnt > 0 else 0)
            stats_info = f"""
                <div style="margin-left: 20px; display: flex; gap: 15px; font-size: 11px;">
                    <span><b>Abs Delta:</b> <span class="{'pos' if abs_delta >= 0 else 'neg'}">{abs_delta:+.2f}%</span></span>
                    <span><b>Rel Delta:</b> <span class="{'pos' if rel_delta >= 0 else 'neg'}">{rel_delta:+.2f}%</span></span>
                    <span style="color:#666;">({total_code} code lines)</span>
                </div>
            """

        header = f"""
            <div class="header">
                <a href="{base_rel}/index.html">&larr; back</a>
                <div style="flex-grow:1; font-weight:bold;">{fname} <small style="color:#888; font-weight:normal; margin-left:10px;">Ground-Truth (GCOV)</small></div>
                {nav_html}
                {stats_info}
            </div>
        """
        
        body = f'<div class="minimap" style="background: {minimap_css}" onclick="window.scrollTo(0, (event.clientY / window.innerHeight) * document.documentElement.scrollHeight)"></div>'
        body += f'<div class="main-content">{header}<div class="code-view">'
        
        for i, line in enumerate(code_lines):
            ln = i + 1
            c1, c2 = cov1.get(ln, 0), cov2.get(ln, 0)
            prefix = " "
            if s2_lines:
                if c1 == 0 and c2 > 0: css = "cov-new"; prefix="+"
                elif c1 > 0 and c2 == 0: css = "cov-lost"; prefix="-"
                elif c1 > 0: css = "cov-both"
                else: css = "cov-none"
            else:
                css = "cov-both" if c1 > 0 else "cov-none"
            
            id_attr = f' id="line-{ln}"' if ln in changes else ""
            body += f'<div class="line-container {css}"{id_attr}><div class="line-num">{ln}</div>{prefix} {html_lib.escape(line.rstrip())}</div>'
        
        return UIComponents.page_wrapper(fname, body + "</div></div>")
