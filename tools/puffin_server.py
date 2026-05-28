#!/usr/bin/env python3
"""
puffin_server.py - Puffin Interactive HTTP Server

Extends Python's built-in SimpleHTTPRequestHandler with two POST endpoints
that enable in-browser management of coverage reports:

  POST /api/delete
    Body (JSON): { "target": "/abs/path/to/report/dir", "protocol": "tls"|"opcua" }
    Action: Recursively deletes the target directory (security-checked to be
            inside a coverage-hub-* folder), then regenerates the master hub.
    Response: { "success": true } or { "success": false, "error": "..." }

  POST /api/compute
    Body (JSON):
      {
        "protocol":     "tls" | "opcua",
        "mode":         "run" | "diff",
        "path_a":       "/absolute/path/to/corpus",      # required
        "path_b":       "/absolute/path/to/corpus_b",    # required for diff
        "name":         "my_experiment",                 # optional label
        "put_override": "openssl340-gcov",               # optional PUT override
        "force":        true | false                     # re-execute even if cached
      }
    Action: Builds a puffin_report.py command and launches it inside nix-shell
            as a background subprocess.  Returns immediately; watch the server
            terminal for progress.
    Response: { "success": true, "message": "..." } or { "success": false, "error": "..." }

DEFAULT PUT NAMES (per README_COVERAGE.md):
  TLS:   openssl340-gcov
  OPC UA: open62541   (NOT open62541-gcov — that is only the vendor build target)

Usage:
  python3 tools/puffin_server.py [port]   (default port: 8890)

Always run from the project root (same directory as puffin_report.py).
"""

import http.server
import socketserver
import json
import shutil
import subprocess
import sys
from pathlib import Path

# Add the tools/ directory to sys.path so we can import puffin_report
sys.path.append(str(Path(__file__).parent))
from puffin_report import PuffinReporter


class PuffinHandler(http.server.SimpleHTTPRequestHandler):
    """
    HTTP request handler for the Puffin coverage server.

    Static file serving (GET) is delegated to SimpleHTTPRequestHandler.
    Two POST endpoints are added for report management.
    """

    def do_POST(self):
        """Route incoming POST requests to the appropriate handler."""
        if self.path == '/api/delete':
            self._handle_delete()
        elif self.path == '/api/compute':
            self._handle_compute()
        else:
            super().do_POST()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _read_json_body(self):
        """Read and parse the JSON request body. Returns a dict."""
        content_length = int(self.headers['Content-Length'])
        return json.loads(self.rfile.read(content_length))

    def _send_json(self, status, payload):
        """Send a JSON response with the given HTTP status code."""
        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode())

    def _handle_delete(self):
        """
        Handle POST /api/delete

        Deletes a report directory and regenerates the master hub dashboard.

        Security model: only directories that are:
          1. Absolute children of the current working directory, AND
          2. Contain "coverage-hub-" in their path
        may be deleted.  This prevents path-traversal attacks.
        """
        try:
            data = self._read_json_body()
            target   = data.get('target')
            protocol = data.get('protocol')

            if not target or not protocol:
                self._send_json(400, {'success': False, 'error': 'Missing target or protocol'})
                return

            target_path = Path(target).resolve()
            cwd = Path.cwd().resolve()

            # Security check: target must be inside a coverage-hub-* directory
            # that lives under the current working directory.
            in_cwd      = cwd in target_path.parents
            in_hub_dir  = "coverage-hub-" in str(target_path)

            if not (in_cwd and in_hub_dir):
                self._send_json(400, {
                    'success': False,
                    'error': 'Invalid request or path not allowed'
                })
                return

            if not target_path.exists() or not target_path.is_dir():
                self._send_json(400, {
                    'success': False,
                    'error': f'Directory not found: {target_path}'
                })
                return

            # Delete the report folder
            shutil.rmtree(target_path)
            print(f"\n[SERVER] Deleted: {target_path}")

            # Regenerate the hub so the deleted row disappears immediately
            reporter = PuffinReporter(protocol, f"./coverage-hub-{protocol}")
            reporter.generate_master_dashboard()
            print(f"[SERVER] Hub regenerated for protocol: {protocol}")

            self._send_json(200, {'success': True})

        except Exception as e:
            self._send_json(500, {'success': False, 'error': str(e)})

    def _handle_compute(self):
        """
        Handle POST /api/compute

        Constructs a puffin_report.py CLI command and launches it as a
        background subprocess inside nix-shell.

        The request returns immediately (HTTP 200) once the process is spawned.
        Coverage computation can take minutes; progress is printed to the
        terminal where puffin_server.py is running.

        PUT default values (see README_COVERAGE.md §1):
          TLS   → openssl340-gcov
          OPC UA → open62541   (NOT open62541-gcov; that's only the vendor build name)
        """
        try:
            data = self._read_json_body()

            protocol = data.get('protocol')
            mode     = data.get('mode')      # 'run' or 'diff'
            path_a   = data.get('path_a')    # required: corpus A (or single corpus)
            path_b   = data.get('path_b')    # required for diff only
            name     = data.get('name')      # optional human-readable label
            force    = data.get('force', False)

            # put_override lets the caller specify a non-default PUT name
            # (e.g. "wolfssl-gcov" for TLS, or to pin a specific OpenSSL version)
            put_override = data.get('put_override')

            if not protocol or not mode or not path_a:
                raise ValueError("Missing required fields: protocol, mode, path_a")

            # Determine the PUT name: caller override > protocol default
            default_put = "openssl340-gcov" if protocol == "tls" else "open62541"
            put = put_override or default_put

            # Build the puffin_report.py command
            cmd = ["./tools/puffin_report.py", mode, protocol, path_a]
            if mode == "diff" and path_b:
                cmd.append(path_b)          # diff requires a second corpus path

            cmd.extend(["--put", put])

            if name:
                cmd.extend(["--name", name])
            if force:
                cmd.append("--force")

            # nix-shell provides the correct toolchain (gcovr, llvm-cov, etc.)
            # The entire command is passed as a single quoted string to --run.
            nix_cmd = ["nix-shell", "--run", " ".join(cmd)]

            print(f"\n[SERVER] Starting async compute job:\n  {' '.join(nix_cmd)}\n")

            # Popen (not call/run) so it runs in the background non-blocking
            subprocess.Popen(nix_cmd, cwd=str(Path.cwd()))

            self._send_json(200, {
                'success': True,
                'message': 'Job started successfully. Check the terminal for progress.'
            })

        except Exception as e:
            self._send_json(500, {'success': False, 'error': str(e)})


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Puffin Interactive Coverage Server — serves static files and manages reports."
    )
    parser.add_argument(
        "port", nargs="?", type=int, default=8890,
        help="TCP port to listen on (default: 8890)"
    )
    args = parser.parse_args()

    # Allow port reuse so the server can be restarted quickly
    socketserver.TCPServer.allow_reuse_address = True

    with socketserver.TCPServer(("", args.port), PuffinHandler) as httpd:
        print(f"Puffin Interactive Server running on http://localhost:{args.port}")
        print("  GET  /*              → serves static files (coverage reports)")
        print("  POST /api/delete     → remove a report folder and refresh hub")
        print("  POST /api/compute    → launch a new coverage job via nix-shell")
        print("\nPress Ctrl+C to stop.\n")
        httpd.serve_forever()
