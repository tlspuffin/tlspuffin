#!/usr/bin/env python3
"""Central PUT (Program-Under-Test) registry + runtime path resolver for the DDYF
version-fingerprinting pipeline.

Everything that used to be a hardcoded literal in the individual stage scripts
(`/home/.../fingerprinting`, `/tmp/tlspuffin_fast200`, `<repo>/vendor`,
`/tmp/ossl_confirmed_reps.txt`, the `openssl3(\\d)(\\d+)` regex, the duplicated `vkey`/`dot`
helpers, …) lives here exactly once, so that:

  * adding a new TLS stack is a single dict entry (see ``PUTS`` below), and
  * NO path is ever a literal absolute -- every location is resolved through one precedence
    chain:  **CLI option  ->  environment variable  ->  derived default**  (and only the derived
    default is computed, never written as a literal).

Stage scripts call ``add_common_args(parser)`` then ``cfg = resolve(args)`` to obtain a shared
:class:`Config`.  Run ``python3 puts.py`` to print the resolved configuration (handy self-check).
"""
import argparse
import glob
import os
import re
from pathlib import Path

# This file's directory == evaluation-ddyf/fingerprinting (derived, never hardcoded).
THIS_DIR = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------------------------
# Per-PUT registry.  One entry per TLS stack we can fingerprint.
#   server_cmd  : key understood by build_live_matrix.server_argv() -- which stock example
#                 server to launch for a given vendored version.
#   vendor_glob : how this stack's vendored servers are named under <vendor_dir>/.
#   ver_re      : regex over the vendor dir name capturing (middle, patch) of the X.<m>.<p> line.
#   line        : the major line digit (OpenSSL 3.x -> "3", WolfSSL 5.x -> "5").
#   base_port   : default first localhost port for the per-version servers.
#   drop        : vendor dirs to ignore (e.g. a re-vendored duplicate build).
#   features    : cargo feature hint shown if the prober binary is missing.
#   sig_len     : signature key length the committed reference model uses (see note below).
#
# Note on sig_len: the committed OpenSSL matrix/tree store the 10-char signature prefix
# (rebuild_matrix used sig[:10]); the committed WolfSSL model stores full 64-char sigs. A live
# probe always yields the full sig, so the walk truncates to the model's sig_len before matching.
PUTS = {
    "openssl": dict(
        server_cmd="openssl", vendor_glob="openssl3*", ver_re=r"^openssl3(\d)(\d+)$",
        line="3", base_port=27000, drop={"openssl340u"}, features="cputs (openssl 3.x PUTs)",
        sig_len=10,
    ),
    "wolfssl": dict(
        server_cmd="wolfssl", vendor_glob="wolfssl5*", ver_re=r"^wolfssl5(\d)(\d+)$",
        line="5", base_port=27000, drop=set(), features="cputs (wolfssl 5.x PUTs)",
        sig_len=0,  # 0 == use the full signature (the WolfSSL reference model keys on full sigs)
    ),
}


def put_names():
    return sorted(PUTS)


# ---- per-PUT version helpers (single definition; were copy-pasted across 4 scripts) ----------
def vkey(put, v):
    """Sort key (middle, patch) for a vendor dir name; unknown names sort last."""
    m = re.match(PUTS[put]["ver_re"], v)
    return (int(m.group(1)), int(m.group(2))) if m else (9, 9)


def dotted(put, v):
    """Pretty dotted version, e.g. 'openssl3013' -> '3.0.13', 'wolfssl584' -> '5.8.4'."""
    m = re.match(PUTS[put]["ver_re"], v)
    return f"{PUTS[put]['line']}.{m.group(1)}.{m.group(2)}" if m else v


def is_version(put, v):
    """True iff vendor dir name `v` is a real numbered release of this PUT (and not dropped)."""
    return bool(re.match(PUTS[put]["ver_re"], v)) and v not in PUTS[put]["drop"]


def versions(put, vendor_dir):
    """All vendored versions of `put` present under vendor_dir, sorted by (middle, patch)."""
    found = set()
    for p in glob.glob(str(Path(vendor_dir) / PUTS[put]["vendor_glob"])):
        name = os.path.basename(p)
        if "-asan" in name:
            continue  # ASAN builds are not used for live probing (poisoned signatures)
        if is_version(put, name):
            found.add(name)
    return sorted(found, key=lambda v: vkey(put, v))


# ---- path/runtime resolver -------------------------------------------------------------------
def _find_repo_root():
    """Walk up from this file until a `.git` dir is found; fall back to <fingerprinting>/../.."""
    p = THIS_DIR
    for _ in range(8):
        if (p / ".git").exists():
            return p
        if p.parent == p:
            break
        p = p.parent
    return THIS_DIR.parent.parent


def _first(*vals):
    """First value that is not None/'' (CLI -> env -> derived precedence)."""
    for v in vals:
        if v not in (None, ""):
            return v
    return None


class Config:
    """Resolved runtime configuration shared by every stage script.

    Each attribute follows CLI option -> environment variable -> derived default. Path-like
    attributes are :class:`pathlib.Path`. ``prober()`` is lazy (resolved only when actually
    probing) so ``--help`` and imports never require the binary to exist.
    """

    def __init__(self, args=argparse.Namespace()):
        g = lambda n: getattr(args, n, None)
        self.repo = Path(_first(g("repo_root"), os.environ.get("DDYF_ROOT"), _find_repo_root()))
        self.this_dir = THIS_DIR
        self.vendor = Path(_first(g("vendor_dir"), os.environ.get("VENDOR_DIR"), self.repo / "vendor"))
        # Export so build_live_matrix.server_argv() (which reads VENDOR_DIR) honors --vendor-dir
        # regardless of import order.
        os.environ["VENDOR_DIR"] = str(self.vendor)
        self.reference = Path(_first(g("reference_dir"), os.environ.get("FP_REFERENCE"),
                                     self.this_dir / "reference"))
        self._prober = _first(g("prober"), os.environ.get("PUFFIN_BIN"))
        self._exp_glob = _first(g("experiments_glob"), os.environ.get("FP_EXPERIMENTS_GLOB"))
        self.cores = _first(g("cores"), os.environ.get("CORES")) or ""  # "" == no taskset pin
        self.jobs = int(_first(g("jobs"), os.environ.get("JOBS"), 15))
        self.base_port = int(_first(g("base_port"), os.environ.get("BASE_PORT"), 27000))
        self.timeout = float(_first(g("timeout"), os.environ.get("TIMEOUT"), 12.0))

    # -- lazily-resolved prober (fail fast with an actionable message) --
    def prober(self, put=None):
        cand = self._prober or str(self.repo / "target" / "release" / "tlspuffin")
        if not Path(cand).exists():
            feat = PUTS.get(put, {}).get("features", "<put-features>")
            raise SystemExit(
                f"prober binary not found at {cand}\n"
                f"  -> set --prober PATH or PUFFIN_BIN, or build it:\n"
                f"     cargo build --release -p tlspuffin --features {feat}")
        return cand

    def task_prefix(self):
        """taskset prefix for pinning probes/servers to `--cores` (empty list if unset)."""
        return ["taskset", "-c", self.cores] if self.cores else []

    # -- per-PUT locations under the reference tree --
    def ref(self, put):
        return self.reference / put

    def probes_full_dir(self, put):
        """Gitignored working dir holding the FULL confirmed-probe set (matrix rebuild input)."""
        return self.ref(put) / "probes_full"

    def reps_file(self, put):
        """The probe list: one trace per line under probes_full/. Entries are normally bare
        filenames resolved against probes_full/ (so the committed set is found by default); an
        absolute path is used as-is (handy when pointing at fresh-campaign traces elsewhere)."""
        return self.probes_full_dir(put) / "reps.txt"

    def read_reps(self, put):
        """Return the confirmed-probe trace paths as resolved absolute paths. A bare filename is
        looked up in probes_full/ (the committed default); an absolute line is kept verbatim."""
        rf = self.reps_file(put)
        full = self.probes_full_dir(put)
        out = []
        for line in rf.read_text().split("\n"):
            e = line.strip()
            if not e:
                continue
            out.append(e if os.path.isabs(e) else str(full / os.path.basename(e)))
        return out

    def probes_dir(self, put):
        """Committed dir with ONLY the decision-tree probe traces (deployment model)."""
        return self.ref(put) / "probes"

    def versions(self, put):
        return versions(put, self.vendor)

    def experiments_glob(self, put):
        """Glob locating this PUT's differential-campaign objective traces (mine stage input)."""
        if self._exp_glob:
            return self._exp_glob
        return str(self.repo / "experiments" / f"*{put}*fpp*" / "objective" / "*.trace")

    def describe(self, puts=()):
        lines = [f"repo        = {self.repo}",
                 f"vendor      = {self.vendor}",
                 f"reference   = {self.reference}",
                 f"prober      = {self._prober or '(derived: ' + str(self.repo/'target/release/tlspuffin') + ')'}",
                 f"cores       = {self.cores or '(unpinned)'}   jobs={self.jobs}   base_port={self.base_port}   timeout={self.timeout}"]
        for put in puts:
            vs = self.versions(put)
            lines.append(f"PUT {put:8s}: {len(vs)} vendored versions"
                         + (f" ({dotted(put, vs[0])}..{dotted(put, vs[-1])})" if vs else " (none found)"))
        return "\n".join(lines)


def add_common_args(parser, only=None):
    """Attach the shared path/runtime options to an argparse parser (CLI tier of the chain).

    `only` (an iterable of dest names) restricts which options are added -- useful for scripts that
    already define some of these flags themselves (e.g. fingerprint_probe.py has its own --timeout).
    """
    specs = [
        ("repo_root", "--repo-root", {}, "repo root [env DDYF_ROOT; default: nearest .git ancestor]"),
        ("vendor_dir", "--vendor-dir", {}, "vendored servers dir [env VENDOR_DIR; default: <repo>/vendor]"),
        ("reference_dir", "--reference-dir", {}, "reference data dir [env FP_REFERENCE; default: ./reference]"),
        ("prober", "--prober", {}, "tlspuffin prober binary [env PUFFIN_BIN; default: <repo>/target/release/tlspuffin]"),
        ("experiments_glob", "--experiments-glob", {}, "objective-trace glob for the mine stage [env FP_EXPERIMENTS_GLOB]"),
        ("cores", "--cores", {}, "taskset core list to pin probes/servers, e.g. 0,2,4,..,28 [env CORES]"),
        ("jobs", "--jobs", {"type": int}, "parallel workers [env JOBS; default 15]"),
        ("base_port", "--base-port", {"type": int}, "first localhost port for per-version servers [env BASE_PORT; default 27000]"),
        ("timeout", "--timeout", {"type": float}, "per-probe timeout in seconds [env TIMEOUT; default 12]"),
    ]
    g = parser.add_argument_group("paths & runtime (CLI > env var > derived default)")
    for dest, flag, kw, helptext in specs:
        if only is not None and dest not in only:
            continue
        g.add_argument(flag, help=helptext, **kw)
    return parser


def add_put_arg(parser, multi=False):
    """Attach the --put selector (single PUT for a stage, or a list for the driver/prober)."""
    if multi:
        parser.add_argument("--put", nargs="+", default=["openssl"], choices=put_names(),
                            help="one or more PUTs to process, e.g. --put openssl wolfssl")
    else:
        parser.add_argument("--put", default="openssl", choices=put_names(),
                            help="which PUT this stage operates on")
    return parser


def resolve(args):
    """Build a :class:`Config` from parsed args (after add_common_args)."""
    return Config(args)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="show the resolved fingerprinting configuration")
    add_common_args(ap)
    add_put_arg(ap, multi=True)
    a = ap.parse_args()
    cfg = resolve(a)
    print("Resolved DDYF fingerprinting configuration:\n" + cfg.describe(a.put))
