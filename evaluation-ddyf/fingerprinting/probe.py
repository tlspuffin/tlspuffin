#!/usr/bin/env python3
"""Live-probing primitives shared by the mine / build_matrix / validate stages.

A *probe* replays one fuzzer-discovered trace against a live server over a real TCP socket (the
tlspuffin ``tcp`` PUT) and canonicalises the server's wire response with the SAME rules used
offline (``_canon.canonicalize_execution`` in tcp+live mode).

Why the pooling matters (hard-won, see DEVELOPER.md): the TCP read uses a fixed idle timeout, so a
slow flight can be *truncated* -- the engine records fewer steps (`executed_until`) than the server
actually sent. Truncation only ever drops trailing flights, never invents them, so the
most-complete capture (max `executed_until`) is the true response. We therefore run each probe
``N_POOL`` times and accept the modal max-depth signature only if it recurs at least ``DOM`` times
(a dominant, reproducible response); otherwise the cell is ``UNSTABLE``. This 10x / >=7-of-10 filter
is what makes the fingerprint robust to OpenSSL's per-connection response jitter.
"""
import contextlib
import hashlib
import io
import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.append(str(_HERE))
from _canon import canonicalize_execution                 # noqa: E402
from build_live_matrix import server_argv, wait_listen     # noqa: E402  (re-exported)
import puts as _puts                                        # noqa: E402

EMPTY = hashlib.sha256(b"").hexdigest()   # canonical signature of "nothing observable"
UNSTABLE = "UNSTABLE"                      # cell sentinel: no reproducible response
TIMEOUT = "TIMEOUT"                        # cell sentinel: server stably timed out
SRVFAIL = "SRVFAIL"                        # cell sentinel: server never came up
MISSING = {UNSTABLE, SRVFAIL, ""}          # treated as "no information" by clustering/tree
N_POOL = 10                                # default probes per cell (overridable via cfg.n_pool)
DOM = 7                                    # default: modal sig must recur >= DOM / N_POOL times
RETRY = 3                                  # default: re-pool an UNSTABLE cell this many times


def _canon_quiet(data):
    """canonicalize_execution can emit stray debug prints; silence them to keep stdout clean."""
    with contextlib.redirect_stdout(io.StringIO()):
        return canonicalize_execution(data, tcp_mode=True, live_mode=True)


def sigkey(full_sig, sig_len):
    """Truncate a full canon signature to a model's key length (sig_len 0/None == use full).

    The committed OpenSSL model keys on the 10-char prefix; the WolfSSL model on full sigs. A live
    probe always yields the full sig, so callers truncate via this helper before matching.
    """
    if full_sig in (UNSTABLE, SRVFAIL, TIMEOUT):
        return full_sig
    return full_sig if not sig_len else full_sig[:sig_len]


def _run_once(cfg, binary, trace, port):
    """One replay -> (depth, full_sig) or None if the probe produced no parseable JSON."""
    try:
        r = subprocess.run(cfg.task_prefix() + [binary, "tcp", str(trace), "--host", "127.0.0.1",
                                                "--port", str(port), "--json"],
                           capture_output=True, text=True, timeout=cfg.timeout)
    except subprocess.TimeoutExpired:
        return (0, TIMEOUT)
    i = r.stdout.find("{")
    if i < 0:
        return (0, EMPTY)
    try:
        d = json.loads(r.stdout[i:])
    except json.JSONDecodeError:
        return None
    depth = (d.get("execution") or {}).get("executed_until", 0) or 0
    return (depth, _canon_quiet(d))


def batch(cfg, trace, port, k=7, resp_min=5):
    """Cheap single-batch screen: k connections -> modal max-depth FULL sig, or None if the server
    responded on fewer than `resp_min` of them (used by the mine A1 screen)."""
    binary = cfg.prober()
    caps = [c for c in (_run_once(cfg, binary, trace, port) for _ in range(k)) if c is not None]
    if not caps:
        return None
    best = max(d for d, _ in caps)
    if len(caps) < resp_min:
        return None
    return Counter(s for d, s in caps if d == best).most_common(1)[0][0]


def pooled_sig(cfg, trace, port, n_pool=None, dom=None):
    """Run `trace` n_pool times against 127.0.0.1:port; return the FULL modal max-depth signature
    iff it recurs >= dom times, else UNSTABLE (the reproducibility filter). When n_pool/dom are not
    given they default to the resolved cfg params (cfg.n_pool/cfg.dom; CLI > env > 10/7)."""
    n_pool = n_pool if n_pool is not None else getattr(cfg, "n_pool", N_POOL)
    dom = dom if dom is not None else getattr(cfg, "dom", DOM)
    binary = cfg.prober()
    caps = [c for c in (_run_once(cfg, binary, trace, port) for _ in range(n_pool)) if c is not None]
    if not caps:
        return UNSTABLE
    best = max(d for d, _ in caps)
    sig, cnt = Counter(s for d, s in caps if d == best).most_common(1)[0]
    return sig if cnt >= dom else UNSTABLE


def stable_sig(cfg, trace, port, retry=None):
    """pooled_sig with up to `retry` attempts before declaring UNSTABLE (used under light load).
    `retry` defaults to the resolved cfg param (cfg.retry; CLI > env > 3)."""
    retry = retry if retry is not None else getattr(cfg, "retry", RETRY)
    for _ in range(retry):
        s = pooled_sig(cfg, trace, port)
        if s != UNSTABLE:
            return s
    return UNSTABLE


def launch(cfg, put, ver, port):
    """Start the vendored stock server for (put, ver) on `port`, pinned to cfg.cores.

    If the server binary is missing (e.g. wolfssl 5.5.0/5.5.1, whose example server does not build),
    return a harmless already-exiting placeholder process: `wait_listen` then fails and the caller
    records SERVER-FAIL. This avoids a FileNotFoundError -- which Popen raises only when UNPINNED
    (with a taskset prefix the wrapper exists and merely exec-fails into a quick exit)."""
    argv, env, cwd = server_argv(_puts.PUTS[put]["server_cmd"], ver, port)
    if not os.path.exists(argv[0]):
        return subprocess.Popen(["true"])          # dead placeholder -> wait_listen fails -> SERVER-FAIL
    e = dict(os.environ)
    e.update(env or {})
    return subprocess.Popen(cfg.task_prefix() + argv, env=e, cwd=cwd,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def kill(*procs):
    for p in procs:
        try:
            p.terminate()
        except Exception:
            pass
