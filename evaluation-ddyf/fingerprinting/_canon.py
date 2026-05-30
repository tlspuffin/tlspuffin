#!/usr/bin/env python3
"""
Shared canonicalization utilities for the fingerprinting pipeline.

Must be run (or imported) with CWD = repo root, because PUFFIN is a
relative path that resolves against CWD.
"""
import hashlib
import json
import re
import subprocess
from pathlib import Path

PUFFIN = Path("target/release/tlspuffin")

# ─── Volatile-field normalization rules ──────────────────────────────────────
#
# Applied left-to-right to every MessageFlight knowledge string.
# The goal: make every two executions of the same trace on the same version
# produce the same canonical signature, while preserving all structural
# information (message types, extension presence/absence, alert codes, etc.)
# that differentiates wolfssl versions.
#
# Volatile fields (change on every TLS connection):
#   Random         — 32-byte server/client random
#   SessionID      — server-assigned session ID (non-empty only;
#                    SessionID([]) = empty is structural and left unchanged)
#   PayloadU16     — key-share bytes (EC public key in TLS 1.3 extensions)
#   PayloadU8      — opaque blobs (PSK ticket data, etc.) — non-empty only
#   Payload([…])   — generic raw bytes that appear in ClientKeyExchange (EC
#                    client key), Finished (PRF output), ServerKeyExchange
#                    (DH/EC params), etc.
#                    NOTE: Certificate DER bytes appear as Certificate([…])
#                    NOT Payload([…]), so cert bytes are *not* stripped here.
#                    NOTE: Payload([]) = empty is structural and not matched
#                    by [\d, ]+ (requires ≥1 char).
#   obfuscated_ticket_age — 32-bit random-looking field in TLS 1.3 PSK

_VOLATILE: list[tuple[re.Pattern, str]] = [
    (re.compile(r'Random\(\[[\d, ]+\]\)'),           'Random(VOLATILE)'),
    (re.compile(r'SessionID\(\[[\d, ]+\]\)'),         'SessionID(VOLATILE)'),
    (re.compile(r'PayloadU16\(\[[\d, ]+\]\)'),        'PayloadU16(VOLATILE)'),
    (re.compile(r'PayloadU8\(\[[\d, ]+\]\)'),         'PayloadU8(VOLATILE)'),
    (re.compile(r'Payload\(\[[\d, ]+\]\)'),           'Payload(VOLATILE)'),
    (re.compile(r'obfuscated_ticket_age: \d+'),       'obfuscated_ticket_age: VOLATILE'),
    (re.compile(r'cipher_suite: [A-Z0-9_]+'),         'cipher_suite: VOLATILE'),
    (re.compile(r'cipher_suites: CipherSuites\(\[.*?\]\)'), 'cipher_suites: VOLATILE'),
]

# ─────────────────────────────────────────────────────────────────────────────


def normalize_knowledge(k: str) -> str | None:
    """
    Canonicalize one knowledge string by stripping volatile fields.

    Returns None for OpaqueMessageFlight strings: we use the parsed
    MessageFlight counterpart (always present alongside OpaqueMessageFlight)
    which carries the same information in a structured form that survives
    encryption-key changes.
    """
    if k.startswith('OpaqueMessageFlight'):
        return None
    for pat, repl in _VOLATILE:
        k = pat.sub(repl, k)
    return k


def normalize_error(error: str | None) -> str:
    """Normalize error string: strip hex addresses that may vary across builds."""
    if error is None:
        return 'none'
    return re.sub(r'0x[0-9a-fA-F]+', 'ADDR', error)


def canonicalize_execution(data: dict) -> str:
    """
    Build a stable SHA-256 hash representing the SERVER-OBSERVABLE behavior of
    an execution.

    Only steps executed by a SERVER-role agent are included in the signature.
    This mirrors the deployment model (we send a fixed probe, observe what the
    remote server sends back) and ensures consistency with differential-execute,
    which compares two server implementations responding to the same inputs.

    CLIENT-role agent steps (e.g., the wolfssl client's own ClientHello) are
    intentionally excluded: they capture client-side implementation differences
    that would not be visible when probing a remote server with a fixed probe.

    Captures for each server-role step:
      - normalized MessageFlight knowledge strings
    Plus global:
      - error string (normalized)
      - executed_until index
      - extra_knowledges (produced outside the step loop)
    """
    execution = data.get('execution', {})
    executed_until = execution.get('executed_until', -1)
    steps = execution.get('steps', [])

    # Identify which agent names have Server role.
    server_agents: set[int] = set()
    any_client = False
    for agent in execution.get('agents', []):
        typ = agent.get('protocol_config', {}).get('typ', '')
        if typ == 'Server':
            server_agents.add(agent['name'])
        elif typ == 'Client':
            any_client = True

    # Client-only traces (wolfssl acting as its own client, no server agent):
    # return a constant so they never distinguish versions in clustering.
    # Triage should already exclude these, but this is defence-in-depth.
    if any_client and not server_agents:
        return hashlib.sha256(b'NO_SERVER_OBSERVABLE').hexdigest()

    # If there are only Server agents (no Client agents in the trace), include all.
    include_all = not any_client or not server_agents

    # Omit err and until to be robust against execution engine variations (FFI vs TCP)
    parts: list[str] = []

    for i, step in enumerate(steps):
        if i > executed_until:
            break
        # Skip client-role steps unless there are no client agents to exclude.
        if not include_all and step.get('agent') not in server_agents:
            continue
        normed = [normalize_knowledge(k) for k in step.get('knowledges', [])]
        normed = [n for n in normed if n is not None]
        if normed:
            parts.append(f's{i}:' + '|||'.join(normed))

    for pair in execution.get('extra_knowledges', []):
        if len(pair) >= 2:
            n = normalize_knowledge(str(pair[1]))
            if n is not None:
                parts.append(f'extra:{n}')

    return hashlib.sha256('\n'.join(parts).encode('utf-8')).hexdigest()


def run_display(trace: str | Path, put: str, timeout: int = 10) -> dict | None:
    """
    Run `tlspuffin --put <put> display-execute --json -k <trace>`.

    Only `-k` (on-wire knowledges) is requested.  `-c` (internal claims) and
    `-p` (post-execution decryptions that may rely on PUT-internal secrets) are
    intentionally omitted so that the signature is provably wire-observable:
    it captures only what a remote TCP client can see.

    Returns parsed JSON dict or None on any failure (binary crash, timeout,
    JSON parse error).
    """
    try:
        r = subprocess.run(
            [str(PUFFIN), '--put', put, 'display-execute', '--json',
             '-k', str(trace)],
            capture_output=True, timeout=timeout,
        )
        return json.loads(r.stdout)
    except Exception:
        return None


def get_signature(trace: str | Path, put: str, timeout: int = 10) -> str | None:
    """
    Compute the canonical observable signature for a trace on a given PUT.
    Returns a 64-hex-char SHA-256 string, or None on execution failure.
    """
    data = run_display(trace, put, timeout)
    return None if data is None else canonicalize_execution(data)
