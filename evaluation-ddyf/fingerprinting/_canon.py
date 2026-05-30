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


def normalize_knowledge(k: str, tcp_mode: bool = False) -> str | None:
    """
    Canonicalize one knowledge string by stripping volatile fields.
    If tcp_mode is True, also strips out cipher suite configurations.
    """
    if k.startswith('OpaqueMessageFlight'):
        messages = re.findall(r"OpaqueMessage \{ typ: (\w+), version: [^,]+, payload: Payload\(\[([^\]]+)\]\)", k)
        if not messages:
            return None
        parts = []
        for typ, payload_str in messages:
            length = len(payload_str.split(","))
            if length < 10:
                bucket = "<10"
            elif length <= 100:
                bucket = "10-100"
            elif length <= 1000:
                bucket = "100-1000"
            else:
                bucket = ">1000"
            parts.append(f"{typ}({bucket})")
        return f"OpaqueFlight[{len(messages)}]:" + ",".join(parts)

    for pat, repl in _VOLATILE:
        k = pat.sub(repl, k)
        
    if tcp_mode:
        k = re.sub(r'cipher_suite: [A-Z0-9_]+', 'cipher_suite: VOLATILE', k)
        k = re.sub(r'cipher_suites: CipherSuites\(\[.*?\]\)', 'cipher_suites: VOLATILE', k)
        
    return k


def normalize_error(error: str | None) -> str:
    """Normalize error string: strip hex addresses that may vary across builds."""
    if error is None:
        return 'none'
    return re.sub(r'0x[0-9a-fA-F]+', 'ADDR', error)


def canonicalize_execution(data: dict, tcp_mode: bool = False) -> str:
    """
    Build a stable SHA-256 hash representing the SERVER-OBSERVABLE behavior of
    an execution.
    If tcp_mode is True, omits internal execution state (`err`, `until`) and
    strips configuration-dependent details (like cipher suites) via normalize_knowledge.
    """
    execution = data.get('execution', {})
    executed_until = execution.get('executed_until', -1)
    error = normalize_error(data.get('error'))
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

    # Client-only traces
    if any_client and not server_agents:
        return hashlib.sha256(b'NO_SERVER_OBSERVABLE').hexdigest()

    include_all = not any_client or not server_agents

    if tcp_mode:
        parts: list[str] = []
    else:
        parts: list[str] = [f'err={error}', f'until={executed_until}']

    for i, step in enumerate(steps):
        if i > executed_until and not tcp_mode:
            break
        # In tcp_mode, we might see the trace execute further because the TCP engine
        # delays error reporting compared to the FFI engine. However, steps beyond
        # the offline `executed_until` would just be local evaluation failures.
        # But wait, in TCP mode, executed_until from the TCP trace will be larger.
        if tcp_mode and step.get('action') != 'MessageFlight':
            # Actually, `knowledges` are what we care about.
            pass
        elif i > executed_until:
            break

        if not include_all and step.get('agent') not in server_agents:
            continue
        normed = [normalize_knowledge(k, tcp_mode) for k in step.get('knowledges', [])]
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


def get_signature(trace: str | Path, put: str, timeout: int = 10, tcp_mode: bool = False) -> str | None:
    """
    Compute the canonical observable signature for a trace on a given PUT.
    Returns a 64-hex-char SHA-256 string, or None on execution failure.
    """
    data = run_display(trace, put, timeout)
    return None if data is None else canonicalize_execution(data, tcp_mode)
