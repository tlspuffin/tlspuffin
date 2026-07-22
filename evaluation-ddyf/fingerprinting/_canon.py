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

import os as _os
# Override via env var so the signatures pipeline always uses the correct
# all-PUT binary (/tmp/tlspuffin_o3x) even when target/release/tlspuffin
# gets overwritten by per-pair 2-PUT campaign builds.
# Set TLSPUFFIN_BINARY=/tmp/tlspuffin_o3x before running signatures.py.
PUFFIN = Path(_os.environ.get("TLSPUFFIN_BINARY", "target/release/tlspuffin"))

# ─── Volatile-field normalization rules ──────────────────────────────────────
#
# Applied left-to-right to every MessageFlight knowledge string.
# The goal: make every two executions of the same trace on the same version
# produce the same canonical signature, while preserving all structural
# information (message types, extension presence/absence, alert codes, etc.)
# that differentiates TLS library versions.
#
# Volatile fields (change on every TLS connection):
#   Random         — 32-byte server/client random
#   SessionID      — server-assigned session ID (non-empty only;
#                    SessionID([]) = empty is structural and left unchanged)
#   PayloadU16     — key-share bytes (EC public key in TLS 1.3 extensions)
#   PayloadU8      — opaque blobs (PSK ticket data, etc.) — non-empty only
#   Payload([…])   — generic raw bytes (ClientKeyExchange, Finished, SKE, …)
#   obfuscated_ticket_age — 32-bit random-looking field in TLS 1.3 PSK
#   Certificate([…]) / CertificatePayload([…]) — DER bytes and chain differ
#                    between the lab test cert and production certificate chains;
#                    only the cert BYTES are volatile, not their presence/absence.
#
# NOT normalized (these are deterministic, version-specific, and discriminating):
#   Alert level/description — even Unknown(N) codes are stable per version;
#     tlspuffin (both display-execute and tcp mode) decrypts and reports the
#     plaintext alert code, which is deterministic for a given PUT.
#   KeyShare group name (X25519, secp256r1, …) — server group preference is
#     a structural version property.
#   cipher_suite in ServerHello — already stripped by the cipher_suite rule
#     below (kept from the original design; does not affect 60-cluster result).

_VOLATILE: list[tuple[re.Pattern, str]] = [
    (re.compile(r'Random\(\[[\d, ]+\]\)'),           'Random(VOLATILE)'),
    (re.compile(r'SessionID\(\[[\d, ]+\]\)'),         'SessionID(VOLATILE)'),
    (re.compile(r'PayloadU16\(\[[\d, ]+\]\)'),        'PayloadU16(VOLATILE)'),
    (re.compile(r'PayloadU8\(\[[\d, ]+\]\)'),         'PayloadU8(VOLATILE)'),
    (re.compile(r'Payload\(\[[\d, ]+\]\)'),           'Payload(VOLATILE)'),
    (re.compile(r'obfuscated_ticket_age: \d+'),       'obfuscated_ticket_age: VOLATILE'),
    # Certificate DER bytes — volatile: lab test cert ≠ production cert.
    (re.compile(r'Certificate\(\[[\d, ]+\]\)'),       'Certificate(VOLATILE)'),
    # Certificate chain — lab sends 1 cert, production sends full chain (3+).
    (re.compile(r'CertificatePayload\(\[.*?\]\)', re.DOTALL), 'CertificatePayload(VOLATILE)'),
    (re.compile(r'cipher_suite: [A-Z0-9_]+'),         'cipher_suite: VOLATILE'),
    (re.compile(r'cipher_suites: CipherSuites\(\[.*?\]\)'), 'cipher_suites: VOLATILE'),
    (re.compile(r'level: Unknown\(\d+\), description: Unknown\(\d+\)'), 'level: VOLATILE, description: VOLATILE'),
]

# Live-TCP-only volatile fields.
_VOLATILE_LIVE: list[tuple[re.Pattern, str]] = []

# Aggressive (application-config-independent) normalization.
# Strips all fields the TLS application layer (nginx, Apache, etc.) can override
# through configuration, leaving only library-level observables:
#   - Which message type was sent (ServerHello / Alert / HelloRetryRequest / …)
#   - Which alert description was used (HandshakeFailure / IllegalParameter / …)
#   - Whether a handshake completed or failed
#
# Stripped (config-layer): extension set & content, signature algorithm choices,
# named group lists, ALPN protocol names, supported version lists, compression.
_VOLATILE_AGGRESSIVE: list[tuple[re.Pattern, str]] = [
    # Entire extension list — which extensions nginx enables is config, not version
    (re.compile(r'extensions: Extensions\(\[.*?\]\)', re.DOTALL), 'extensions: VOLATILE'),
    # Signature scheme (CertificateVerify / SignatureAlgorithms extension)
    (re.compile(r'scheme: [A-Za-z0-9_]+'),                        'scheme: VOLATILE'),
    # Supported signature algorithms list
    (re.compile(r'supported_signature_algs: SignatureSchemes\(\[.*?\]\)', re.DOTALL),
     'supported_signature_algs: VOLATILE'),
    # Named groups list (supported_groups extension)
    (re.compile(r'NamedGroups\(\[.*?\]\)', re.DOTALL),            'NamedGroups(VOLATILE)'),
    # ALPN protocol name
    (re.compile(r'ProtocolName\([^)]*\)'),                        'ProtocolName(VOLATILE)'),
    # Supported TLS versions list (supported_versions extension)
    (re.compile(r'SupportedVersions\(\[.*?\]\)', re.DOTALL),      'SupportedVersions(VOLATILE)'),
    # Compression methods
    (re.compile(r'compression_method: \w+'),                      'compression_method: VOLATILE'),
    # legacy_version field inside ServerHello payload (compat field, set by app)
    (re.compile(r'legacy_version: \w+'),                          'legacy_version: VOLATILE'),
    # PSK key exchange modes (psk_key_exchange_modes extension)
    (re.compile(r'PskKeyExchangeModes\(\[.*?\]\)', re.DOTALL),    'PskKeyExchangeModes(VOLATILE)'),
]

# ─────────────────────────────────────────────────────────────────────────────


_EMPTY_MSGFLIGHT = re.compile(r'^MessageFlight\s*\{\s*messages:\s*\[\s*\]\s*\}\s*$')


def normalize_knowledge(k: str, tcp_mode: bool = True, live_mode: bool = False,
                        aggressive_mode: bool = False, seg_robust: bool = False) -> str | None:
    """
    Canonicalize one knowledge string by stripping volatile fields.

    OpaqueMessageFlight (raw TLS records): skipped entirely.
    The length-bucket encoding was not stable between lab (tiny test cert) and
    live (full production cert chain) — different cert sizes fall in different
    buckets, breaking the lab↔live match.  MessageFlight (parsed, decrypted)
    carries all the discriminating information with cert bytes already stripped
    by CertificatePayload(VOLATILE), so OpaqueMessageFlight is redundant.

    live_mode=True applies _VOLATILE_LIVE on top of _VOLATILE.  Currently empty;
    reserved for any future live-only normalization.

    seg_robust=True additionally drops EMPTY MessageFlights (`MessageFlight { messages: [] }`):
    an empty read is a TCP read-boundary artifact, not server behavior, and keeping it perturbs
    the per-step indexing (see canonicalize_execution).
    """
    if k.startswith('OpaqueMessageFlight'):
        return None  # cert size differs between lab and live — use MessageFlight only

    if seg_robust and _EMPTY_MSGFLIGHT.match(k):
        return None  # empty read = TCP segmentation artifact, not a distinguishing response

    for pat, repl in _VOLATILE:
        k = pat.sub(repl, k)
    if live_mode:
        for pat, repl in _VOLATILE_LIVE:
            k = pat.sub(repl, k)
    if aggressive_mode:
        for pat, repl in _VOLATILE_AGGRESSIVE:
            k = pat.sub(repl, k)
    return k


def normalize_error(error: str | None) -> str:
    """Normalize error string: strip hex addresses that may vary across builds."""
    if error is None:
        return 'none'
    return re.sub(r'0x[0-9a-fA-F]+', 'ADDR', error)


def canonicalize_execution(data: dict, tcp_mode: bool = True, live_mode: bool = False,
                           aggressive_mode: bool = False, seg_robust: bool = False) -> str:
    """
    Build a stable SHA-256 hash representing the SERVER-OBSERVABLE behavior of
    an execution.
    If tcp_mode is True, omits internal execution state (`err`, `until`) and
    strips configuration-dependent details (like cipher suites) via normalize_knowledge.

    seg_robust=True keys on the ORDERED SEQUENCE of message-bearing steps rather than on absolute
    step indices (`s{i}:`). The live TCP read uses a fixed idle timeout, so the same server response
    (e.g. ServerHello then Alert) can be split across a different number of reads run-to-run, inserting
    empty-read steps that shift every later step's index and change the hash even though the messages
    are identical. Dropping the index (and empty MessageFlights, via normalize_knowledge) makes the
    signature invariant to where the read boundaries fell. Opt-in: legacy models key on `s{i}:`.
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

    # Reject any trace that has a client agent or multiple server agents, because `tlspuffin tcp`
    # will hang waiting for an external client or panic with 'Address already in use'
    if any_client or len(server_agents) != 1:
        return hashlib.sha256(b'NO_SERVER_OBSERVABLE').hexdigest()

    include_all = True

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
        normed = [normalize_knowledge(k, tcp_mode, live_mode, aggressive_mode, seg_robust)
                  for k in step.get('knowledges', [])]
        normed = [n for n in normed if n is not None]
        if normed:
            # seg_robust: omit the absolute step index `s{i}:` so empty-read insertions (which shift
            # indices) don't change the hash; the ordered list still preserves message sequence.
            parts.append('|||'.join(normed) if seg_robust else f's{i}:' + '|||'.join(normed))

    for pair in execution.get('extra_knowledges', []):
        if len(pair) >= 2:
            n = normalize_knowledge(str(pair[1]))
            if n is not None:
                parts.append(f'extra:{n}')

    # Terminal TCP behavior (fingerprinting): how the server ended the connection -- clean close
    # (TCP_CLOSE), reset (TCP_RST), or held-open/idle (TCP_WAIT). Injected by probe.py from the
    # gated `__FP_DISP__` line the tcp PUT emits. This distinguishes servers that previously all
    # collapsed to EMPTY ("nothing parsed") by *why* nothing was parsed. Absent (legacy probes / no
    # disposition captured) -> signature is unchanged, so old models still match.
    disp = data.get('fp_disposition')
    if tcp_mode and disp:
        parts.append(f'disp={disp}')

    raw = '\n'.join(parts)
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


def run_display(trace: str | Path, put: str, timeout: int = 15) -> dict | None:
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


_EMPTY_SIG = hashlib.sha256(b'').hexdigest()  # SHA256("") — wire-observable "no output"


def get_signature(trace: str | Path, put: str, timeout: int = 30, tcp_mode: bool = True,
                  aggressive_mode: bool = False) -> str:
    """
    Compute the canonical observable signature for a trace on a given PUT.

    Returns a 64-hex-char SHA-256 string.  Never returns None.

    If display-execute crashes or produces no parseable JSON, the signature is
    _EMPTY_SIG (SHA256 of the empty string).  This maps to the same value that
    canonicalize_execution produces for an execution with no observable steps,
    which is exactly what a live TCP probe returns when the server closes the
    connection without sending any TLS record.  The transformation is therefore
    semantically correct: "the PUT aborted before producing wire output" ≡
    "the server sent nothing", both observable as the empty-response hash.
    """
    data = run_display(trace, put, timeout)
    return _EMPTY_SIG if data is None else canonicalize_execution(data, tcp_mode,
                                                                   aggressive_mode=aggressive_mode)
