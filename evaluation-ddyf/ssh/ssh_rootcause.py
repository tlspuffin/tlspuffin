"""Root-cause keying for the libssh-vs-wolfSSH differential triage (re-cut 2026-09-24).

Every objective is mapped to ONE root-cause key: the observable FIRST divergence between the
two PUTs, qualified by the PUT's role. Buckets in sort_objectives_libssh_wolfssh.py are then
"all traces with key K" (see RootCauseC), so a bucket holds exactly one observable cause.

Key families, in precedence order (first applicable wins; see root_cause_key()):

  named:<mechanism>        a documented mechanism recognised semantically (findings, harness gaps)
  auth_unexplained:<role>  the two PUTs disagree on authentication and the disagreement is NOT a
                           consequence of the non-authenticating side having already died before
                           the attacker's auth step -> audit pile, never benign
  aead:<role>:<cause>      wolfSSH fails first with AES-GCM tag failure (gerr=-180); cause in
                           {mutated_key_schedule, plaintext_after_newkeys, wrong_invocation_counter,
                           computed_counter_term, broken_key_schedule_term, stale_pre_rekey_schedule,
                           non_canonical_exchange_hash, unexplained}
  status:<role>:<side>:<error-class>
                           execution-status divergence; <side> = the PUT that failed FIRST in the
                           differential run (L, W, or '=' for the same step); error class of that PUT
  claim:<role>:<side>:<error-class>
                           no status divergence; exactly one PUT finalised KEX (emitted its claim);
                           <side> = the PUT that did NOT, keyed by that PUT's own error class
  shape:<role>:<ops>       transcript-only divergence; <ops> = the exact set of per-message
                           Added/Removed/Changed operations in the aligned decrypted transcripts
                           ("A92" = message 92 present on wolfSSH only, "R96" = on libssh only,
                           "C92" = content differs), or ORDER for a pure reordering

Everything is computed from the objective's cached DIFFERENTIAL record (metadata_diff_*.json,
the oracle the objective was selected on) plus the two uniformised per-PUT replays (for the
decrypted transcripts, the attacker recipe and each PUT's own error).
"""
import re

LIBSSH, WOLFSSH = 1, 2
_OP = re.compile(r"(Added|Removed|Changed)\(AlignmentKey \{ channel: \d+, msg_number: (\d+)")
_KEY = re.compile(r"AlignmentKey \{ channel: \d+, msg_number: (\d+), ordinal: \d+ \}")


# ---------------------------------------------------------------- attacker recipe parsing
class Node:
    __slots__ = ("name", "children")

    def __init__(self, name):
        self.name = name
        self.children = []


def parse_term(text):
    """Parse sshpuffin's pretty-printed term (one argument per line, `fn(` opens, `) -> T` closes)."""
    root = Node("<root>")
    stack = [root]
    for raw in text.split("\n"):
        line = raw.strip().rstrip(",")
        if not line:
            continue
        if line.endswith("("):
            n = Node(line[:-1])
            stack[-1].children.append(n)
            stack.append(n)
        elif line.startswith(")"):
            if len(stack) > 1:
                stack.pop()
        else:
            stack[-1].children.append(Node(line.split(" -> ")[0]))
    return root.children[0] if root.children else Node("<empty>")


def inputs(status):
    """[(step_number, root Node, recipe text)] of the attacker inputs, from a per-PUT replay."""
    out = []
    for s in status["execution"]["steps"]:
        a = s.get("action")
        if isinstance(a, dict) and a.get("Input"):
            r = a["Input"].get("recipe") or ""
            out.append((s["step_number"], parse_term(r), r))
    return out


def message_of(node):
    """The SSH message builder carried by an input step (fn_packet(X) / fn_encrypt_packet_*(X, ...))."""
    if node.name.startswith("fn_encrypt_packet") or node.name in ("fn_packet", "fn_onwire_message"):
        return node.children[0].name if node.children else node.name
    return node.name


def _msg_node(node):
    if node.name.startswith("fn_encrypt_packet") or node.name in ("fn_packet", "fn_onwire_message"):
        return node.children[0] if node.children else None
    return node


def is_encrypted(node):
    return node.name.startswith("fn_encrypt_packet")


# ---------------------------------------------------------------- per-PUT observables
def transcript(status):
    """Message numbers present in the PUT's own decrypted transcript (by_key section)."""
    ms = set()
    for e in status["execution"].get("extra_knowledges", []):
        v = e[1] if len(e) > 1 else ""
        if v.startswith("AlignedTranscript"):
            i = v.find("order:")
            ms.update(int(m) for m in _KEY.findall(v[:i] if i >= 0 else v))
    return ms


def role(es):
    return es.put1()["execution"]["agents"][0]["protocol_config"]["typ"]


def diff_status(es):
    for e in es.errors or []:
        if "Status" in e:
            return e["Status"]
    return None


def fail_step(es, put):
    """Step at which `put` failed: differential record if it carries a Status, else live replay.
    None = did not fail."""
    st = diff_status(es)
    if st is not None:
        s = st["first_status"] if put == LIBSSH else st["second_status"]
        if s == "Success":
            return None
        return st["first_executed_steps"] if put == LIBSSH else st["second_executed_steps"]
    live = es.put1() if put == LIBSSH else es.put2()
    return None if live.get("error") is None else live["execution"]["executed_until"]


def error_class(err):
    """Normalise a status/error string to its check (wolfSSH gerr code, libssh message, mapper kind)."""
    if err is None or err == "Success":
        return "success"
    e = err.replace("error in PUT : ", "")
    m = re.search(r"gerr=(-?\d+)", e)
    if m:
        return "wolfssh_gerr" + m.group(1).lstrip("-")
    if e.startswith("error executing a function symbol"):
        m = re.search(r"rustls: (no message \d+|Expected [\w:]+|no CHANNEL_OPEN_CONFIRMATION|peer public key|Passed argument|"
                      r"AES-GCM key|AES-GCM IV|AES-CTR key|AES-CTR IV|no message)", e)
        k = m.group(1) if m else "other"
        k = re.sub(r"no message \d+", "no_message", k)
        return "mapper_" + re.sub(r"\W+", "_", k).strip("_").lower()
    if e.startswith("error evaluating a term"):
        return "mapper_unbound_variable"
    if e.startswith("Packet filter"):
        return "libssh_packet_filter"
    if "Packet len too high" in e:
        return "libssh_packet_len_too_high"
    if e.startswith("Received SSH_MSG_DISCONNECT"):
        return "libssh_received_disconnect"
    if e.startswith("kex error"):
        m = re.search(r"no match for method ([\w >-]+?)(:|$)", e)
        return "libssh_kex_no_match_" + re.sub(r"\W+", "_", m.group(1) if m else "x").strip("_")
    return "libssh_" + re.sub(r"\W+", "_", re.sub(r"\d+", "", e.split(":")[0])).strip("_").lower()[:40]


# ---------------------------------------------------------------- named mechanisms
def _first(inp, pred):
    return next((i for i, n, _ in inp if pred(n)), None)


def named_mechanisms(es, rl, inp, tl, tw):
    """All documented mechanisms this trace exhibits, in precedence order (first = its bucket)."""
    out = []
    for fn in _NAMED:
        try:
            m = fn(es, rl, inp, tl, tw)
        except Exception:
            m = None
        if m:
            out.append(m)
    return out


def _n_core(es, rl, inp, tl, tw):
    msgs = [(i, message_of(n)) for i, n, _ in inp]
    names = [m for _, m in msgs]
    if rl == "Client":
        us = next((i for i, m in msgs if m == "fn_user_auth_success"), None)
        if us is not None:
            sa_before = any(m == "fn_service_accept" and i < us for i, m in msgs)
            w_post = any(m >= 80 for m in tw)
            l_post = any(m >= 80 for m in tl)
            if not sa_before and (w_post or 50 in tw) and not (l_post or 50 in tl):
                # wolfSSH CLIENT treats a USERAUTH_SUCCESS that arrives before any SERVICE_ACCEPT
                # (hence before it sent any auth request) as authentication.
                return ("known_wolfssh_client_accepts_unsolicited_userauth_success" if 50 in tw
                        else "known_wolfssh_client_accepts_unsolicited_userauth_success_no_request")
        # Sibling of the above, same ladder gap, milder consequence and a different trigger: the
        # server sends USERAUTH_FAILURE before any SERVICE_ACCEPT -- i.e. before the client is
        # entitled to be in userauth at all -- and the wolfSSH client answers it with a
        # USERAUTH_REQUEST, while the libssh client stays silent and waits for the SERVICE_ACCEPT
        # its SERVICE_REQUEST is owed (RFC 4253 §10). A later SERVICE_ACCEPT does not change this:
        # the divergence is already fixed at the earlier unsolicited FAILURE.
        uaf = next((i for i, m in msgs if m == "fn_user_auth_failure"), None)
        sa = next((i for i, m in msgs if m == "fn_service_accept"), None)
        if uaf is not None and (sa is None or uaf < sa) and 50 in tw and 50 not in tl:
            return "known_wolfssh_client_userauth_request_after_unsolicited_failure"
        return None
    # ---- server role
    first_ua = next((i for i, m in msgs if m == "fn_user_auth_request"), None)
    sr_before_ua = any(m == "fn_service_request" and (first_ua is None or i < first_ua) for i, m in msgs)
    if not sr_before_ua and 6 in tw:
        wo, lo = _order(es.put2()) or [], _order(es.put1()) or []
        w_early = (6, 0) in wo and ((52, 0) not in wo or wo.index((6, 0)) < wo.index((52, 0)))
        l_early = (6, 0) in lo and ((52, 0) not in lo or lo.index((6, 0)) < lo.index((52, 0)))
        if w_early and not l_early:
            # wolfSSH SERVER sends SERVICE_ACCEPT although no SERVICE_REQUEST preceded the auth request
            return "known_wolfssh_unsolicited_service_accept"
    # USERAUTH_REQUEST whose service field is not "ssh-connection": wolfSSH never checks it.
    bad_svc = any(message_of(n) == "fn_user_auth_request" and _uar_service(n) not in (None, "fn_ssh_connection")
                  for _, n, _ in inp)
    if bad_svc and (52 in tw or 60 in tw) and 52 not in tl:
        return "known_wolfssh_userauth_service_name_not_validated"
    # Same defect, milder consequence: the trace ALSO carries a well-formed request, so libssh
    # authenticates too (52 in tl) and the arm above cannot see it. What still divides the two
    # stacks is the answer to the bad-service request itself -- libssh replies USERAUTH_FAILURE,
    # wolfSSH replies PK_OK/SUCCESS and never emits a FAILURE at all. Same root cause (wolfSSH
    # DoUserAuthRequest does not validate the service field), so same bucket; the transcripts are
    # message-number SETS, so the surviving signal is "libssh sent 51, wolfSSH sent none".
    if bad_svc and (52 in tw or 60 in tw) and 51 in tl and 51 not in tw:
        return "known_wolfssh_userauth_service_name_not_validated"
    # libssh harness accepts any SERVICE_REQUEST service name; wolfSSH rejects -> only libssh authenticates
    bad_sr = any(m.name == "fn_service_request" and (not m.children or m.children[0].name != "fn_ssh_userauth")
                 for m in (_msg_node(n) for _, n, _ in inp) if m is not None)
    if bad_sr and 52 in tl and 52 not in tw:
        return "harness_libssh_service_request_name_not_checked"
    ua = _first(inp, lambda n: message_of(n) == "fn_user_auth_request")
    st = diff_status(es)
    wf = fail_step(es, WOLFSSH)
    werr = (st["second_status"] if st else es.put2().get("error")) or ""
    # repeated SERVICE_REQUEST before auth: wolfSSH aborts ("Message ID 5 not allowed by server after
    # starting user auth", gerr=-1094) while libssh answers it again.
    # The abort may land on a SERVICE_REQUEST sent before OR after the first auth request (in the latter
    # case libssh has answered the auth in between, which is the same mechanism, not an auth divergence).
    if ("gerr=-1094" in werr and wf is not None
            and any(i == wf and message_of(n) == "fn_service_request" for i, n, _ in inp)
            and sum(1 for i, m in msgs if m == "fn_service_request" and i <= wf) >= 2):
        return "known_wolfssh_repeated_service_request_fatal"
    # The USERAUTH_REQUEST packet itself fails wolfSSH's AES-GCM tag check (wrong key/nonce) and libssh
    # authenticates on it: libssh ignores the tag failure (CVE-2026-59847, EVP_DecryptFinal rc < 0).
    # The witness is that libssh ACTED on a packet whose AES-GCM tag wolfSSH rejected; HOW the key came to
    # be wrong (mutated schedule / literal counter / non-canonical hash / not yet classified) is a
    # sub-cause and must not narrow the class.
    if ("gerr=-180" in werr and wf is not None and 52 in tl and 52 not in tw
            and any(i == wf and message_of(n) == "fn_user_auth_request" for i, n, _ in inp)):
        return "known_libssh_cve_2026_59847_authenticates_on_tag_failed_packet"
    # wolfSSH, acting as SERVER, parses an EXT_INFO "server-sig-algs" extension -- which RFC 8308 §3.1
    # defines as server->client -- finds no usable signature algorithm in its value, and ABORTS the
    # connection: DoExtInfoServerSigAlgs -> MatchIdLists returns ID_UNKNOWN -> WS_MATCH_UA_KEY_ID_E
    # (internal.c:6806). libssh tolerates the unusable extension and goes on to authenticate.
    #
    # The former name of this bucket, diverge_wolfssh_rejects_userauth_key_type_libssh_accepts, was
    # WRONG: -1089 is not raised on the credential at all. Measured over all 852 traces -- the step
    # wolfSSH fails on is an fn_ext_info in 852/852, role is Server in 852/852, and the extension value
    # is never a signature-algorithm name list (it is the extension NAME reused as its own value in 535,
    # otherwise a KEXINIT payload, an ECDH public key, a host-key blob, a channel type string, ...).
    # The credential these traces carry is an ordinary, properly signed rsa-sha2-256 publickey auth, so
    # libssh is not accepting anything deprecated; wolfSSH is the non-conformant side.
    #
    # Scope note: 16,348 traces corpus-wide hit -1089, so the abort is NOT unique to this bucket. The
    # auth-divergence conjunct is what makes it the FIRST observable divergence here; elsewhere the
    # first divergence is something else and the trace is keyed by that.
    if ("gerr=-1089" in werr and 52 in tl and 52 not in tw and wf is not None
            and any(i == wf and message_of(_msg_node(n) or n) == "fn_ext_info" for i, n, _ in inp)):
        return "known_wolfssh_aborts_on_unusable_server_sig_algs"
    # wolfSSH's USERAUTH_REQUEST parser refuses a malformed/mutated request (bad buffer size, bad argument,
    # overflow) ON THAT VERY STEP, while libssh's parser tolerates it and authenticates. Parser-strictness
    # divergence at the auth step: libssh's ssh_packet_userauth_request() frees the message and returns
    # SSH_PACKET_USED on a parse error (messages.c error: label), i.e. it silently ignores the malformed
    # request and keeps the connection alive for the next, well-formed one, which it then authenticates.
    if (any(g in werr for g in ("gerr=-1004", "gerr=-1002", "gerr=-1007")) and wf is not None
            and any(i == wf and message_of(n) == "fn_user_auth_request" for i, n, _ in inp)
            and 52 in tl and 52 not in tw):
        return "diverge_wolfssh_rejects_malformed_userauth_libssh_accepts"
    return None


def _da():
    from .. import diff_analyzer
    return diff_analyzer


_CONN_BUILDERS = ("fn_channel_open", "fn_channel_open_conf", "fn_channel_open_failure", "fn_channel_window_adjust",
                  "fn_channel_data", "fn_channel_extended_data", "fn_channel_eof", "fn_channel_close",
                  "fn_channel_request", "fn_channel_success", "fn_channel_failure", "fn_global_request",
                  "fn_request_success", "fn_request_failure", "fn_request_cancel_tcpip_forward")


def _n_preauth_conn(es, rl, inp, tl, tw):
    """wolfSSH CLIENT dispatches a connection-layer message (RFC 4250 msg >= 80) delivered in PLAINTEXT
    before NEWKEYS -- i.e. before key exchange completes, before host-key verification and before any
    authentication -- while the libssh client refuses it (packet filter).

    Root cause (vendored wolfSSH 1.5.0, src/internal.c IsMessageAllowedClient): the RFC 4252 s6 guard on
    msg >= 80 is armed only inside the window `connectState >= CONNECT_KEYED && connectState <
    CONNECT_SERVER_USERAUTH_ACCEPT_DONE`; below CONNECT_KEYED the else-branch returns 1 (allowed). The
    server half of the same file has the matching guard (`acceptState < ACCEPT_KEYED` -> reject anything
    above KEXDH_GEX_REQUEST); the client half has no counterpart. Upstream master drops the lower bound,
    which closes it. IsMessageAllowed() is called in DoPacket() immediately before the dispatch switch,
    so it is the only gate between the wire and the connection-layer parsers.
    """
    if rl != "Client":
        return None
    nk = _first(inp, lambda n: message_of(n) == "fn_new_keys" and not is_encrypted(n))
    if not (any(m >= 80 for m in tw) and not any(m >= 80 for m in tl)):
        return None
    # (a) a recognised connection-layer builder was delivered in plaintext before NEWKEYS
    if any(not is_encrypted(n) and message_of(n) in _CONN_BUILDERS and (nk is None or i < nk)
           for i, n, _ in inp):
        return "known_wolfssh_client_accepts_preauth_connection_layer"
    # (b) NO NEWKEYS was delivered AT ALL -- plaintext or sealed -- so the PUT cannot have taken any
    #     receive key into use and the whole trace is pre-KEYED: whatever wolfSSH answered at the
    #     connection layer, it answered unkeyed. Catches deliveries built from raw/unknown message
    #     symbols that no builder-name list can enumerate -- name matching alone is too brittle here.
    #
    #     This tests for NEWKEYS, NOT for "no sealed input": an input built with
    #     fn_encrypt_packet_aesgcm before any NEWKEYS is, from the receiver's side, just opaque
    #     bytes parsed as a plaintext packet -- it cannot key the peer. The earlier form
    #     (`not any(is_encrypted(...))`) therefore missed 5 traces in which the attacker sealed
    #     packets without ever sending NEWKEYS and the wolfSSH client still answered
    #     CHANNEL_OPEN_FAILURE while unkeyed; they fell to the auth_unexplained audit pile.
    if not any(message_of(_msg_node(n) or n) == "fn_new_keys" for _, n, _ in inp):
        return "known_wolfssh_client_accepts_preauth_connection_layer"
    return None


def _n_cve_client_auth_state(es, rl, inp, tl, tw):
    """libssh CLIENT enters the AUTHENTICATED state although the peer never sent USERAUTH_SUCCESS.

    Witness of CVE-2026-59847 with an authentication-state consequence: an attacker packet encrypted
    under a bogus key (e.g. key/IV literals instead of the derived schedule) fails its AES-GCM tag,
    libssh does not reject it (src/libcrypto.c checks EVP_DecryptFinal rc < 0, which never holds),
    decrypts garbage, and parses it as a control message. Observed on
    20260923-190740214-0137008569caef86, whose step-8 packet carries key/IV literals
    (fn_placeholder_32bytes | fn_channel_type_direct_tcpip) instead of the derived schedule: libssh logs
    `read type 52`, then "Authentication successful", then CHANNEL_OPEN. (The `padding=-88` in that log is
    a uint8_t printed with %hhd, i.e. 168 -- not malformed padding; libssh's padding check at
    packet.c:1387 is sound and is not part of this defect.)
    Scope note: this is an ILLUSTRATION of the same integrity defect reaching a control-plane decision,
    NOT an impact escalation. An attacker wanting to feed forged bytes to the client application would
    simply let authentication complete and then tamper with CHANNEL_DATA -- simpler, and it leaves the
    session alive, whereas after a forged SUCCESS the server is still in its auth loop and rejects the
    client's channel operations. No capability here is unavailable via plain post-auth tampering.
    """
    if rl != "Client":
        return None
    if not (any(m >= 80 for m in tl) and not any(m >= 80 for m in tw)):
        return None
    # (a) no USERAUTH_SUCCESS was ever sent, so libssh can only have decoded garbage as one
    if not any(message_of(n) == "fn_user_auth_success" for _, n, _ in inp):
        return "known_libssh_cve_2026_59847_client_enters_authenticated_state"
    # (b) a USERAUTH_SUCCESS was sent but its AES-GCM tag does not verify (wolfSSH rejects it at that
    #     very step); libssh accepts it and proceeds into the connection layer. Same defect.
    wf = fail_step(es, WOLFSSH)
    st = diff_status(es)
    werr = (st["second_status"] if st else es.put2().get("error")) or ""
    if ("gerr=-180" in werr and wf is not None
            and any(i == wf and message_of(n) == "fn_user_auth_success" for i, n, _ in inp)):
        return "known_libssh_cve_2026_59847_client_enters_authenticated_state"
    return None


def _n_rekey(es, rl, inp, tl, tw):
    # RFC 4253 s7.1: between sending KEXINIT (ordinal>=1) and NEWKEYS a party MUST NOT send
    # non-transport messages. Checked on each PUT's OWN emitted transcript, both roles.
    da = _da()
    r = "server" if rl == "Server" else "client"
    if da.RekeyWindowViolationC(WOLFSSH).check_condition(es):
        return f"known_wolfssh_{r}_sends_during_incomplete_rekey"
    if da.RekeyWindowViolationC(LIBSSH).check_condition(es):
        return f"known_libssh_{r}_sends_during_incomplete_rekey"
    return None


def _n_misc(es, rl, inp, tl, tw):
    da = _da()
    if da.InnerKnowledgeC(diff_contains="response_data: [Added(0, 0), Added(1, 0), Added(2, 0), Added(3, 22)").check_condition(es):
        return "known_wolfssh_1246_fwd_port_echo"
    names = {message_of(n) for _, n, _ in inp}
    if rl == "Server":
        if (da.InnerKnowledgeC(diff_contains="Added(AlignmentKey { channel: 0, msg_number: 81,").check_condition(es)
                and "fn_request_cancel_tcpip_forward" in "".join(r for _, _, r in inp)):
            return "harness_wolfssh_fwd_cancel_skips_allowlist"
        if (da.InnerKnowledgeC(diff_contains="Added(AlignmentKey { channel: 0, msg_number: 99,").check_condition(es)
                and "fn_channel_request" in names):
            return "harness_libssh_channel_request_types_unhandled"
        if (da.DifferentClaimC(in_first_type="()", in_second_type="alloc::boxed::Box<sshpuffin::claim::SshClaimInner>").check_condition(es)
                and da.ClaimContainsC(WOLFSSH, in_claim=r'auth_method: "publickey"').check_condition(es)
                and 51 in tw and 52 not in tw):
            return "harness_wolfssh_premature_auth_claim"
    return None


_NAMED = [_n_cve_client_auth_state, _n_preauth_conn, _n_core, _n_rekey, _n_misc]


def _uar_service(node):
    n = node if node.name == "fn_user_auth_request" else (node.children[0] if node.children else None)
    if n is None or n.name != "fn_user_auth_request" or len(n.children) < 2:
        return None
    return n.children[1].name


# ---------------------------------------------------------------- auth asymmetry guard
def auth_unexplained(es, rl, inp, tl, tw):
    """True iff the PUTs disagree on authentication and the side that did not authenticate had not
    already failed strictly before the attacker's auth step (so the disagreement is a decision,
    not a consequence of an earlier, differently-caused abort)."""
    # Compare against the LAST deciding message, not the first. A PUT's success can come from any of
    # several attempts, so a loser that died before the final attempt may simply never have seen the
    # request the winner succeeded on -- its own earlier verdict was about a different request.
    # (Witness: a trace where libssh correctly rejected attempt #1 as "invalid signature" and accepted
    # attempt #2, while wolfSSH rejected #1 and then died on an AEAD tag before #2 ever arrived.)
    def _last(pred):
        return next((i for i, n, _ in reversed(inp) if pred(n)), None)
    if rl == "Server":
        la, wa = 52 in tl, 52 in tw
        step = _last(lambda n: message_of(n) == "fn_user_auth_request")
    else:
        la, wa = any(m >= 80 for m in tl), any(m >= 80 for m in tw)
        step = _last(lambda n: message_of(n) == "fn_user_auth_success")
    if la == wa:
        return False
    loser = WOLFSSH if la else LIBSSH
    f = fail_step(es, loser)
    if step is None or f is None:
        return True
    return not (f < step)


# ---------------------------------------------------------------- AEAD cause
def _sig(node):
    return node.name + ("(" + ",".join(_sig(c) for c in node.children) + ")" if node.children else "")


def _keysig(node):
    """The key-schedule arguments of an fn_encrypt_packet_* call (all but the message and the counter)."""
    return "|".join(_sig(c) for c in node.children[1:-1])


def _counter(node):
    return node.children[-1].name if node.children else None


# ---- AES-GCM invocation counter --------------------------------------------------------------
# The 4th argument of fn_encrypt_packet_aesgcm is the AES-GCM INVOCATION COUNTER, not the SSH
# sequence number: fn_crypto.rs aesgcm_nonce() adds it to be64(iv[4..12]) (RFC 5647), and
# differential.rs renumber_aesgcm_counters() resets it to 0 at every NEWKEYS while the SSH
# sequence number keeps counting. A packet's counter is therefore its index since the last
# NEWKEYS -- 0 for the first encrypted packet.
#
# renumber_aesgcm_counters rewrites ONLY the fn_u32_auto sentinel; an explicit atom is left as
# authored. So an explicit counter is wrong only when its VALUE differs from that true index --
# and the mutator does sometimes slot in an atom that happens to be right (fn_u32_0 on the first
# encrypted packet). Measured over all 800,055 AEAD objectives: 107 such traces, 92 of them in
# the *_literal_seq_counter buckets, i.e. traces the old "any non-sentinel counter" rule named
# after a counter that was in fact correct. Hence the value check below.
_AUTO_FN = "fn_u32_auto"
_ENC_FN = "fn_encrypt_packet_aesgcm"
_U32_LITERAL = re.compile(r"^fn_u32_(\d+)$")
U32_AUTO_SENTINEL = 0xFFFFFFFF - 1  # fn_constants.rs: u32::MAX - 1
# u32-typed atoms the mutator can slot into the counter position, with their values.
_U32_CONST = {
    "fn_port_ssh": 22,
    "fn_u32_0x10000": 0x10000,
    "fn_u32_max": 0xFFFFFFFF,
    "fn_disconnect_reason_protocol_error": 2,
    "fn_disconnect_reason_service_not_available": 7,
}


# u32 accessors the mutator can slot into the counter position. Both fn_channel_open and
# fn_channel_open_confirmation take (.., .., initial_window_size, maximum_packet_size, data), so
# the field is statically known whenever the message argument is itself a literal builder
# (fn_message.rs: fn_initial_window_size / fn_channel_send_budget).
_WINDOW_MSGS = ("fn_channel_open", "fn_channel_open_confirmation")


def _counter_value(node, nested=False):
    """The u32 the counter term evaluates to, or None if not statically evaluable.

    `nested` matters for the sentinel: renumber_aesgcm_counters rewrites the counter argument
    only when fn_u32_auto is its ROOT. Buried inside a computed term (e.g.
    fn_initial_window_size(fn_channel_open(.., fn_u32_auto, ..))) the pass does not match it, so
    the sentinel's raw value u32::MAX-1 is used as the invocation counter -- a guaranteed wrong
    nonce. Measured: 6 of the AEAD `unexplained` pile fail exactly this way."""
    if node is None:
        return None
    if not node.children:
        if node.name == _AUTO_FN:
            return U32_AUTO_SENTINEL if nested else None
        m = _U32_LITERAL.match(node.name)
        return int(m.group(1)) if m else _U32_CONST.get(node.name)
    if node.name in ("fn_initial_window_size", "fn_channel_send_budget"):
        msg = node.children[0]
        if msg.name not in _WINDOW_MSGS or len(msg.children) < 4:
            return None
        win = _counter_value(msg.children[2], nested=True)
        if node.name == "fn_initial_window_size":
            return win
        pkt = _counter_value(msg.children[3], nested=True)
        return None if win is None or pkt is None else min(win, pkt)
    return None


def _outermost_enc(node):
    """Pre-order search for the outermost fn_encrypt_packet_aesgcm (find_outermost_aesgcm_path)."""
    if node.name == _ENC_FN:
        return node
    for c in node.children:
        r = _outermost_enc(c)
        if r is not None:
            return r
    return None


def true_counters(status):
    """{step_number: true AES-GCM invocation counter}, replaying renumber_aesgcm_counters
    (sshpuffin/src/ssh/differential.rs) over the per-PUT replay: per agent, +1 per encrypted
    packet, reset to 0 after a NEWKEYS (plaintext one, or an encrypted one after its own count)."""
    counters, out = {}, {}
    for s in status["execution"]["steps"]:
        a = s.get("action")
        if not (isinstance(a, dict) and a.get("Input")):
            continue
        root = parse_term(a["Input"].get("recipe") or "")
        agent = s.get("agent")
        c = counters.get(agent, 0)
        enc = _outermost_enc(root)
        if enc is not None:
            out[s["step_number"]] = c
            c += 1
            if enc.children and enc.children[0].name == "fn_new_keys":
                c = 0
        elif root.name == "fn_packet" and root.children and root.children[0].name == "fn_new_keys":
            c = 0
        counters[agent] = c
    return out


def counter_verdict(es, inp, fail_step_no):
    """Verdict on the AES-GCM invocation counter of the packet wolfSSH rejected:

      "ok"       sentinel at the root (renumber_aesgcm_counters always sets it correctly), or an
                 explicit value that equals the packet's true index -- the counter is not the cause
      "wrong"    an explicit / statically-evaluable value that differs from the true index
      "computed" the counter is a term computed from a QUERIED message (e.g.
                 fn_channel_send_budget(fn_decrypted_message(..))), so it evaluates to a channel
                 window or packet size rather than an invocation index. Not decidable from the term
                 alone; verified by execution (PUFFIN_DUMP_KEY) on 100% of the affected population
                 that the value used is never the true index.
    """
    node = next((n for i, n, _ in inp if i == fail_step_no), None)
    enc = _outermost_enc(node) if node is not None else None
    if enc is None or len(enc.children) < 4:
        return "ok"
    ctr = enc.children[3]
    if ctr.name == _AUTO_FN:
        return "ok"                      # rewritten by the renumbering pass
    v = _counter_value(ctr)
    if v is None:
        return "computed"
    return "wrong" if v != true_counters(es.put1()).get(fail_step_no) else "ok"


_DERIVE_KEY = ("fn_derive_aes_key_c2s", "fn_derive_aes_key_s2c")
_DERIVE_IV = ("fn_derive_iv_c2s", "fn_derive_iv_s2c")


def _find1(node, name):
    if node.name == name:
        return node
    for c in node.children:
        r = _find1(c, name)
        if r is not None:
            return r
    return None


def broken_key_schedule_term(es, inp, fail_step_no):
    """True iff the rejected packet's key/IV schedule is broken ON THE FACE OF THE TERM, so the
    derived key cannot match the peer's whatever the peer did. Any of:

      * the key or IV slot is not a derivation at all (a raw constant, a public key, a queried
        byte string, even a channel-type or command string, substituted directly as the AES key);
      * no exchange hash anywhere in that slot's schedule;
      * the derivation direction contradicts the attacker's role (a Server-role trace, i.e. an
        attacker acting as client, must seal c2s);
      * the shared secret handed to derive() is a different term from the K inside that same
        derivation's own exchange hash -- so H can match the peer's while the key does not. This
        is the shape that let 8 traces pass an H-vs-session_id check in the 2026-09-23 campaign;
      * key and IV are derived from different exchange hashes.

    Distinct from `mutated_key_schedule`, which compares the key-schedule SIGNATURE against forms
    wolfSSH accepted elsewhere in the corpus: these traces pass that reference check and are still
    plainly broken, which is why they used to land in the `unexplained` audit pile."""
    node = next((n for i, n, _ in inp if i == fail_step_no), None)
    enc = _outermost_enc(node) if node is not None else None
    if enc is None or len(enc.children) < 3:
        return False
    want = "c2s" if role(es) == "Server" else "s2c"
    key, iv = enc.children[1], enc.children[2]
    if key.name not in _DERIVE_KEY or iv.name not in _DERIVE_IV:
        return True
    if not key.name.endswith(want) or not iv.name.endswith(want):
        return True
    hk, hi = _find1(key, "fn_kex_exchange_hash"), _find1(iv, "fn_kex_exchange_hash")
    if hk is None or hi is None:
        return True
    if _sig(hk) != _sig(hi):
        return True
    for d, xh in ((key, hk), (iv, hi)):
        if len(xh.children) > 7 and d.children and _sig(d.children[0]) != _sig(xh.children[7]):
            return True
    return False


def stale_pre_rekey_schedule(es, inp, fail_step_no):
    """RFC 4253 7.2/7.3: after NEWKEYS both sides MUST take the new keys into use, and those keys
    come from the NEW exchange hash H' (only session_id stays the first H). True iff the rejected
    packet reuses a key-schedule term that appears only BEFORE the last NEWKEYS -- i.e. the
    attacker kept sealing under the pre-rekey schedule while the PUT had rotated.

    Note this is invisible to an "attacker H == PUT session_id" check, because the stale H *is*
    the session id."""
    nks = [i for i, n, _ in inp if message_of(_msg_node(n) or n) == "fn_new_keys" and i < fail_step_no]
    if len(nks) < 2:
        return False
    last_nk = max(nks)
    fail = next((n for i, n, _ in inp if i == fail_step_no), None)
    if fail is None or not is_encrypted(fail):
        return False
    fsig = _keysig(fail)
    pre = [_keysig(n) for i, n, _ in inp if is_encrypted(n) and i < last_nk]
    post = [_keysig(n) for i, n, _ in inp if is_encrypted(n) and last_nk < i < fail_step_no]
    return fsig in pre and fsig not in post


def _abstract_arg(node):
    sig = _sig(node)
    return node.name + ("[Q]" if "(Some(Agent" in sig else "[L]")


def hash_pattern(enc_node):
    """Abstracted argument pattern of the fn_kex_exchange_hash inside an fn_encrypt_packet_* term:
    for each argument, its head function plus whether it is an agent QUERY [Q] (a value really
    exchanged with the peer) or a LITERAL [L] builder. A wrong-key packet usually shows up here as a
    [Q] replaced by an [L] (e.g. the shared secret computed from a constant) or as the wrong slot."""
    st = [enc_node]
    while st:
        n = st.pop()
        if n.name == "fn_kex_exchange_hash":
            return tuple(_abstract_arg(c) for c in n.children)
        st.extend(n.children)
    return None


_HASH_REF = None


def _accepted_hash_patterns():
    global _HASH_REF
    if _HASH_REF is None:
        import json, os
        path = os.path.join(os.path.dirname(__file__), "aead_accepted_hash_patterns.json")
        try:
            with open(path) as fh:
                _HASH_REF = {(rl, tuple(p)) for rl, p, _c in json.load(fh)}
        except FileNotFoundError:
            _HASH_REF = set()
    return _HASH_REF


_ACCEPTED = None


def _accepted_keysigs():
    """Key-schedule forms wolfSSH successfully decrypted somewhere in the corpus (aead_accepted_keysigs.json,
    built from a 40,000-trace random sample: every encrypted packet strictly before wolfSSH's failure step).
    A rejected packet whose form is NOT in this set uses a key schedule that never yields a valid key.
    Caveat: a legitimate but rare form absent from the sample would be counted as mutated."""
    global _ACCEPTED
    if _ACCEPTED is None:
        import json, os
        with open(os.path.join(os.path.dirname(__file__), "aead_accepted_keysigs.json")) as fh:
            _ACCEPTED = {(r, s) for r, s, _n in json.load(fh)}
    return _ACCEPTED


def aead_cause(es, inp):
    """Why wolfSSH's AES-GCM tag check failed. The attacker packet up to wolfSSH's failure step is
    compared with the trace's other encrypted packets as TERM TREES (key/IV arguments)."""
    wf = fail_step(es, WOLFSSH)
    if wf is None:
        return "unexplained"
    nk = _first(inp, lambda n: n.name == "fn_packet" and message_of(n) == "fn_new_keys")
    if nk is not None and any(nk < i <= wf and not is_encrypted(n) and n.name != "fn_banner" for i, n, _ in inp):
        return "plaintext_after_newkeys"
    enc = [(i, n) for i, n, _ in inp if is_encrypted(n)]
    upto = [(i, n) for i, n in enc if i <= wf]
    if not upto:
        return "unexplained"
    cv = counter_verdict(es, inp, wf)
    if cv == "wrong":
        return "wrong_invocation_counter"
    if cv == "computed":
        return "computed_counter_term"
    if stale_pre_rekey_schedule(es, inp, wf):
        return "stale_pre_rekey_schedule"
    f_i, f_n = upto[-1]
    if (role(es), _keysig(f_n)) not in _accepted_keysigs():
        return "mutated_key_schedule"
    # The term SHAPE is one wolfSSH accepts, but the exchange hash feeding this packet's keys is
    # computed from a non-canonical argument pattern: at least one input is a literal where the
    # canonical computation uses the value actually exchanged with the peer (or occupies the wrong
    # slot). The derived key therefore cannot match the peer's -- consistent with wolfSSH's rejection.
    hp = hash_pattern(f_n)
    ref = _accepted_hash_patterns()
    if hp is not None and ref and (role(es), hp) not in ref:
        return "non_canonical_exchange_hash"
    others = [_keysig(n) for i, n in enc if i != f_i]
    if others:
        from collections import Counter
        canon = Counter(others).most_common(1)[0][0]
        if _keysig(f_n) != canon:
            return "mutated_key_schedule"
    # LAST, deliberately: a structural defect visible on the face of the term. Checked only after
    # the reference-set causes above, because it OVERLAPS them heavily -- placed earlier it pulls
    # ~259,000 traces out of `mutated_key_schedule`, re-describing an already-established cause
    # rather than explaining anything new. Here it rescues exactly the traces that would otherwise
    # fall through unexplained: the schedule passes every reference check and is still plainly
    # broken (861 of the 862 such traces in the 09-23 corpus).
    if broken_key_schedule_term(es, inp, wf):
        return "broken_key_schedule_term"
    return "unexplained"


_REPLIES = {
    "Server": {"fn_service_request": {6}, "fn_user_auth_request": {51, 52, 60}, "fn_channel_open": {91, 92},
               "fn_global_request": {81, 82}, "fn_channel_request": {99, 100}},
    "Client": {"fn_service_accept": {50}, "fn_user_auth_success": {90}},
}


def libssh_continued(es, rl, inp, tl):
    """libssh answered a request type that the attacker first sent AFTER the packet wolfSSH rejected,
    i.e. libssh kept processing the stream past that packet."""
    wf = fail_step(es, WOLFSSH)
    if wf is None:
        return False
    table = _REPLIES["Server" if rl == "Server" else "Client"]
    before = {message_of(n) for i, n, _ in inp if i <= wf}
    for i, n, _ in inp:
        m = message_of(n)
        if i > wf and m in table and m not in before and table[m] & tl:
            return True
    return False


# ---------------------------------------------------------------- the key
_ORD = re.compile(r"AlignmentKey \{ channel: (\d+), msg_number: (\d+), ordinal: (\d+) \}")


def _order(status):
    """The PUT's own decrypted transcript as an ordered list of (msg_number, ordinal); None if it has none."""
    for e in status["execution"].get("extra_knowledges", []):
        v = e[1] if len(e) > 1 else ""
        if v.startswith("AlignedTranscript"):
            i = v.find("order:")
            if i >= 0:
                return [(int(m), int(o)) for _c, m, o in _ORD.findall(v[i:])]
    return None


def _shape(es):
    """Transcript-only divergence keyed by its FIRST point in time: walk both PUTs' decrypted transcripts in
    order and report the first position where they differ -- 'L<n>/W<m>' (libssh sent message n where wolfSSH
    sent m; '-' = nothing more), prefixed 'reorder:' when both transcripts hold the same message multiset.
    If the orders are identical the divergence is a CONTENT change: 'C<n>' for the earliest changed message.
    A missing transcript on one side is reported as its type difference ('T:...')."""
    for e in es.errors or []:
        k = e.get("Knowledges") or {}
        if "DifferentTypes" in k:
            dt = k["DifferentTypes"]
            return "T:" + dt["first_type"].split("::")[-1] + "/" + dt["second_type"].split("::")[-1]
    lo, wo = _order(es.put1()), _order(es.put2())
    if lo is None or wo is None:
        return "no_transcript"
    for i in range(max(len(lo), len(wo))):
        a = lo[i] if i < len(lo) else None
        b = wo[i] if i < len(wo) else None
        if a != b:
            # rekey handshake (KEX message of a SECOND key exchange, ordinal >= 1) progressing differently
            if any(x is not None and x[0] in (20, 21, 30, 31) and x[1] >= 1 for x in (a, b)):
                return "rekey_progress"
            # a further USERAUTH_REQUEST attempt by one client only (retry policy)
            if any(x is not None and x[0] == 50 and x[1] >= 1 for x in (a, b)):
                return "auth_retry_count"
            pre = "reorder:" if sorted(lo) == sorted(wo) else ""
            return f"{pre}L{a[0] if a else '-'}/W{b[0] if b else '-'}"
    changed = set()
    for e in es.errors or []:
        d = ((e.get("Knowledges") or {}).get("InnerDifference") or {}).get("diff", "")
        changed.update(int(m) for op, m in _OP.findall(d) if op == "Changed")
    first = next((m for m, _o in lo if m in changed), None)
    return f"C{first}" if first is not None else "same_order_other"


def root_cause_key(es):
    cached = getattr(es, "_rc_key", None)
    if cached is not None:
        return cached
    rl = role(es)
    r = "server" if rl == "Server" else "client"
    inp = inputs(es.put1())
    tl, tw = transcript(es.put1()), transcript(es.put2())
    key = None
    nms = named_mechanisms(es, rl, inp, tl, tw)
    es._rc_named = nms
    if nms:
        key = "named:" + nms[0]
    elif auth_unexplained(es, rl, inp, tl, tw):
        key = f"auth_unexplained:{r}"
    else:
        st = diff_status(es)
        if st is not None:
            f, s = st["first_executed_steps"], st["second_executed_steps"]
            side = "L" if f < s else "W" if s < f else "="
            if side == "W" and "gerr=-180" in st["second_status"]:
                # evidence strength only (NOT part of the key): libssh visibly kept processing
                es._rc_libssh_continued = libssh_continued(es, rl, inp, tl)
                key = f"aead:{r}:{aead_cause(es, inp)}"
            elif side == "=":
                key = f"status:{r}:=:{error_class(st['first_status'])}|{error_class(st['second_status'])}"
            else:
                key = f"status:{r}:{side}:{error_class(st['first_status'] if side == 'L' else st['second_status'])}"
        else:
            cl = next((e["Claims"]["DifferentTypes"] for e in es.errors or []
                       if "Claims" in e and "DifferentTypes" in e["Claims"]), None)
            if cl is not None:
                side = "L" if cl["first_type"] == "()" else "W"
                err = es.put1().get("error") if side == "L" else es.put2().get("error")
                key = f"claim:{r}:{side}:{error_class(err)}"
            else:
                key = f"shape:{r}:{_shape(es)}"
    es._rc_key = key
    return key
