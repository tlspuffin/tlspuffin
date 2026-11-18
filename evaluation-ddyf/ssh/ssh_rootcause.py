"""Root-cause keying for the libssh-vs-wolfSSH differential triage.

Every objective is mapped to ONE root-cause key: the observable FIRST divergence between the
two PUTs, qualified by the PUT's role. Buckets in sort_objectives_libssh_wolfssh.py are then
"all traces with key K" (see RootCauseC), so a bucket holds exactly one observable cause.

Key families, in precedence order (first applicable wins; see root_cause_key()):

  named:<mechanism>        a documented mechanism recognised semantically (_NAMED)
  auth_unexplained:<role>  the two PUTs disagree on authentication and the disagreement is NOT a
                           consequence of the non-authenticating side having already died before
                           the step the other authenticated on -> audit pile, never benign
  aead:<role>:<cause>[:unconfirmed]
                           wolfSSH fails on an AES-GCM tag (wolfSSH error -180) before libssh
                           fails, or at the same step; <cause> (aead_cause) in
                           {plaintext_after_newkeys, wrong_invocation_counter,
                           computed_counter_term, stale_pre_rekey_schedule, wrong_exchange_hash,
                           broken_key_schedule_term, mutated_key_schedule, unexplained};
                           ":unconfirmed" unless the trace shows libssh accepting that packet
                           (libssh_accepted): libssh got past it although its own run shows that the
                           packet cannot verify under libssh's keys either (invalid_for_libssh)
  status:<role>:<side>:<error-class>
                           execution-status divergence; <side> = the PUT that failed FIRST in the
                           differential run (L, W, or '=' for the same step, then the class is
                           "<libssh class>|<wolfSSH class>"); error class of that PUT (error_class)
  claim:<role>:<side>:<error-class>
                           no status divergence; exactly one PUT finalised KEX (emitted its claim);
                           <side> = the PUT that did NOT, keyed by that PUT's own error class
  shape:<role>:<shape>     transcript-only divergence, keyed by the first position at which the two
                           decrypted transcripts differ (_shape): "L<m>.<o>/W<m>.<o>" = libssh sent
                           message number <m> (its <o>-th such message, from 0) where wolfSSH sent
                           its own, "-" for no further message, prefixed "reorder:" when both hold
                           the same messages overall; "C<m>" = same messages in the same order, the
                           first whose content differs being <m>; "rekey_progress";
                           "auth_retry_count"; "T:<type>/<type>"; "no_transcript";
                           "same_order_other"

Everything is computed from the objective's cached DIFFERENTIAL record (metadata_diff_*.json,
the oracle the objective was selected on) plus the two uniformised per-PUT replays (for the
decrypted transcripts, the attacker recipe, each PUT's own error and claims, and the values the
attacker's precomputations evaluated to).
"""
import re

LIBSSH, WOLFSSH = 1, 2
_OP = re.compile(r"(Added|Removed|Changed)\(AlignmentKey \{ channel: \d+, msg_number: (\d+)")
_KEY = re.compile(r"AlignmentKey \{ channel: \d+, msg_number: (\d+), ordinal: \d+ \}")


# ---------------------------------------------------------------- attacker recipe parsing
class Node:
    __slots__ = ("name", "children", "label")

    def __init__(self, name, label=None):
        self.name = name
        self.children = []
        # (label, n) when the node stands for the n-th value bound to a precomputation label,
        # which a sealed step refers to by a variable (see inputs())
        self.label = label


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


# A variable of a sealed step: `(Some(Label(Some("c2s_key_0@1"))), 0)[None]/SshBytes` is the 0-th
# value bound to the label c2s_key_0@1.
_LABEL_VAR = re.compile(r'^\(Some\(Label\(Some\("([^"]*)"\)\)\), (\d+)\)')


def _bind(node, bindings):
    """`node` with each label variable replaced by the term bound to it. puffin answers the query
    (label, n) with the n-th value bound to that label so far, in execution order; each sealed
    step binds its precomputations again, after the earlier steps' (find_variable)."""
    if not node.children:
        m = _LABEL_VAR.match(node.name)
        if m:
            bound = bindings.get(m.group(1), [])
            n = int(m.group(2))
            if n < len(bound):
                out = Node(bound[n].name, (m.group(1), n))
                out.children = bound[n].children
                return out
        return node
    out = Node(node.name, node.label)
    out.children = [_bind(c, bindings) for c in node.children]
    return out


def inputs(status):
    """[(step_number, root Node, recipe text)] of the attacker inputs, from a per-PUT replay.

    A sealed step names its keys by label variables, bound by its precomputations: the variables
    are replaced by the terms bound to them, so that a packet's key schedule reads as one term, as
    an unsealed step writes it. The recipe text is the stored one."""
    out, bindings = [], {}
    for s in status["execution"]["steps"]:
        a = s.get("action")
        if isinstance(a, dict) and a.get("Input"):
            step = a["Input"]
            # evaluated in order, each bound before the next (InputAction::execute_precomputations)
            for label, text in step.get("precomputations") or []:
                bindings.setdefault(label, []).append(_bind(parse_term(text), bindings))
            r = step.get("recipe") or ""
            out.append((s["step_number"], _bind(parse_term(r), bindings), r))
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


_WS_FATAL_ERROR = -1001


def wolfssh_code(err):
    """The wolfSSH error code of a status string, None if it carries none. The harness writes
    "<name> (rc=<rc> gerr=<gerr>)": the code is gerr when rc is WS_FATAL_ERROR, which leaves the
    cause to wolfSSH_get_error(), and rc itself otherwise (gerr can then be an earlier call's)."""
    if not err:
        return None
    m = re.search(r"rc=(-?\d+) gerr=(-?\d+)", err)
    if m:
        rc, gerr = int(m.group(1)), int(m.group(2))
        return gerr if rc == _WS_FATAL_ERROR else rc
    m = re.search(r"gerr=(-?\d+)", err)
    return int(m.group(1)) if m else None


def error_class(err):
    """Normalise a status/error string to its check (wolfSSH error code, libssh message, mapper kind)."""
    if err is None or err == "Success":
        return "success"
    e = err.replace("error in PUT : ", "")
    code = wolfssh_code(e)
    if code is not None:
        return "wolfssh_gerr" + str(abs(code))
    if e.startswith("error executing a function symbol"):
        m = re.search(r"rustls: (no message \d+|Expected [\w:]+|no CHANNEL_OPEN_CONFIRMATION|peer public key|Passed argument|"
                      r"AES-GCM key|AES-GCM IV|AES-CTR key|AES-CTR IV|no message)", e)
        k = m.group(1) if m else "other"
        k = re.sub(r"no message \d+", "no_message", k)
        return "mapper_" + re.sub(r"\W+", "_", k).strip("_").lower()
    if e.startswith("error evaluating a term"):
        return "mapper_unbound_variable"
    # the libssh harness reports a session that ended in an error as "SESSION_ERROR: <libssh's error>"
    e = re.sub(r"^SESSION_ERROR: ", "", e)
    if e.startswith("Packet filter"):
        return "libssh_packet_filter"
    if "Packet len too high" in e:
        return "libssh_packet_len_too_high"
    if e.startswith("Received SSH_MSG_DISCONNECT"):
        return "libssh_received_disconnect"
    if e.startswith("kex error"):
        m = re.search(r"no match for method ([\w >-]+?)(:|$)", e)
        return "libssh_kex_no_match_" + re.sub(r"\W+", "_", m.group(1) if m else "x").strip("_")
    if e.startswith("Socket error"):
        # libssh closes the socket when it fails the session, and a later poll of it reports a
        # socket error, with an errno left by an unrelated call ("File exists"): the text says
        # nothing about the cause, only the peer's EOF does.
        return "libssh_socket_error" + ("_disconnected" if e.startswith("Socket error: disconnected") else "")
    # The whole message without its values: "Receiving banner: too large banner" is not another
    # "Receiving banner: ..." check, while "Invalid padding: 200 (12 left)" is "Invalid padding".
    msg = re.sub(r"\([^)]*\)", "", re.sub(r"\d+", "", e))
    return "libssh_" + (re.sub(r"\W+", "_", msg).strip("_").lower()[:60] or "empty_error")


# ---------------------------------------------------------------- named mechanisms
def _first(inp, pred):
    return next((i for i, n, _ in inp if pred(n)), None)


# (trace, classifier, error) of each classifier that raised: reported at the end of a sort
# (sort_objectives_libssh_wolfssh.py), and the trace stays out of every bucket.
CLASSIFIER_ERRORS = []


def named_mechanisms(es, rl, inp, tl, tw):
    """All documented mechanisms this trace exhibits, in precedence order (first = its bucket).
    A classifier that raises is not taken for "no mechanism": the error is recorded and raised
    again, so the trace stays unbucketed instead of falling to a later family."""
    out = []
    for fn in _NAMED:
        try:
            m = fn(es, rl, inp, tl, tw)
        except Exception as e:
            CLASSIFIER_ERRORS.append((getattr(es, "filepath", "?"), fn.__name__, repr(e)))
            raise
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
    st = diff_status(es)
    wf = fail_step(es, WOLFSSH)
    werr = (st["second_status"] if st else es.put2().get("error")) or ""
    wcode = wolfssh_code(werr)
    # repeated SERVICE_REQUEST before auth: wolfSSH aborts ("Message ID 5 not allowed by server after
    # starting user auth", gerr=-1094) while libssh answers it again.
    # The abort may land on a SERVICE_REQUEST sent before OR after the first auth request (in the latter
    # case libssh has answered the auth in between, which is the same mechanism, not an auth divergence).
    if (wcode == -1094 and wf is not None
            and any(i == wf and message_of(n) == "fn_service_request" for i, n, _ in inp)
            and sum(1 for i, m in msgs if m == "fn_service_request" and i <= wf) >= 2):
        return "known_wolfssh_repeated_service_request_fatal"
    # The USERAUTH_REQUEST packet itself fails wolfSSH's AES-GCM tag check (wrong key/nonce) and libssh
    # authenticates on it: libssh ignores the tag failure (CVE-2026-59847, EVP_DecryptFinal rc < 0).
    # The witness is that libssh ACTED on a packet whose tag cannot verify under libssh's keys either
    # (invalid_for_libssh: a packet wrong for wolfSSH only may verify for libssh, and libssh then
    # authenticates rightly). Which AES-GCM cause made the key wrong is a sub-cause: it does not narrow
    # the class.
    if (wcode == -180 and wf is not None and 52 in tl and 52 not in tw
            and any(i == wf and message_of(n) == "fn_user_auth_request" for i, n, _ in inp)
            and invalid_for_libssh(es, inp, aead_cause(es, inp), wf)):
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
    if (wcode == -1089 and 52 in tl and 52 not in tw and wf is not None
            and any(i == wf and message_of(_msg_node(n) or n) == "fn_ext_info" for i, n, _ in inp)):
        return "known_wolfssh_aborts_on_unusable_server_sig_algs"
    # wolfSSH's USERAUTH_REQUEST parser refuses a malformed/mutated request (bad buffer size, bad argument,
    # overflow) ON THAT VERY STEP, while libssh's parser tolerates it and authenticates. Parser-strictness
    # divergence at the auth step: libssh's ssh_packet_userauth_request() frees the message and returns
    # SSH_PACKET_USED on a parse error (messages.c error: label), i.e. it silently ignores the malformed
    # request and keeps the connection alive for the next, well-formed one, which it then authenticates.
    if (wcode in (-1004, -1002, -1007) and wf is not None
            and any(i == wf and message_of(n) == "fn_user_auth_request" for i, n, _ in inp)
            and 52 in tl and 52 not in tw):
        return "diverge_wolfssh_rejects_malformed_userauth_libssh_accepts"
    return None


def _da():
    from .. import diff_analyzer
    return diff_analyzer


# The builders of the connection-layer messages (RFC 4254, numbers 80 to 100), fn_message.rs.
_CONN_BUILDERS = ("fn_global_request", "fn_request_success", "fn_request_failure", "fn_channel_open",
                  "fn_channel_open_confirmation", "fn_channel_open_failure", "fn_channel_window_adjust",
                  "fn_channel_data", "fn_channel_extended_data", "fn_channel_eof", "fn_channel_close",
                  "fn_channel_request", "fn_channel_success", "fn_channel_failure")


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
    decrypts garbage, and parses it as a control message. Observed in the 2026-09-23 campaign on a
    trace whose step-8 packet carries key/IV literals (fn_placeholder_32bytes |
    fn_channel_type_direct_tcpip) instead of the derived schedule: libssh logs `read type 52`, then
    "Authentication successful", then CHANNEL_OPEN. (The `padding=-88` in that log is a uint8_t
    printed with %hhd, i.e. 168, which the packet's 192 bytes allow: the garbage passed libssh's padding
    check, which is sound and is not part of this defect.)
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
    #     very step), nor under libssh's keys (invalid_for_libssh); libssh accepts it and proceeds into
    #     the connection layer. Same defect.
    wf = fail_step(es, WOLFSSH)
    st = diff_status(es)
    werr = (st["second_status"] if st else es.put2().get("error")) or ""
    if (wolfssh_code(werr) == -180 and wf is not None
            and any(i == wf and message_of(n) == "fn_user_auth_success" for i, n, _ in inp)
            and invalid_for_libssh(es, inp, aead_cause(es, inp), wf)):
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


# wolfssh#1246: one side's REQUEST_SUCCESS carries the 4 bytes of a port, the other's no data.
_PORT_ECHO = re.compile(r"response_data: \[(Added|Removed)\(0, \d+\), \1\(1, \d+\), \1\(2, \d+\), "
                        r"\1\(3, \d+\)\]")


# Channel request types wolfSSH 1.5.0 recognises (DoChannelRequest), as the signature's atoms.
_WOLFSSH_CHANNEL_REQUESTS = ("fn_channel_exec", "fn_channel_shell", "fn_channel_pty_req")


def _channel_request_types(inp):
    """The request-type terms of the attacker's CHANNEL_REQUESTs."""
    out = []
    for _, n, _ in inp:
        m = _msg_node(n)
        if m is not None and m.name == "fn_channel_request" and len(m.children) > 1:
            out.append(m.children[1])
    return out


def _n_misc(es, rl, inp, tl, tw):
    # wolfSSH 1.5.0 answers CHANNEL_SUCCESS to a channel request type it does not recognise:
    # DoChannelRequest replies SendChannelSuccess(.., ret == WS_SUCCESS && !rej) and no branch
    # handles an unknown type, while RFC 4254 5.4 returns CHANNEL_FAILURE for one, as libssh does.
    # wolfSSH 1.6.0 rejects it ("unknown channel request type, rejecting"). The first divergence
    # is that answer, and the trace asks for a type outside wolfSSH's list.
    if rl == "Server" and re.match(r"(reorder:)?L100\.\d+/W99\.\d+$", _shape(es)):
        if any(not t.children and t.name not in _WOLFSSH_CHANNEL_REQUESTS for t in _channel_request_types(inp)):
            return "known_wolfssh_unrecognised_channel_request_answered_success"
    # wolfssh#1246, when it is the trace's only difference (whatever the port, whichever PUT is
    # first): another difference next to it is keyed on its own.
    diffs = es.errors or []
    if len(diffs) == 1:
        d = ((diffs[0].get("Knowledges") or {}).get("InnerDifference") or {}).get("diff", "")
        if ("BothRequestSuccess" in d and _PORT_ECHO.search(d) and d.count("Changed(AlignmentKey") == 1
                and "Added(AlignmentKey" not in d and "Removed(AlignmentKey" not in d):
            return "known_wolfssh_1246_fwd_port_echo"
    return None


# The census of the 2026-09-23 corpus also named four gaps of the harnesses of the time, which
# have since been fixed (harness_libssh_service_request_name_not_checked,
# harness_libssh_channel_request_types_unhandled, harness_wolfssh_fwd_cancel_skips_allowlist,
# harness_wolfssh_premature_auth_claim). A trace of one of these shapes is now a divergence of the
# libraries, keyed as any other.
_NAMED = [_n_cve_client_auth_state, _n_preauth_conn, _n_core, _n_rekey, _n_misc]


def _uar_service(node):
    n = node if node.name == "fn_user_auth_request" else (node.children[0] if node.children else None)
    if n is None or n.name != "fn_user_auth_request" or len(n.children) < 2:
        return None
    return n.children[1].name


# ---------------------------------------------------------------- auth asymmetry guard
def _auth_claim_step(status):
    """The first step at which the PUT's claims name an authentication method, None if none does
    (a client's claims never do)."""
    for s in status["execution"]["steps"]:
        if any(re.search(r'auth_method: "[^"]', str(c)) for c in s.get("claims") or []):
            return s["step_number"]
    return None


def auth_unexplained(es, rl, inp, tl, tw):
    """True iff the PUTs disagree on authentication and the side that did not authenticate had not
    already failed strictly before the step the other one authenticated on (so the disagreement is
    a decision, not a consequence of an earlier, differently-caused abort).

    That step is the one at which the winner's claims first name an authentication method, which a
    server's do from its USERAUTH_SUCCESS on: a loser that died before it never saw the request the
    winner accepted, whichever attempt that was. A client's claims name no method, so for it the
    step is the first USERAUTH_SUCCESS of the trace (to a server without such a claim, the first
    USERAUTH_REQUEST). That errs toward the audit pile: a loser that died between two attempts is not
    excused, where the last attempt would excuse one that rejected an earlier attempt the winner
    accepted."""
    if rl == "Server":
        la, wa = 52 in tl, 52 in tw
        deciding = "fn_user_auth_request"
    else:
        la, wa = any(m >= 80 for m in tl), any(m >= 80 for m in tw)
        deciding = "fn_user_auth_success"
    if la == wa:
        return False
    winner, loser = (LIBSSH, WOLFSSH) if la else (WOLFSSH, LIBSSH)
    f = fail_step(es, loser)
    step = _auth_claim_step(es.put1() if winner == LIBSSH else es.put2())
    if step is None:
        step = _first(inp, lambda n: message_of(n) == deciding)
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
# The u32 atoms the mutator can slot into the counter position, with their values: every nullary
# u32 atom of the signature but fn_u32_<n> and fn_u32_auto (test_ssh_rootcause.py checks them
# against the Rust sources).
_U32_CONST = {
    "fn_port_ssh": 22,
    "fn_u32_0x10000": 0x10000,
    "fn_u32_max": 0xFFFFFFFF,
    "fn_window_size_default": 2 * 1024 * 1024,
    "fn_max_packet_size_default": 32 * 1024,
    "fn_extended_data_stderr": 1,
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

      "ok"       the sentinel at the root of a packet among the first 16 of its key epoch, which
                 renumber_aesgcm_counters sets to its index, or an explicit value that equals the
                 packet's true index -- the counter is not the cause
      "wrong"    an explicit / statically-evaluable value that differs from the true index, or the
                 sentinel at the root of a later packet: renumber_aesgcm_counters has atoms for
                 0..15 only and leaves it, so its own value u32::MAX-1 is used
      "computed" the counter is a term computed from a QUERIED message (e.g.
                 fn_channel_send_budget(fn_decrypted_message(..))), so it evaluates to a channel
                 window or packet size rather than an invocation index. Not decidable from the term
                 alone (in the 2026-09-23 campaign, the counters these packets were sealed with were
                 dumped by an instrumented build: none was the packet's index).
    A sentinel whose payload a bit-level mutation changed is not renumbered either; the replay does
    not show payloads, so such a packet is judged as an unmutated sentinel.
    """
    node = next((n for i, n, _ in inp if i == fail_step_no), None)
    enc = _outermost_enc(node) if node is not None else None
    if enc is None or len(enc.children) < 4:
        return "ok"
    ctr = enc.children[3]
    index = true_counters(es.put1()).get(fail_step_no)
    if ctr.name == _AUTO_FN and not ctr.children:
        return "ok" if index is not None and index < 16 else "wrong"
    v = _counter_value(ctr)
    if v is None:
        return "computed"
    return "wrong" if v != index else "ok"


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

    Bound precomputations are part of the term (inputs()), so a key label whose precomputation
    derives in the wrong direction, or from another K, is broken too."""
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


def _bytes(text):
    """The bytes of the first `[n, n, ...]` list in a Debug-printed value, None if there is none."""
    m = re.search(r"\[([\d,\s]*)\]", text or "")
    return bytes(int(x) for x in m.group(1).split(",") if x.strip()) if m else None


def label_values(status):
    """{label: the bytes each binding of the label evaluated to, in binding order}: puffin lists the
    values of the precomputations among a replay's extra knowledges."""
    out = {}
    for e in status["execution"].get("extra_knowledges", []):
        if len(e) > 1 and isinstance(e[0], dict) and e[0].get("Label"):
            out.setdefault(e[0]["Label"], []).append(_bytes(e[1]))
    return out


def put_session_id(status):
    """The session id (the exchange hash H of the first key exchange, RFC 4253 7.2) in the PUT's
    claims, None if it claimed none."""
    for s in status["execution"]["steps"]:
        for c in s.get("claims") or []:
            m = re.search(r"session_id: \[[\d,\s]+\]", str(c))
            if m:
                return _bytes(m.group(0))
    return None


def _epochs(inp):
    """{step: the number of NEWKEYS the attacker sent before it}: the key epoch a packet is sealed in
    (1 for the first keys). A sealed NEWKEYS is the last packet of its epoch."""
    out, n = {}, 0
    for i, node, _ in inp:
        out[i] = n
        if message_of(_msg_node(node) or node) == "fn_new_keys":
            n += 1
    return out


def wrong_exchange_hash(es, inp, fail_step_no):
    """True iff a value the rejected packet's keys are derived from is not the PUT's: the session
    id handed to the derivation is not the one the PUT claimed, or, under the first keys, the
    exchange hash is not (the first exchange hash IS the session id). The keys then cannot match the
    PUT's, whatever else the term does.

    Decided on VALUES: those the attacker's precomputations evaluated to in wolfSSH's run, against
    wolfSSH's own claim. So only for keys derived from labelled precomputations (a sealed step);
    an inline schedule, or the exchange hash of a later key exchange, which no claim carries, is
    left to the structural checks."""
    node = next((n for i, n, _ in inp if i == fail_step_no), None)
    enc = _outermost_enc(node) if node is not None else None
    if enc is None or len(enc.children) < 3:
        return False
    sid = put_session_id(es.put2())
    if sid is None:
        return False
    values = label_values(es.put2())
    first_keys = _epochs(inp).get(fail_step_no) == 1
    for derivation in enc.children[1:3]:
        if derivation.name not in _DERIVE_KEY + _DERIVE_IV or len(derivation.children) < 3:
            continue
        args = [derivation.children[2]] + ([derivation.children[1]] if first_keys else [])
        for arg in args:
            if arg.label is None:
                continue
            label, n = arg.label
            bound = values.get(label, [])
            value = bound[n] if n < len(bound) else None
            if value is not None and value != sid:
                return True
    return False


def aead_cause(es, inp):
    """Why wolfSSH's AES-GCM tag check failed, from the attacker's packet at wolfSSH's failure step
    (term trees, key/IV arguments with their precomputations bound) and, where the keys come from
    precomputations, from the values those evaluated to. In order:

      plaintext_after_newkeys    an unencrypted packet after NEWKEYS
      wrong_invocation_counter   the AES-GCM invocation counter is not the packet's index (counter_verdict)
      computed_counter_term      the counter is a term computed from a queried message
      stale_pre_rekey_schedule   the key schedule of the keys before the last NEWKEYS
      wrong_exchange_hash        a value the keys derive from is not the PUT's (wrong_exchange_hash)
      broken_key_schedule_term   the key schedule is broken on the face of the term
      mutated_key_schedule       the key schedule is not the one of the trace's other packets under
                                 the same keys
      unexplained                none of the above: the fail-open residue
    """
    wf = fail_step(es, WOLFSSH)
    if wf is None:
        return "unexplained"
    nk = _first(inp, lambda n: n.name == "fn_packet" and message_of(n) == "fn_new_keys")
    if nk is not None and any(nk < i <= wf and not is_encrypted(n) and n.name != "fn_banner" for i, n, _ in inp):
        return "plaintext_after_newkeys"
    packet = rejected_packet(es, inp)
    if packet is None:
        return "unexplained"
    f_i, f_n = packet
    cv = counter_verdict(es, inp, f_i)
    if cv == "wrong":
        return "wrong_invocation_counter"
    if cv == "computed":
        return "computed_counter_term"
    if stale_pre_rekey_schedule(es, inp, f_i):
        return "stale_pre_rekey_schedule"
    if wrong_exchange_hash(es, inp, f_i):
        return "wrong_exchange_hash"
    if broken_key_schedule_term(es, inp, f_i):
        return "broken_key_schedule_term"
    # The schedule of the packets BEFORE it under the same keys: a later packet, mutated after
    # wolfSSH failed, cannot make this one look mutated.
    epoch = _epochs(inp)
    earlier = [_keysig(n) for i, n, _ in inp if is_encrypted(n) and i < f_i and epoch.get(i) == epoch.get(f_i)]
    if earlier:
        from collections import Counter
        if _keysig(f_n) != Counter(earlier).most_common(1)[0][0]:
            return "mutated_key_schedule"
    return "unexplained"


def rejected_packet(es, inp):
    """(step, node) of the packet wolfSSH rejected with its AES-GCM tag failure: the last encrypted
    attacker input at or before wolfSSH's failure step (the failure surfaces at that input's step,
    or at a later output step). None if there is none."""
    wf = fail_step(es, WOLFSSH)
    if wf is None:
        return None
    sealed = [(i, n) for i, n, _ in inp if is_encrypted(n) and i <= wf]
    return sealed[-1] if sealed else None


class _LibsshRun:
    """An objective seen through libssh's run: the checks that read wolfSSH's run (put2) read libssh's."""

    def __init__(self, es):
        self.errors, self._es = es.errors, es

    def put1(self):
        return self._es.put1()

    def put2(self):
        return self._es.put1()


def invalid_for_libssh(es, inp, cause, step):
    """True iff libssh's own run shows that the packet at `step`, which wolfSSH rejected for `cause`, cannot
    verify under libssh's keys either. libssh must have keys: its claims carry a session id. Then:

      wrong_invocation_counter, broken_key_schedule_term  the cause is in the term, wrong in any run;
      stale_pre_rekey_schedule  libssh too took its new keys into use: it sent its second NEWKEYS;
      wrong_exchange_hash       the values the keys derive from are not those of libssh's run either.

    Any other cause is not shown invalid for libssh: a mutated key schedule may still derive libssh's key,
    a computed counter evaluates per run, a plaintext packet is never decrypted, an unexplained cause is
    unknown."""
    if put_session_id(es.put1()) is None:
        return False
    if cause in ("wrong_invocation_counter", "broken_key_schedule_term"):
        return True
    if cause == "stale_pre_rekey_schedule":
        return (21, 1) in (_order(es.put1()) or ())
    if cause == "wrong_exchange_hash":
        return wrong_exchange_hash(_LibsshRun(es), inp, step)
    return False


def libssh_accepted(es, inp, cause):
    """True iff the trace shows libssh accepting the packet wolfSSH rejected with an AES-GCM tag failure
    (CVE-2026-59847): libssh got past it (it failed at a later step, or not at all), although its own run
    shows that the packet cannot verify under libssh's keys either (invalid_for_libssh). Answering a later
    request would show that libssh went on, not that the packet was invalid for libssh, so it confirms
    nothing by itself."""
    wf, lf = fail_step(es, WOLFSSH), fail_step(es, LIBSSH)
    if wf is None or (lf is not None and lf <= wf):
        return False
    packet = rejected_packet(es, inp)
    return packet is not None and invalid_for_libssh(es, inp, cause, packet[0])


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
    order and report the first position where they differ -- 'L<n>.<i>/W<m>.<j>' (libssh sent its i-th
    message n where wolfSSH sent its j-th message m, counting from 0; '-' = nothing more), prefixed
    'reorder:' when both transcripts hold the same message multiset.
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
            at = lambda x: f"{x[0]}.{x[1]}" if x else "-"
            return f"{pre}L{at(a)}/W{at(b)}"
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
            if side != "L" and wolfssh_code(st["second_status"]) == -180:
                # wolfSSH rejected an AES-GCM tag, before libssh failed or at the same step. Evidence
                # that libssh accepted the packet (CVE-2026-59847) confirms it; without it the key
                # says ":unconfirmed".
                cause = aead_cause(es, inp)
                es._rc_libssh_accepted = libssh_accepted(es, inp, cause)
                key = f"aead:{r}:{cause}" + ("" if es._rc_libssh_accepted else ":unconfirmed")
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
