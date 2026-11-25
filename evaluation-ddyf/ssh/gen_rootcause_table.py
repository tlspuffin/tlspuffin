"""Generate rootcause_table.py, the SSH buckets, from a root-cause census (rootcause_census.py).

From the repository root, with the evaluation_ddyf symlink (`ln -sfn evaluation-ddyf evaluation_ddyf`):
    python3 -m evaluation_ddyf.ssh.gen_rootcause_table <census.jsonl> --corpus "<the corpus, in words>" \\
        --templated-tag <TAG> [--min N] > evaluation-ddyf/ssh/rootcause_table.py

One row per root-cause key: (bucket name, key, tag, explanation, census count). The documented
mechanisms (`named:`), the AES-GCM causes (`aead:`) and the classes of the other families whose cause is
established (CLASS_RULES) have their tag and explanation here. Any other status, claim or shape key gets
the template of its family, which only restates the key: no cause is established for it, so its tag is
the one --templated-tag gives (BUCKET_GRANULARITY.md, Criterion 5). Keys of those families with fewer
than --min objectives are left unbucketed: the fail-open residual.
"""

import argparse
import json
import re
import sys
from collections import Counter

from .ssh_rootcause import wolfssh_code

TAGS = {
    "KNOWN-CVE": "a known CVE explains the bucket, and its traces witness it",
    "KNOWN-BUG": "a known, reported bug explains the bucket",
    "KNOWN-CLASS": "a documented class of divergence explains the bucket",
    "FINDING-LOW": "a defect this evaluation found, of low impact",
    "RFC-LOW": "an RFC non-conformance, of low impact",
    "HARNESS": "the apparatus (sshpuffin), not the libraries: Gate 0",
    "AUDIT": "a divergence whose cause is to be established: an audit pile",
    "BENIGN": "a difference both stacks are permitted, for the cause given",
    "BENIGN-STRICT": "one stack is stricter than the other, both permitted",
    "BENIGN-ARTEFACT": "a measurement artefact, for the cause given",
}

CVE = (
    "libssh 0.11.4 does not reject it: its OpenSSL AES-GCM decryption takes only rc < 0 from EVP_DecryptFinal "
    "for a failure, and EVP_DecryptFinal returns 0 on a tag mismatch, so the unauthenticated plaintext is "
    "processed. This is CVE-2026-59847 (libssh 0.9.0 to 0.11.4 and 0.12.0, fixed in 0.11.5 and 0.12.1; CVSS 3.1 "
    "6.5 in the libssh advisory, AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:L, and 5.9 by the CNA, Red Hat, with A:N), "
    "rediscovered through the differential."
)
WITNESSED = (
    " The trace witnesses it: libssh got past that packet although it cannot verify under libssh's own keys "
    "either, or answered a request sent after it (ssh_rootcause.libssh_accepted)."
)
NOT_WITNESSED = (
    " The trace does not show libssh accepting the packet (it failed at the same step, or the packet may "
    "verify under libssh's own keys), so it does not witness the CVE: audit."
)

AEAD = {  # cause: explanation of the packet wolfSSH rejected with an AES-GCM tag failure (gerr=-180)
    "wrong_exchange_hash": (
        "A value the rejected packet's keys derive from is not the PUT's: the session id handed to the key "
        "derivation is not the one wolfSSH claimed, or, under the first keys, the exchange hash is not (the "
        "first exchange hash is the session id, RFC 4253 7.2). Decided on the values the attacker's "
        "precomputations evaluated to. The keys cannot match wolfSSH's, so its rejection is correct."
    ),
    "wrong_invocation_counter": (
        "The packet carries an explicit AES-GCM invocation counter (the mutator replaced the fn_u32_auto "
        "sentinel, or the sentinel sits past the 16 packets it is renumbered for) whose value is not the "
        "packet's index since the last NEWKEYS: the GCM nonce is wrong (RFC 5647) and the tag must fail, so "
        "wolfSSH's rejection is correct."
    ),
    "computed_counter_term": (
        "The packet's AES-GCM invocation counter is a computed term, not the fn_u32_auto sentinel or a constant "
        "(e.g. fn_channel_send_budget(fn_decrypted_message(..)) or fn_initial_window_size(fn_channel_open(..))): "
        "it evaluates to a channel window or packet size rather than the packet's index since the last NEWKEYS, "
        "or, for a sentinel buried in such a term, to its own value u32::MAX-1. In the 2026-09-23 campaign the "
        "counters of such packets were dumped by an instrumented build: none was the packet's index. wolfSSH's "
        "rejection is correct."
    ),
    "stale_pre_rekey_schedule": (
        "The packet is sealed under the key schedule of the keys before the last NEWKEYS: after NEWKEYS both "
        "sides MUST use the new keys, derived from the new exchange hash (RFC 4253 7.2, 7.3; only the session id "
        "keeps the first one). wolfSSH rotated, the attacker did not, so its rejection is correct."
    ),
    "broken_key_schedule_term": (
        "The packet's key/IV schedule is broken on the face of the term, so the derived key cannot match the "
        "peer's whatever the peer did: the key or IV slot is not a derivation at all (a constant, a public key, "
        "a queried byte string), or its schedule holds no exchange hash, or the derivation's direction is not "
        "the attacker's, or the shared secret handed to the derivation is not the one inside its own exchange "
        "hash, or key and IV come from different exchange hashes. wolfSSH's rejection is correct."
    ),
    "mutated_key_schedule": (
        "The packet is sealed under a key schedule that is not the one of the trace's other packets under the "
        "same keys: a mutated key/IV schedule, so its keys cannot match the peer's and wolfSSH's rejection is "
        "correct."
    ),
}
PLAINTEXT = (
    "The attacker sends an unencrypted packet after NEWKEYS; wolfSSH tries to AEAD-decrypt it and fails (gerr=-180), "
    "which is correct. libssh waits for the tag bytes the plaintext packet lacks, and the harness reports that "
    "silence as no error: a measurement artefact, not an acceptance."
)
UNEXPLAINED = (
    "A wolfSSH AES-GCM tag failure (gerr=-180) that none of the causes of ssh_rootcause.aead_cause explains: the "
    "fail-open residue. Its cause is to be established."
)

NAMED = {  # mechanism (ssh_rootcause._NAMED): (tag, explanation)
    "known_wolfssh_client_accepts_preauth_connection_layer": ("FINDING-LOW", (
        "wolfSSH 1.5.0 CLIENT dispatches a connection-layer message (msg >= 80) delivered in plaintext before "
        "NEWKEYS, i.e. before key exchange completes, before host-key verification and before authentication, "
        "while the libssh client refuses it. Cause: IsMessageAllowedClient arms the RFC 4252 6 guard only while "
        "`connectState >= CONNECT_KEYED && < CONNECT_SERVER_USERAUTH_ACCEPT_DONE`; below CONNECT_KEYED its else "
        "branch allows the message. The server half has the matching `acceptState < ACCEPT_KEYED` guard; the "
        "client half has none. Upstream master drops the lower bound (fixed). It exposes the connection-layer "
        "parsers to unauthenticated input; an ASan sweep of 4,065 such traces found no memory error, so this is "
        "conformance and attack surface, not a demonstrated DoS.")),
    "known_libssh_cve_2026_59847_client_enters_authenticated_state": ("KNOWN-CVE", (
        "libssh CLIENT enters the authenticated state although the peer never sent USERAUTH_SUCCESS: a packet "
        "sealed under a bogus key (key/IV literals instead of the derived schedule) fails its AES-GCM tag, libssh "
        "does not reject it (CVE-2026-59847) and parses the garbage as a control message. A trace of the "
        "2026-09-23 campaign shows libssh logging `read type 52 [len=192,padding=-88]`, then \"Authentication "
        "successful\", then CHANNEL_OPEN; the padding is a uint8_t printed with %hhd, i.e. 168, which the "
        "packet's 192 bytes allow, so the garbage passed libssh's padding check, which is sound. Scope: an "
        "illustration that the integrity defect reaches control-plane decisions, not an impact escalation: an "
        "attacker wanting to feed forged data to the client would let authentication complete and tamper with "
        "CHANNEL_DATA instead (simpler, and the session survives).")),
    "known_wolfssh_client_accepts_unsolicited_userauth_success": ("FINDING-LOW", (
        "wolfSSH CLIENT treats a USERAUTH_SUCCESS that arrives before any SERVICE_ACCEPT (so before it sent an "
        "authentication request) as authentication, then sends a method-\"none\" USERAUTH_REQUEST and opens a "
        "channel without awaiting a reply; the libssh client refuses the message (packet.c:588). Library defect "
        "(wolfSSH ssh.c connect ladder; DoUserAuthSuccess has no state check), present on master. Only the keyed "
        "peer can send it (after NEWKEYS); no credential is sent.")),
    "known_wolfssh_client_accepts_unsolicited_userauth_success_no_request": ("FINDING-LOW", (
        "The wolfSSH client defect of known_wolfssh_client_accepts_unsolicited_userauth_success, where the client "
        "goes on to connection-layer messages without sending any USERAUTH_REQUEST in the trace.")),
    "known_wolfssh_client_userauth_request_after_unsolicited_failure": ("FINDING-LOW", (
        "The same wolfSSH client ladder gap, with another trigger and a milder consequence: the server sends "
        "USERAUTH_FAILURE before any SERVICE_ACCEPT, so before the client is entitled to be in the userauth "
        "service at all, and the wolfSSH client answers it with a USERAUTH_REQUEST, while the libssh client waits "
        "for the SERVICE_ACCEPT its SERVICE_REQUEST is owed (RFC 4253 10). Only the keyed peer can send it, and "
        "the request goes to that peer: a state-machine conformance gap, not a disclosure.")),
    "known_wolfssh_unsolicited_service_accept": ("RFC-LOW", (
        "wolfSSH SERVER sends SSH_MSG_SERVICE_ACCEPT although the client never sent SERVICE_REQUEST (its accept "
        "ladder waits on clientState >= CLIENT_USERAUTH_REQUEST_DONE, which a bare USERAUTH_REQUEST satisfies); "
        "libssh does not. RFC 4253 10. Present on master.")),
    "known_wolfssh_userauth_service_name_not_validated": ("RFC-LOW", (
        "USERAUTH_REQUEST whose service field is not \"ssh-connection\": wolfSSH 1.5.0 DoUserAuthRequest never "
        "checks it and answers SUCCESS or PK_OK, libssh rejects it (messages.c strcmp). Fixed on wolfSSH master "
        "(d0551fa1).")),
    "known_wolfssh_repeated_service_request_fatal": ("BENIGN-STRICT", (
        "The client sends SERVICE_REQUEST twice before authenticating: wolfSSH aborts (\"Message ID 5 not "
        "allowed by server after starting user auth\", gerr=-1094) before the authentication request arrives, "
        "libssh answers the repeat and authenticates. Verified with a DEBUG_WOLFSSH build. A strictness "
        "difference: RFC 4253 10 forbids neither.")),
    "known_libssh_cve_2026_59847_authenticates_on_tag_failed_packet": ("KNOWN-CVE", (
        "The client's USERAUTH_REQUEST is itself sealed under a wrong key or nonce: wolfSSH rejects it with an "
        "AES-GCM tag failure (gerr=-180), libssh accepts it and answers USERAUTH_SUCCESS: CVE-2026-59847 at the "
        "authentication step. Integrity only: the credential inside is the attacker's own valid one, so no "
        "party without credentials authenticates; libssh acts on an unauthenticated ciphertext. " + CVE)),
    "known_wolfssh_aborts_on_unusable_server_sig_algs": ("RFC-LOW", (
        "wolfSSH, as SERVER, parses an EXT_INFO \"server-sig-algs\" extension, which RFC 8308 3.1 defines as "
        "server-to-client, matches no signature algorithm in its value and aborts the connection "
        "(DoExtInfoServerSigAlgs: MatchIdLists returns ID_UNKNOWN, WS_MATCH_UA_KEY_ID_E, gerr=-1089); libssh "
        "tolerates the unusable extension and authenticates the client's credential. -1089 is raised there only, "
        "never on a credential, despite its name (\"unable to match user auth key type\"). wolfSSH is the "
        "non-conformant side twice over: it processes a server-to-client extension as server, and it tears the "
        "connection down over an advisory extension it cannot use. Impact low: only the keyed peer can send "
        "it, and that peer can close the connection anyway.")),
    "diverge_wolfssh_rejects_malformed_userauth_libssh_accepts": ("BENIGN-STRICT", (
        "wolfSSH refuses a malformed USERAUTH_REQUEST at that very step (gerr -1004 buffer size, -1002 bad "
        "argument, -1007 overflow) while libssh ignores it and authenticates the next, well-formed one: "
        "ssh_packet_userauth_request() frees a request it cannot parse and returns SSH_PACKET_USED (messages.c, "
        "error label). RFC 4252 does not say what a server does with a request it cannot parse, so neither "
        "behaviour breaks it: a parser-strictness difference. Not a bypass: in the 2026-09-23 corpus, every one "
        "of the 37 such traces where libssh authenticated carries a genuine credential.")),
    "known_wolfssh_unrecognised_channel_request_answered_success": ("RFC-LOW", (
        "wolfSSH 1.5.0 SERVER answers CHANNEL_SUCCESS to a channel request type it does not recognise (any but "
        "exec, shell and pty-req): DoChannelRequest replies SendChannelSuccess(.., ret == WS_SUCCESS && !rej) and "
        "no branch handles an unknown type, where RFC 4254 5.4 answers CHANNEL_FAILURE, as libssh does. wolfSSH "
        "1.6.0 rejects it. Only an authenticated client with an open channel can send it.")),
    "known_wolfssh_1246_fwd_port_echo": ("KNOWN-BUG", (
        "wolfssh#1246: the REQUEST_SUCCESS of a tcpip-forward carries a bound port although the client asked for "
        "a fixed one, where RFC 4254 7.1 sends the port only for a request of port 0. Reported, fixed on master "
        "24c2139a, present in 1.5.0.")),
}
for _who, _layer in (("wolfssh", "wolfSSH"), ("libssh", "libssh")):
    for _role in ("server", "client"):
        NAMED[f"known_{_who}_{_role}_sends_during_incomplete_rekey"] = ("RFC-LOW", (
            f"{_layer} {_role.upper()} sends a non-transport message between its rekey KEXINIT and its NEWKEYS, "
            "which RFC 4253 7.1 forbids (MUST NOT), checked on its own decrypted transcript."))

MESSAGES = {
    1: "DISCONNECT", 2: "IGNORE", 3: "UNIMPLEMENTED", 4: "DEBUG", 5: "SERVICE_REQUEST", 6: "SERVICE_ACCEPT",
    7: "EXT_INFO", 20: "KEXINIT", 21: "NEWKEYS", 30: "KEX_ECDH_INIT", 31: "KEX_ECDH_REPLY",
    50: "USERAUTH_REQUEST", 51: "USERAUTH_FAILURE", 52: "USERAUTH_SUCCESS", 60: "USERAUTH_PK_OK",
    80: "GLOBAL_REQUEST", 81: "REQUEST_SUCCESS", 82: "REQUEST_FAILURE", 90: "CHANNEL_OPEN",
    91: "CHANNEL_OPEN_CONFIRMATION", 92: "CHANNEL_OPEN_FAILURE", 93: "CHANNEL_WINDOW_ADJUST", 94: "CHANNEL_DATA",
    95: "CHANNEL_EXTENDED_DATA", 96: "CHANNEL_EOF", 97: "CHANNEL_CLOSE", 98: "CHANNEL_REQUEST",
    99: "CHANNEL_SUCCESS", 100: "CHANNEL_FAILURE",
}
# Replies that accept and refuse the same request: one PUT accepting what the other refuses.
ACCEPT_REFUSE = ({81, 82}, {91, 92}, {99, 100})


def layer(m):
    """RFC 4250 4.1.2: the layer of a message number."""
    if m < 20:
        return "transport generic"
    if m < 50:
        return "key exchange"
    if m < 80:
        return "user authentication"
    return "connection protocol"


def after_rekey(epoch):
    """', after its first rekey (key epoch 2)' for a message of key epoch `epoch` of a shape key (the digits
    of its '@e<k>'); '' for None, a message before the PUT's first rekey."""
    if not epoch:
        return ""
    rekeys = int(epoch) - 1
    return f", after {'its first rekey' if rekeys == 1 else f'{rekeys} rekeys'} (key epoch {epoch})"


def slug(text):
    return re.sub(r"_+", "_", re.sub(r"\W+", "_", text)).strip("_").lower()


class Generator:
    def __init__(self, census, templated_tag, minimum=1):
        self.templated_tag = templated_tag
        self.minimum = minimum
        self.counts = Counter(row["key"] for row in census if row.get("key"))
        self.residual = sum(1 for row in census if not row.get("key"))
        names = {}  # wolfSSH code: the names its statuses give it
        for row in census:
            for text in (row.get(f) for f in ("first_status", "second_status", "first_error", "second_error")):
                code = wolfssh_code(text)
                if code is not None and " (rc=" in text:
                    name = text.replace("error in PUT : ", "").split(" (rc=")[0]
                    names.setdefault(code, Counter())[name] += 1
        self.wolfssh_names = {code: c.most_common(1)[0][0] for code, c in names.items()}

    # ---- error classes
    def class_name(self, cls):
        m = re.fullmatch(r"wolfssh_gerr(\d+)", cls)
        if not m:
            return cls
        name = self.wolfssh_names.get(-int(m.group(1)), "unknown")
        return f"gerr{m.group(1)}_" + slug("unknown" if name == "Unknown error code" else name)

    @staticmethod
    def what(who, cls):
        if cls == "success":
            return (f"{who} ended the trace without an error: it was still waiting for input the other stack "
                    "did not need")
        if cls.startswith("mapper_"):
            return (f"{who}'s run stopped on {cls}, an error of sshpuffin's own term evaluation: the attacker's recipe "
                    f"read a message {who} had not sent, or a variable it could not bind")
        if cls == "libssh_empty_error":
            return f"{who} ended the session with an empty error message"
        return f"{who} stopped on {cls}"

    # ---- the classes with an established cause, before any template
    def class_rule(self, family, role, side, cls):
        """(tag, explanation) for a status or claim key whose class has an established cause, or None."""
        if family == "claim" and cls.startswith("mapper_"):
            who = "libssh" if side == "L" else "wolfSSH"
            return "HARNESS", (
                f"{role} role: Gate 0, the apparatus, not a library divergence. No status difference; the claim "
                f"difference comes from {who}'s run ending on {cls}, an error of sshpuffin's own term evaluation "
                "(\"error executing a function symbol\", \"error evaluating a term\"), not of the library. In the "
                "2026-09-23 corpus, 498 sampled logs of the libssh rows of this class showed no native libssh error, "
                "and the other PUT hit the same term-evaluation failure.")
        if cls == "wolfssh_gerr1089":
            return "RFC-LOW", (
                f"{role} role: wolfSSH stops with gerr -1089 (WS_MATCH_UA_KEY_ID_E), which it raises only when an "
                "EXT_INFO \"server-sig-algs\" value matches no algorithm (DoExtInfoServerSigAlgs), never on a "
                "credential despite its name; it parses that server-to-client extension (RFC 8308 3.1) whatever "
                "its role. The non-conformance of known_wolfssh_aborts_on_unusable_server_sig_algs, without an "
                "authentication divergence.")
        if cls == "libssh_could_not_generate_shared_secret":
            return "AUDIT", (
                f"{role} role: libssh cannot compute the ECDH shared secret from the peer's public key, while "
                "wolfSSH goes on with the same key: whether wolfSSH checks the peer's point is not established.")
        if cls.startswith("libssh_received_unexpected_packets_in_strict_ke"):
            return "BENIGN", (
                f"{role} role: libssh enforces strict key exchange (OpenSSH's kex-strict, the countermeasure to "
                "Terrapin, CVE-2023-48795) and rejects a packet it forbids during the initial key exchange; wolfSSH "
                "1.5.0 does not implement strict key exchange (1.6.0 does), so it goes on. With AES-GCM only, the "
                "Terrapin prefix truncation does not apply: an optional extension one stack implements.")
        if cls.startswith("libssh_receiving_banner_too_large_banner"):
            return "KNOWN-BUG", (
                f"{role} role: libssh refuses a banner longer than its limit (\"Receiving banner: too large "
                "banner\"), reported as libssh-mirror#376; wolfSSH accepts it.")
        return None

    # ---- one row per key
    def row(self, key, n):
        family = key.split(":")[0]
        if family == "named":
            mechanism = key.split(":", 1)[1]
            if mechanism not in NAMED:
                raise KeyError(f"{key}: no explanation in gen_rootcause_table.NAMED")
            tag, text = NAMED[mechanism]
            return mechanism, key, tag, text, n
        if family == "auth_unexplained":
            role = key.split(":")[1]
            return (f"diverge_auth_asymmetry_unexplained_{role}", key, "AUDIT",
                    f"{role} role: the two PUTs disagree on authentication (server: USERAUTH_SUCCESS from one only; "
                    "client: one client reaches the connection layer), the PUT that did not authenticate had not "
                    "failed before the step the other authenticated on, and no documented mechanism explains it. "
                    "Audit pile, never benign.", n)
        if family == "aead":
            _, role, cause, *unconfirmed = key.split(":")
            name = f"wolfssh_aead_reject_{cause}_{role}" + ("_unconfirmed" if unconfirmed else "")
            if cause == "plaintext_after_newkeys":
                return name, key, "BENIGN-ARTEFACT", PLAINTEXT, n
            if cause == "unexplained":
                return name, key, "AUDIT", UNEXPLAINED, n
            if cause not in AEAD:
                raise KeyError(f"{key}: no explanation in gen_rootcause_table.AEAD")
            if unconfirmed:
                return name, key, "AUDIT", AEAD[cause] + NOT_WITNESSED, n
            return name, key, "KNOWN-CVE", AEAD[cause] + " " + CVE + WITNESSED, n
        if n < self.minimum:
            return None
        if family == "status":
            return self.status_row(key, n)
        if family == "claim":
            return self.claim_row(key, n)
        if family == "shape":
            return self.shape_row(key, n)
        raise KeyError(f"{key}: unknown key family")

    def status_row(self, key, n):
        _, role, side, cls = key.split(":", 3)
        if side == "=":
            a, b = cls.split("|")
            name = f"both_fail_same_step_{role}_libssh_{slug(self.class_name(a))}_wolfssh_{slug(self.class_name(b))}"
            rules = [r for r in (self.class_rule("status", role, "L", a), self.class_rule("status", role, "W", b)) if r]
            # A cause to look at (a non-conformance, a known bug, an audit) is not hidden by the other PUT's
            # benign one.
            rule = next((r for r in rules if not r[0].startswith("BENIGN")), rules[0] if rules else None)
            text = (f"{role} role: both PUTs stop at the same step; " + self.what("libssh", a) + "; "
                    + self.what("wolfSSH", self.class_name(b)) + ".")
        else:
            who, other = ("wolfSSH", "libssh") if side == "W" else ("libssh", "wolfSSH")
            name = f"{who.lower()}_{role}_rejects_first_{slug(self.class_name(cls))}"
            rule = self.class_rule("status", role, side, cls)
            text = (f"{role} role: {who} is the first PUT to stop: " + self.what(who, self.class_name(cls))
                    + f"; {other} gets further on the same input. An authentication disagreement, if any, comes "
                    "from that earlier stop (auth_unexplained takes the others).")
        if rule:
            return name, key, rule[0], rule[1] + " " + text, n
        return name, key, self.templated_tag, text, n

    def claim_row(self, key, n):
        _, role, side, cls = key.split(":", 3)
        who, other = ("libssh", "wolfSSH") if side == "L" else ("wolfSSH", "libssh")
        name = f"kex_not_finalised_by_{who.lower()}_{role}_{slug(self.class_name(cls))}"
        rule = self.class_rule("claim", role, side, cls)
        if rule:
            return name, key, rule[0], rule[1], n
        text = (f"{role} role: no status difference; {other} completed the key exchange (it emitted its post-KEX "
                f"claim) and {who} did not: " + self.what(who, self.class_name(cls)) + ".")
        return name, key, self.templated_tag, text, n

    def shape_row(self, key, n):
        _, role, shape = key.split(":", 2)
        prefix = f"{role} role, transcript-only divergence (no status or claim difference): "
        if shape == "rekey_progress":
            return (f"transcript_{role}_rekey_handshake_progress", key, "KNOWN-CLASS", prefix + (
                "the attacker starts a second key exchange once keys are in place, and at the first divergence one "
                "stack is further into it (KEXINIT, KEX_ECDH or NEWKEYS of ordinal >= 1) than the other (RFC 4253 "
                "9). Messages sent inside an incomplete rekey are the RFC 4253 7.1 mechanisms."), n)
        if shape == "auth_retry_count":
            return (f"transcript_{role}_auth_retry_count", key, "BENIGN", prefix + (
                "after USERAUTH_FAILURE one client makes one more USERAUTH_REQUEST attempt than the other: their "
                "retry policies differ, which RFC 4252 leaves to the client."), n)
        m = re.fullmatch(r"(reorder:)?L(?:(\d+)\.(\d+)(?:@e(\d+))?|-)/W(?:(\d+)\.(\d+)(?:@e(\d+))?|-)", shape)
        if m:
            reorder, lm, lo, le, wm, wo, we = m.groups()

            def sent(msg, ordinal, epoch):
                if msg is None:
                    return "nothing more"
                return (f"its message {ordinal} of type {msg} ({MESSAGES.get(int(msg), 'unnamed')}, {layer(int(msg))})"
                        + after_rekey(epoch))

            def part(msg, ordinal, epoch):
                return "none" if msg is None else f"{msg}_{ordinal}" + (f"_epoch{epoch}" if epoch else "")

            name = (f"transcript_{role}_{'reorder_' if reorder else ''}first_libssh_{part(lm, lo, le)}"
                    f"_wolfssh_{part(wm, wo, we)}")
            text = prefix + (f"at the first point where the two decrypted transcripts differ, libssh sent "
                             f"{sent(lm, lo, le)} and wolfSSH {sent(wm, wo, we)}"
                             + (" (the same messages overall: an order difference)" if reorder else "") + ".")
            numbers = {int(x) for x in (lm, wm) if x is not None}
            if any(numbers == pair for pair in ACCEPT_REFUSE):
                refusal = " One PUT accepts what the other refuses: which one conforms is to be established."
                return name, key, "AUDIT", text + refusal, n
            if any(20 <= x < 80 for x in numbers):
                sensitive = " The first divergence is a key-exchange or authentication message."
                return name, key, "AUDIT", text + sensitive, n
            return name, key, self.templated_tag, text, n
        m = re.fullmatch(r"C(\d+)(?:@e(\d+))?", shape)
        if m:
            msg, epoch = int(m.group(1)), m.group(2)
            name = f"transcript_{role}_content_differs_{msg}" + (f"_epoch{epoch}" if epoch else "")
            text = prefix + (f"both transcripts carry the same messages in the same order; the first whose content "
                             f"differs is of type {msg} ({MESSAGES.get(msg, 'unnamed')}, {layer(msg)})"
                             + after_rekey(epoch) + ".")
            if 20 <= msg < 80:
                return name, key, "AUDIT", text + " It is a key-exchange or authentication message.", n
            return name, key, self.templated_tag, text, n
        return (f"transcript_{role}_{slug(shape)}", key, self.templated_tag, prefix + f"transcript shape {shape}.", n)

    def rows(self):
        out = [r for r in (self.row(key, n) for key, n in self.counts.most_common()) if r is not None]
        duplicates = [name for name, c in Counter(r[0] for r in out).items() if c > 1]
        if duplicates:
            raise ValueError(f"bucket names given to several keys: {duplicates}")
        return out


def render(rows, corpus, templated_tag, minimum, residual):
    total = sum(r[4] for r in rows)
    legend = "\n".join(f"  {tag:15} {meaning}" for tag, meaning in TAGS.items())
    lines = [
        '"""GENERATED by gen_rootcause_table.py from the root-cause census (rootcause_census.py) of ' + corpus + ".",
        "",
        f"{len(rows)} buckets holding {total} objectives; {residual} objectives without a key (a replay or a "
        "classifier failed) stay unbucketed"
        + (f", as do the status, claim and shape keys of fewer than {minimum} objectives (the fail-open residual)."
           if minimum > 1 else "."),
        "One row per bucket: (bucket_name, root_cause_key, tag, explanation, census_count). Tags:",
        "",
        legend,
        "",
        f"A status, claim or shape key with no established cause has the explanation of its family's template, which "
        f"only restates the key, and the tag {templated_tag}.",
        '"""',
        "ROWS = [",
        *(f"    {row!r}," for row in rows),
        "]",
        "",
    ]
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("census")
    parser.add_argument("--corpus", required=True, help="what the census is of, in words (the docstring cites it)")
    parser.add_argument("--templated-tag", required=True, help="the tag of a templated row (no established cause)")
    parser.add_argument("--min", type=int, default=1, help="objectives a templated family's key needs for a bucket")
    args = parser.parse_args(argv)
    if args.templated_tag not in TAGS:
        TAGS[args.templated_tag] = "no cause established yet: a template restates the key"
    census = [json.loads(line) for line in open(args.census)]
    generator = Generator(census, args.templated_tag, args.min)
    sys.stdout.write(render(generator.rows(), args.corpus, args.templated_tag, args.min, generator.residual))


if __name__ == "__main__":
    main()
