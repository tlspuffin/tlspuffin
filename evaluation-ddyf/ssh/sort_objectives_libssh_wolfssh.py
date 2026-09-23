"""Offline triaging of libssh-vs-wolfSSH differential objectives into named buckets.

This is the *post-campaign, human-audited* companion to sshpuffin's *online*
(in-fuzzer) shadow layer. During a campaign, `SshProtocolTypes::differential_fuzzing_
filter_diff` / `filter_diffs` (sshpuffin/src/protocol.rs) drop a handful of documented
classes so long runs surface NEW findings; everything else becomes an objective. THIS
script then sorts those saved objectives into precise, reviewable buckets so a human
can confirm the campaign's residue is benign and spot anything new.

Each bucket is a `BucketCondition` (see `diff_analyzer.py`) over the objective's
status/claim/term/knowledge diffs. An objective is filed under the FIRST matching
bucket (order matters); anything unmatched stays "unbucketed" for manual audit — the
fail-open direction (a new divergence is never silently absorbed).

Bucket families
---------------
* `bootstrap_*`            — pre-auth banner/version strictness + the step-0 socket
                             harness artifact. libssh is the strict side.
* `diverge_{a}_accepts_{b}_rejects`
                           — one stack COMPLETES where the other rejects. NOT benign;
                             an explicit, countable audit pile (never a benign bucket).
* `wolfssh_*` / `libssh_packet_filter_*` / `bootstrap_*_error`
                           — internal-error classes that are benign ONLY when BOTH
                             stacks reject; AND-ed with `BOTH_ERROR` so a one-side
                             success can never be masked.
* `benign_decrypt_*`       — decrypted-s2c reply-framing/timing latitude (RFC
                             4253/4254 permit it); matched on the knowledge-diff shape.
                             Two sub-shapes: DifferentTypes (`SshMessage::X vs ()`,
                             a whole message on one side only) and InnerDifference
                             (`InnerKnowledgeC`, an aligned key Added/Removed/Changed
                             inside a shared AlignedTranscript, e.g. the msg-93
                             CHANNEL_WINDOW_ADJUST presence class and the msg-92
                             `BothChannelOpenFailure` reason-code class).
* `benign_kex_*`           — KEX-phase packet-length strictness (libssh stricter);
                             both ultimately reject.
* `known_wolfssh_unsolicited_service_accept`, `known_repeated_service_request_reply`
                           — two documented SERVICE_REQUEST behaviour differences (see
                             the bucket comments); pinned to their exact transcript shape.
* `benign_client_kex_reply_reject`
                           — client-side (server-attacker) traces where both CLIENTS
                             reject a mutated KEX_ECDH_REPLY.
* `known_rekey_kexinit_presence`
                           — the RFC 4253 §7.1 second-KEXINIT (msg 20 ordinal 1)
                             presence marker; names the known incomplete-rekey class
                             so it stays out of the unbucketed tail. Marks a rekey
                             KEXINIT's PRESENCE only — it does NOT mask a genuine
                             §7.1 divergence (traffic processed mid-rekey shows up as
                             DIFFERENT downstream messages, matching no benign bucket).

Correspondence to the in-fuzzer shadow predicates (sshpuffin/src/protocol.rs)
-----------------------------------------------------------------------------
The offline buckets and the online shadow predicates classify the SAME classes; the
shadows are the subset suppressed live, documented next to each predicate in
sshpuffin/src/ssh/differential.rs:
    bootstrap_too_large_banner* / bootstrap_no_version_usable*  <->  is_banner_strictness_diff        (SHADOW_KNOWN_BENIGN)
    benign_kex_decrypt_transcript_presence                      <->  is_banner_induced_transcript_presence
    benign_decrypt_userauth_failure                             <->  is_userauth_failure_only_diff     (SHADOW_KNOWN_BENIGN)
    (a decrypted REQUEST_SUCCESS +bound-port change)            <->  is_fwd_reqsuccess_port_echo_diff  (SHADOW_KNOWN_BUGS, wolfssh#1246)
The `diverge_*` / `BOTH_ERROR`-guarded buckets are the offline mirror of the shadow
predicates' *safety guards* (a shadow never drops an accept/reject or success delta).

SSH classification reference (for writing/extending buckets)
------------------------------------------------------------
The `BucketCondition` engine (`diff_analyzer.py`: `StatusC`, `TermContainsC`,
`ClaimContainsC`, `CheckAgentC`, `StepC`, `KnowledgeDiffC`, `DifferentClaimC`, …) is
protocol-agnostic and reused from the TLS pipeline unchanged; only the *conditions*
are SSH-specific. The SSH facts they key on (from the sshpuffin mapper):

* Claims — `SshClaimInner` fields: `is_server, kex, cipher_in/out, hmac_in/out,
  auth_method, auth_user, auth_key_fingerprint, session_id, secure_tx/rx_digest,
  phase (0=init,1=kex,2=auth,3=done), rx/tx_count`. Key on these with `ClaimContainsC`
  / `DifferentClaimC`. NOTE only `phase==3` (DONE) claims carry final security state;
  `phase<3` are coverage-only (distinct TypeShape `SshProgressClaim`, already excluded
  from the differential comparison).
* No `tls_version`. SSH config is `SshDescriptorConfig { typ: Client|Server,
  try_reuse }`; the TLS `CheckAgentC([...,"tls_version"],…)` has no SSH analogue — key
  on `typ` if a config discriminator is needed.
* Term names are `fn_*` SSH builders (`fn_banner, fn_packet, fn_onwire_message,
  fn_kex_algos, fn_encrypt_packet_*`, … in `sshpuffin/src/ssh/fn_*.rs`); use with
  `TermContainsC` / `TermContainsReC`.
* Knowledge types are `RawSshMessage, OnWireData, SshMessage, RawSshMessageFlight`
  (not TLS records/alerts); use with `KnowledgeDiffC` / `KnowledgeContainsC`.
* The in-engine `filter_diff` already runs during the campaign: surviving objectives
  keep `SecurityClaim` (always), `Claims` (always) and `Status` only on an acceptance
  disagreement; benign `Knowledges` are dropped online — so the objectives this script
  sorts are already meaningful, and the benign buckets below are the residual taxonomy.

Benign class distribution (historical v1 xvendor campaign, libssh0114 vs wolfSSH —
seeds the bucket set): ~45% version-string leniency (`No version usable` vs Success),
~30% banner >255 B (`too large banner` vs Success), ~9% libssh `Socket error: File
exists` (own error, kept), ~7% claim-presence (one finalises KEX), ~5% libssh
leniency (`Unknown error code`). These are the high-volume benign classes the buckets
above name; a genuinely new divergence matches none and stays unbucketed for audit.

Usage
-----
    ln -sfn evaluation-ddyf evaluation_ddyf   # once: `-m` needs an importable (underscore) name
    python -m evaluation_ddyf.ssh.sort_objectives_libssh_wolfssh [objective_folder]

The two PUT names and worker count are overridable via the environment (defaults are
the clean, non-ASAN artifact vendors: libssh 0.11.4 vs wolfSSH 1.5.0):
    SSHPUFFIN_FIRST_PUT   (default "libssh0114")
    SSHPUFFIN_SECOND_PUT  (default "wolfssh150")
    SSHPUFFIN_TRIAGE_PARALLELISM (default 24)  sizes the classifier ThreadPool
    PUFFIN_TRIAGE_UNIFORMISE     (default 1)   re-execute each PUT under the uniformised
                                               differential config (display-execute --uniformise)
    PUFFIN_TRIAGE_NO_CACHE       (unset)       set to force live re-execution instead of
                                               reading the Phase-0 metadata_diff_*.json cache

Note on parallelism: the pool size above is real, but `ps` typically shows only a few
concurrent `sshpuffin` subprocesses even at a high value — each per-trace differential
execution is short, and once Phase 0 has produced the metadata_diff_*.json cache the
classifier reads it instead of executing at all (see diff_analyzer.get_diff), so triage is
I/O/JSON-bound, not exec-bound. A large PARALLELISM does not give a proportional speed-up.
"""

import os
import sys

from ..diff_analyzer import (
    BucketCondition,
    NoDiffC,
    AllC,
    AnyC,
    NotC,
    StatusC,
    CheckAgentC,
    TermContainsC,
    ClaimContainsC,
    TermContainsReC,
    StepC,
    InnerKnowledgeC,
    DifferentClaimC,
    KnowledgeContainsC,
    run_triaging,
    KnowledgeDiffC,
    InnerKnowledgeReC,
    OnlyDiffKindsC,
)

LIBSSH = 1
WOLFSSH = 2
FIRST_PUT = os.environ.get("SSHPUFFIN_FIRST_PUT", "libssh0114")
SECOND_PUT = os.environ.get("SSHPUFFIN_SECOND_PUT", "wolfssh150")
PARALLELISM = int(os.environ.get("SSHPUFFIN_TRIAGE_PARALLELISM", "24"))
# Re-execute each PUT under the SAME uniformised config as the differential run that
# produced the objective (see diff_analyzer.uniformise_single_runs). Without it the
# per-PUT status of a client-role (server-attacker) objective came from a run with
# the libssh client's default algorithms, which fails elsewhere than in the
# differential, so status buckets misfired. Override with PUFFIN_TRIAGE_UNIFORMISE=0.
os.environ.setdefault("PUFFIN_TRIAGE_UNIFORMISE", "1")

# ── Over-permissiveness guard ────────────────────────────────────────────────
# BOTH_ERROR is true iff NEITHER PUT completed the trace (both have a non-None
# execution error). It is the key defence against a bucket silently classifying a
# real ACCEPTANCE divergence as benign: any bucket whose benign-ness was
# established only for the "both stacks reject" case is AND-ed with BOTH_ERROR, so
# a trace where one stack SUCCEEDS while the other fails can never match it — it
# stays unbucketed and surfaces for manual audit. (first_to_fail=False makes
# StatusC read that PUT's OWN status.error directly rather than the diff, so this
# works whether or not the objective carries a Status diff.)
BOTH_ERROR = AllC(
    StatusC(LIBSSH, first_to_fail=False),
    StatusC(WOLFSSH, first_to_fail=False),
)

buckets: dict[str, BucketCondition] = {
    # AUDITED
    "bootstrap_no_version_usable/": AllC(StatusC(LIBSSH, in_error="No version of SSH protocol usable"), TermContainsC(LIBSSH, in_term="fn_banner")),
    "bootstrap_no_version_usable_onwire/": AllC(StatusC(LIBSSH, in_error="No version of SSH protocol usable"), TermContainsC(LIBSSH, in_term="fn_onwire_message")),
    "bootstrap_no_version_usable_packet/": AllC(StatusC(LIBSSH, in_error="No version of SSH protocol usable"), TermContainsC(LIBSSH, in_term="fn_packet")),
    "bootstrap_no_version_usable_encrypt/": AllC(StatusC(LIBSSH, in_error="No version of SSH protocol usable"), TermContainsC(LIBSSH, in_term="fn_encrypt_packet")),
    # AUDITED
    "bootstrap_too_large_banner/": AllC(StatusC(LIBSSH, in_error="too large banner"), TermContainsC(LIBSSH, in_term="fn_banner")),
    "bootstrap_too_large_banner_onwire/": AllC(StatusC(LIBSSH, in_error="too large banner"), TermContainsC(LIBSSH, in_term="fn_onwire_message")),
    "bootstrap_too_large_banner_packet/": AllC(StatusC(LIBSSH, in_error="too large banner"), TermContainsC(LIBSSH, in_term="fn_packet")),
    "bootstrap_too_large_banner_encrypt/": AllC(StatusC(LIBSSH, in_error="too large banner"), TermContainsC(LIBSSH, in_term="fn_encrypt_packet")),
    # AUDITED
    "bootstrap_socket_error/": AllC(StatusC(LIBSSH, in_error="Socket error: File exists"), TermContainsC(LIBSSH, in_term="fn_banner")),
    "bootstrap_socket_error_onwire/": AllC(StatusC(LIBSSH, in_error="Socket error: File exists"), TermContainsC(LIBSSH, in_term="fn_onwire_message")),
    "bootstrap_socket_error_packet/": AllC(StatusC(LIBSSH, in_error="Socket error: File exists"), TermContainsC(LIBSSH, in_term="fn_packet")),
    "bootstrap_socket_error_encrypt/": AllC(StatusC(LIBSSH, in_error="Socket error: File exists"), TermContainsC(LIBSSH, in_term="fn_encrypt_packet")),

    # ─────────────────────────────────────────────────────────────────────────
    # ACCEPT-vs-REJECT DIVERGENCES — NOT benign, collected for manual audit.
    #
    # These capture the case one stack COMPLETES the trace (Success, error is None)
    # while the other REJECTS it — i.e. one implementation accepts an input the
    # other refuses. That is a real behavioural divergence (potential leniency /
    # over-acceptance bug), NOT implementation latitude, so it must NOT land in any
    # benign bucket. They are placed HERE — after the two documented-benign
    # accept-vs-reject classes (banner over-permissiveness = wolfSSH accepts a
    # banner libssh rejects; and the libssh step-0 socket harness artifact), which
    # are matched first above — and BEFORE all the "benign only when both reject"
    # internal-error buckets below, so an accept-vs-reject trace is siphoned into
    # its own explicit, countable audit pile instead of leaking into a benign
    # bucket. (This is what a pre-fix run did: libssh-Success/wolfSSH-reject traces
    # were being filed under wolfssh_invalid_state / would_overflow / etc.)
    #
    # "success" is expressed as NotC(<that PUT errored>): StatusC(put,
    # first_to_fail=False) is true iff that PUT's own status.error is non-None, so
    # NotC(...) is true iff it completed with error None.
    "diverge_libssh_accepts_wolfssh_rejects/": AllC(
        NotC(StatusC(LIBSSH, first_to_fail=False)),  # libssh completed (error is None)
        StatusC(WOLFSSH, first_to_fail=False),       # wolfSSH errored
    ),
    "diverge_wolfssh_accepts_libssh_rejects/": AllC(
        NotC(StatusC(WOLFSSH, first_to_fail=False)),  # wolfSSH completed (error is None)
        StatusC(LIBSSH, first_to_fail=False),         # libssh errored (non-banner: banner matched above)
    ),

    # RFC 4252 §5 USERAUTH service-name divergence (wolfSSH; rediscovered by DDYF from
    # honest seeds, fixed on wolfSSH master). Unlike the accept-vs-reject buckets above,
    # BOTH stacks complete WITHOUT a status error — the divergence is in the AUTH OUTCOME
    # inside the decrypted transcript: wolfSSH accepts a USERAUTH_REQUEST whose service
    # name != "ssh-connection" and reaches USERAUTH_SUCCESS (msg 52) + ChannelOpen, where
    # libssh refuses with USERAUTH_FAILURE (msg 51). That is a real security-state
    # divergence (it is NOT shadowed and must NOT fall into a benign bucket), so it gets
    # its own countable audit pile. Placed before the benign_decrypt_* buckets so it wins.
    # Reproducer: the `bad_service` eval probe (seed_client_attacker_bad_service).
    "diverge_wolfssh_accepts_bad_service/": AllC(
        InnerKnowledgeC(diff_contains="Added(AlignmentKey { channel: 0, msg_number: 52, ordinal: 0 }, UserAuthSuccess)"),
        InnerKnowledgeC(diff_contains="Removed(AlignmentKey { channel: 0, msg_number: 51"),
    ),

    # wolfSSH UNSOLICITED SERVICE_ACCEPT (found 2026-09-23 by the multi-round-trip
    # seed; reported in SERVICE_ACCEPT_FINDING.md). A client that skips SERVICE_REQUEST
    # and sends USERAUTH_REQUEST straight away is authenticated by BOTH stacks, but
    # wolfSSH's accept() state machine (ssh.c ~557-569) then also emits a
    # SERVICE_ACCEPT nobody asked for, right before USERAUTH_SUCCESS; libssh sends
    # none. RFC 4253 §10 puts the obligation on the client, so this is an unspecified
    # deviation, LOW, no security impact; still present on wolfSSH master.
    # Pinned exactly: the ONLY transcript change is that one added (6,0)
    # ServiceAccept, sitting where libssh has USERAUTH_SUCCESS (U8Change(52, 6)),
    # and no Status/Claim difference. Mixed cases stay unbucketed for audit.
    "known_wolfssh_unsolicited_service_accept/": AllC(
        OnlyDiffKindsC("Knowledges"),
        InnerKnowledgeReC(
            r"\[ByKey\(\[Added\(AlignmentKey \{ channel: 0, msg_number: 6, ordinal: 0 \}, "
            r"ServiceAccept\(ServiceAcceptMessageDesc \{ service_name: SshBytesDesc\(\[[0-9, ]*\]\) \}\)\)\]\), "
            r"Order\(\[.*U8Change\(52, 6\).*\]\)\]"
        ),
    ),
    # REPEATED SERVICE_REQUEST (same campaign): when the client sends SERVICE_REQUEST
    # again (e.g. after auth or after a channel closed), libssh answers every one with
    # another SERVICE_ACCEPT (ordinal >= 1 on libssh only = "Removed" in the diff),
    # while wolfSSH answers only the first and stays silent afterwards. Behavioural
    # latitude around a request a real client never repeats; no acceptance or
    # auth-state difference. Pinned exactly: the ONLY transcript changes are
    # extra (6, ordinal>=1) ServiceAccepts on the libssh side, no Status/Claim diff.
    "known_repeated_service_request_reply/": AllC(
        OnlyDiffKindsC("Knowledges"),
        InnerKnowledgeReC(
            r"\[ByKey\(\[Removed\(AlignmentKey \{ channel: 0, msg_number: 6, ordinal: [1-9][0-9]* \}\)"
            r"(, Removed\(AlignmentKey \{ channel: 0, msg_number: 6, ordinal: [1-9][0-9]* \}\))*\]\)"
            r"(, Order\(\[.*\]\))?\]"
        ),
    ),

    # AUDITED (tightened 2026-09-02 with BOTH_ERROR + mirror direction).
    # A claim-presence diff (one PUT emitted the session-id/H claim, the other did
    # not) means exactly one stack finalised KEX. Guard BOTH_ERROR so a case where
    # one stack COMPLETES the handshake while the other fails at KEX is NOT masked
    # as benign (it would be a real KEX-acceptance divergence → manual audit). Both
    # directions covered: libssh-has-claim (original) and wolfSSH-has-claim (mirror,
    # possible after the harness claim-timing alignment).
    "bootstrap_claim_presence/": AllC(
        AnyC(
            DifferentClaimC(in_first_type="alloc::boxed::Box<sshpuffin::claim::SshClaimInner>", in_second_type="()"),
            DifferentClaimC(in_first_type="()", in_second_type="alloc::boxed::Box<sshpuffin::claim::SshClaimInner>"),
        ),
        BOTH_ERROR,
    ),
    # AUDITED
    "bootstrap_unknown_error_code/": AllC(StatusC(WOLFSSH, in_error="Unknown error code"), TermContainsC(WOLFSSH, in_term="fn_encrypt_packet")),
    # AUDITED
    "wolfssh_invalid_state/": AllC(StatusC(WOLFSSH, in_error="invalid state"), TermContainsC(WOLFSSH, in_term="fn_banner")),
    # AUDITED
    "wolfssh_io_buffer_size_error/": AllC(StatusC(WOLFSSH, in_error="input/output buffer size error"), TermContainsC(WOLFSSH, in_term="fn_encrypt_packet")),
    # AUDITED
    "wolfssh_would_overflow/": AllC(StatusC(WOLFSSH, in_error="would overflow if continued failure"), TermContainsC(WOLFSSH, in_term="fn_encrypt_packet")),
    # AUDITED
    "wolfssh_bad_function_argument/": AllC(StatusC(WOLFSSH, in_error="bad function argument"), TermContainsC(WOLFSSH, in_term="fn_encrypt_packet")),
    # AUDITED
    "wolfssh_invalid_channel_id/": AllC(StatusC(WOLFSSH, in_error="peer requested invalid channel id"), TermContainsC(WOLFSSH, in_term="fn_encrypt_packet")),
    # AUDITED
    "wolfssh_out_of_order/": AllC(StatusC(WOLFSSH, in_error="out of order message"), TermContainsC(WOLFSSH, in_term="fn_encrypt_packet")),
    # AUDITED
    "wolfssh_message_not_allowed/": AllC(StatusC(WOLFSSH, in_error="message not allowed before user authentication"), TermContainsC(WOLFSSH, in_term="fn_onwire_message")),
    # wolfSSH's pre-auth message gating firing on an ENCRYPTED post-KEX packet: the
    # attacker sends a channel operation (CHANNEL_OPEN/WINDOW_ADJUST/DATA/… via
    # fn_encrypt_packet_aesgcm) before authentication completes, and wolfSSH rejects
    # it with "message not allowed before user authentication". Same benign root
    # cause as the fn_onwire_message variant above, one layer up (encrypted). This
    # is reached only after the accept-vs-reject `diverge_*` buckets (matched first),
    # so libssh did NOT complete either — both reject. wolfSSH's defensive auth
    # ordering, RFC 4252 §10; NIL security impact. (Largest unbucketed class before
    # this bucket: ~51% of the residual tail.)
    "wolfssh_message_not_allowed_encrypt/": AllC(StatusC(WOLFSSH, in_error="message not allowed before user authentication"), TermContainsC(WOLFSSH, in_term="fn_encrypt_packet")),
    # libssh's defensive packet filter rejects an out-of-context message. Originally
    # only `type 7)` was bucketed; a 1M-objective sample shows the same filter firing
    # on many message numbers (types 5,20,21,30,31,52,53,80,81,82,93,94,96,97,98,99…)
    # as mutations move messages out of their allowed KEX/auth phase. Match the libssh
    # filter string generically (any type). Benign: a defensive strictness check, and
    # any case where libssh REJECTS while wolfSSH ACCEPTS was already siphoned into the
    # accept-vs-reject audit pile above, so this only sees libssh-strictness rejections.
    "libssh_packet_filter_rejected/": StatusC(LIBSSH, in_error="Packet filter: rejected packet", first_to_fail=False),

    # ─────────────────────────────────────────────────────────────────────────
    # BENIGN both-reject internal rejections (added from the 1M-objective sample).
    #
    # These name the recurring PUT-internal rejection strings that were the bulk of the
    # unbucketed tail. Every one is AND-ed with BOTH_ERROR, so a trace where either
    # stack COMPLETED (an acceptance divergence) can NEVER match — it is already caught
    # by the `diverge_*` audit piles above, which are ordered before this section. With
    # both stacks rejecting a mutated input, the *reason* each gives is benign latitude
    # (defensive bounds checks, algorithm-negotiation mismatches, phase/state gating,
    # or the mapper failing to decode a rejected peer's non-reply); no protocol or
    # security divergence. `first_to_fail=False` reads each PUT's OWN status so the
    # match is independent of which stack stopped first.

    # CLIENT-side (server-attacker traces, where the PUT is the CLIENT): both clients
    # reject a mutated KEX_ECDH_REPLY (host key / signature / exchange value), each with
    # its own error. Scoped by the trace shape (the attacker sends fn_kex_ecdh_reply,
    # which only server-attacker traces do) and keyed on wolfSSH's client errors;
    # libssh's error text is deliberately not keyed on, since it depends on exactly
    # where libssh's parser stops on the mutated reply. (Before per-PUT re-runs were
    # uniformised, see PUFFIN_TRIAGE_UNIFORMISE above, the libssh client's single-PUT
    # run even negotiated other algorithms than the differential and so failed
    # elsewhere; that, not randomness, made its error look unstable.) BOTH_ERROR
    # keeps any case where one client ACCEPTS the reply out of here (diverge_* above).
    "benign_client_kex_reply_reject/": AllC(
        TermContainsC(LIBSSH, in_term="fn_kex_ecdh_reply"),
        OnlyDiffKindsC("Status"),
        AnyC(
            StatusC(WOLFSSH, in_error="RSA buffer error", first_to_fail=False),
            StatusC(WOLFSSH, in_error="general parsing error", first_to_fail=False),
            StatusC(WOLFSSH, in_error="crypto action failed", first_to_fail=False),
        ),
        BOTH_ERROR,
    ),

    # wolfSSH internal rejections — the term-agnostic superset of the fn_encrypt_packet
    # buckets above (catches the same errors on fn_banner / fn_packet / fn_kex_* terms).
    "benign_wolfssh_internal_reject/": AllC(
        AnyC(
            StatusC(WOLFSSH, in_error="Unknown error code", first_to_fail=False),
            StatusC(WOLFSSH, in_error="would overflow if continued failure", first_to_fail=False),
            StatusC(WOLFSSH, in_error="input/output buffer size error", first_to_fail=False),
            StatusC(WOLFSSH, in_error="bad function argument", first_to_fail=False),
            StatusC(WOLFSSH, in_error="invalid state", first_to_fail=False),
            StatusC(WOLFSSH, in_error="peer requested invalid channel id", first_to_fail=False),
            StatusC(WOLFSSH, in_error="out of order message", first_to_fail=False),
            StatusC(WOLFSSH, in_error="message not allowed before user authentication", first_to_fail=False),
            StatusC(WOLFSSH, in_error="channel closed", first_to_fail=False),
        ),
        BOTH_ERROR,
    ),
    # wolfSSH algorithm-negotiation mismatches on mutated KEXINIT algorithm lists.
    "benign_wolfssh_negotiation_mismatch/": AllC(
        AnyC(
            StatusC(WOLFSSH, in_error="cannot match encrypt algo with peer", first_to_fail=False),
            StatusC(WOLFSSH, in_error="cannot match key algo with peer", first_to_fail=False),
            StatusC(WOLFSSH, in_error="cannot match KEX algo with peer", first_to_fail=False),
            StatusC(WOLFSSH, in_error="invalid algorithm id", first_to_fail=False),
            StatusC(WOLFSSH, in_error="unable to match user auth key type", first_to_fail=False),
            StatusC(WOLFSSH, in_error="peer version unsupported", first_to_fail=False),
        ),
        BOTH_ERROR,
    ),
    # libssh KEX / crypto / framing rejections of a mutated input.
    "benign_libssh_kex_crypto_reject/": AllC(
        AnyC(
            StatusC(LIBSSH, in_error="kex error : no match for method", first_to_fail=False),
            StatusC(LIBSSH, in_error="Could not generate shared secret", first_to_fail=False),
            StatusC(LIBSSH, in_error="Invalid padding", first_to_fail=False),
        ),
        BOTH_ERROR,
    ),
    # Mapper/replay artifact: the trace mutation left a step whose term cannot be built,
    # or the PUT's rejection means its response cannot be decoded into the message the
    # recipe expected ("Expected SshMessage::X"). A consequence of rejecting a mutated
    # input, on EITHER side; guarded BOTH_ERROR so it never hides a one-side completion.
    "benign_mapper_malformed_or_unbound/": AllC(
        AnyC(
            StatusC(LIBSSH, in_error="error executing a function symbol", first_to_fail=False),
            StatusC(WOLFSSH, in_error="error executing a function symbol", first_to_fail=False),
            StatusC(LIBSSH, in_error="error evaluating a term", first_to_fail=False),
            StatusC(WOLFSSH, in_error="error evaluating a term", first_to_fail=False),
        ),
        BOTH_ERROR,
    ),

    # ─────────────────────────────────────────────────────────────────────────
    # BENIGN decryption-recipe divergences.
    #
    # These are cross-vendor differences observed in the DECRYPTED s2c message
    # streams (Source::Label("Decryption")). After flight decryption + semantic
    # alignment, the objective filter is fail-closed and keeps them as objectives
    # (rather than silently whitelisting), and we classify them here as BENIGN via
    # a precise per-shape bucket condition (mirroring the TLS triaging pipeline).
    #
    # Each was confirmed benign by transport-level instrumentation of both stacks:
    # they are implementation latitude in HOW each stack packetizes replies and
    # WHEN it flushes a control reply relative to reading the next packet — RFC
    # 4253/4254 permit this — not a protocol or security divergence. A message can
    # therefore appear on one PUT's decrypted stream only (kind vs "()").
    #
    # NOTE: these buckets match on the KNOWLEDGE (decryption) diff shape, which is
    # exactly what these objectives carry. A genuinely new decryption divergence
    # will NOT match any BENIGN bucket and will stand out for manual audit.

    # libssh replies to CHANNEL_OPEN with CHANNEL_OPEN_CONFIRMATION at a packet
    # position wolfSSH does not (channel-setup packetization). Either direction.
    "benign_decrypt_channel_open_confirmation/": AnyC(
        KnowledgeDiffC(first_type_name="SshMessage::ChannelOpenConfirmation", second_type_name="()"),
        KnowledgeDiffC(first_type_name="()", second_type_name="SshMessage::ChannelOpenConfirmation"),
    ),
    # wolfSSH acknowledges the CHANNEL_REQUEST with CHANNEL_SUCCESS where libssh
    # does not (want_reply handling differs). Either direction.
    "benign_decrypt_channel_success/": AnyC(
        KnowledgeDiffC(first_type_name="SshMessage::ChannelSuccess", second_type_name="()"),
        KnowledgeDiffC(first_type_name="()", second_type_name="SshMessage::ChannelSuccess"),
    ),
    # ServiceAccept appears on one decrypted stream only (reply pipelining).
    "benign_decrypt_service_accept/": AnyC(
        KnowledgeDiffC(first_type_name="SshMessage::ServiceAccept", second_type_name="()"),
        KnowledgeDiffC(first_type_name="()", second_type_name="SshMessage::ServiceAccept"),
    ),
    # CHANNEL_FAILURE / CHANNEL_OPEN_FAILURE on one stream only. Same
    # channel-control framing / numbering class as channel_open_confirmation /
    # channel_success: the seed's fixed recipient_channel matches one stack's
    # channel numbering but not the other's, so a channel reply lands on one
    # decrypted stream only. Benign.
    "benign_decrypt_channel_failure/": AnyC(
        KnowledgeDiffC(first_type_name="SshMessage::ChannelFailure", second_type_name="()"),
        KnowledgeDiffC(first_type_name="()", second_type_name="SshMessage::ChannelFailure"),
    ),
    "benign_decrypt_channel_open_failure/": AnyC(
        KnowledgeDiffC(first_type_name="SshMessage::ChannelOpenFailure", second_type_name="()"),
        KnowledgeDiffC(first_type_name="()", second_type_name="SshMessage::ChannelOpenFailure"),
    ),
    # One stack answers an unexpected/out-of-order message with SSH_MSG_UNIMPLEMENTED
    # (RFC 4253 §11.4 latitude) where the other stays silent. Either direction.
    "benign_decrypt_unimplemented/": AnyC(
        KnowledgeDiffC(first_type_name="SshMessage::Unimplemented", second_type_name="()"),
        KnowledgeDiffC(first_type_name="()", second_type_name="SshMessage::Unimplemented"),
    ),
    # Auth-reply flush timing: one stack emits USERAUTH_FAILURE / USERAUTH_SUCCESS
    # before hitting a subsequent malformed packet, the other dies first without
    # flushing. Both ultimately reject; not a protocol/security divergence.
    #
    # GUARDED with BOTH_ERROR (tightened): the raw shape "UserAuthSuccess vs ()" is
    # over-permissive on its own — if one stack genuinely COMPLETED authentication
    # (trace Success) while the other rejected the same credential, that is a REAL
    # auth-acceptance divergence and MUST NOT be classed benign. BOTH_ERROR requires
    # neither stack completed, so the lone auth reply is a mid-flight flush (both
    # ultimately fail). A one-side-Success case no longer matches → manual audit.
    "benign_decrypt_userauth_failure/": AllC(
        AnyC(
            KnowledgeDiffC(first_type_name="SshMessage::UserAuthFailure", second_type_name="()"),
            KnowledgeDiffC(first_type_name="()", second_type_name="SshMessage::UserAuthFailure"),
        ),
        BOTH_ERROR,
    ),
    "benign_decrypt_userauth_success/": AllC(
        AnyC(
            KnowledgeDiffC(first_type_name="SshMessage::UserAuthSuccess", second_type_name="()"),
            KnowledgeDiffC(first_type_name="()", second_type_name="SshMessage::UserAuthSuccess"),
        ),
        BOTH_ERROR,
    ),

    # ─────────────────────────────────────────────────────────────────────────
    # BENIGN decrypted-transcript INNER divergences (AlignedTranscript InnerDifference).
    #
    # The benign_decrypt_* buckets above match the DifferentTypes shape (a whole
    # decrypted message present on one side only: `SshMessage::X vs ()`). The
    # buckets below match the *inner* shape: BOTH sides produced an AlignedTranscript
    # and they differ INSIDE it on one aligned key (`InnerKnowledgeC`, diff string
    # `[ByKey([Removed/Added/Changed(AlignmentKey { …, msg_number: N, … })])]`).
    # These are the reply-framing/flow-control latitude classes RFC 4253/4254 permit;
    # matched on a PRECISE msg_number + presence/shape so a genuinely new inner
    # divergence (e.g. a Changed on a security-bearing message) matches none and is
    # surfaced for audit. Reached only after the accept-vs-reject / claim / status
    # buckets, so these are not acceptance divergences.

    # CHANNEL_WINDOW_ADJUST (msg 93) present on one decrypted stream only: server
    # flow-control window management is advisory (RFC 4254 §5.2) — one stack grants a
    # window adjust the other does not. Presence-only (Added/Removed), so a content
    # Changed on msg 93 would NOT match. Benign. (Largest transcript-inner class.)
    "benign_decrypt_window_adjust_presence/": AnyC(
        InnerKnowledgeC(diff_contains="Removed(AlignmentKey { channel: 0, msg_number: 93"),
        InnerKnowledgeC(diff_contains="Added(AlignmentKey { channel: 0, msg_number: 93"),
    ),
    # Both stacks REJECT the channel open with CHANNEL_OPEN_FAILURE (msg 92) but pick
    # a different reason code / description (`BothChannelOpenFailure([ReasonCode(
    # U32Change(...)), Description(...)])`). The `Both…` confirms both refused → not an
    # accept-vs-reject; RFC 4254 §5.1 leaves the reason code to the server. Benign.
    "benign_decrypt_channel_open_failure_reasoncode/": InnerKnowledgeC(diff_contains="BothChannelOpenFailure"),
    # RFC 4253 §7.1 incomplete-rekey marker: one stack emits a SECOND KEXINIT
    # (msg 20, ordinal 1 = a rekey) that the other withholds. This is the KNOWN §7.1
    # class (the counter-renumbering preprocess_trace pass makes it fuzz-discoverable);
    # naming it keeps it out of the unbucketed noise. NOTE it marks the *presence* of a
    # rekey KEXINIT only — the real §7.1 concern (traffic PROCESSED during an
    # incomplete rekey, ledger #2) manifests as DIFFERENT downstream messages
    # (SERVICE_ACCEPT / USERAUTH_SUCCESS after the 2nd KEXINIT) and is NOT masked here.
    "known_rekey_kexinit_presence/": InnerKnowledgeC(diff_contains="AlignmentKey { channel: 0, msg_number: 20, ordinal: 1 }"),
    # SSH_MSG_UNIMPLEMENTED (msg 3) present on one decrypted stream only: one stack
    # answers an unexpected/out-of-order message with UNIMPLEMENTED (RFC 4253 §11.4
    # latitude) where the other stays silent. Presence-only; the DifferentTypes variant
    # is `benign_decrypt_unimplemented` above — this is its InnerDifference counterpart.
    "benign_decrypt_unimplemented_presence/": AnyC(
        InnerKnowledgeC(diff_contains="Removed(AlignmentKey { channel: 0, msg_number: 3,"),
        InnerKnowledgeC(diff_contains="Added(AlignmentKey { channel: 0, msg_number: 3,"),
    ),
    # Channel teardown ordering: one stack sends CHANNEL_EOF (msg 96) where the other
    # sends CHANNEL_CLOSE (msg 97) at that position (`MsgNumber(U8Change(96, 97))`), a
    # framing/ordering latitude at end-of-channel (RFC 4254 §5.3). Both tear the channel
    # down; benign.
    "benign_decrypt_channel_eof_close_order/": InnerKnowledgeC(diff_contains="MsgNumber(U8Change(96, 97))"),

    # ─────────────────────────────────────────────────────────────────────────
    # BENIGN KEX-phase packet-length strictness (added 2026-09-02).
    #
    # On a mutation that corrupts a KEX-phase packet, libssh's stricter
    # read_packet() length check rejects EARLY (`Packet len too high`, often
    # reading banner ASCII "SSH-"/0x5353482d as a length after a framing desync),
    # so it never finalises KEX (no session_id / exchange hash H) and its s2c
    # decryption recipe yields NO transcript. wolfSSH parses the same input
    # further (completes KEX, sets sessionId, emits s2c) before its OWN failure.
    # BOTH ultimately reject — a real strictness difference, benign, same family as
    # the banner-strictness class one protocol layer up. NIL security impact.
    #
    # Two shapes depending on whether the stacks stop at the same step:
    #   * different steps  -> a Status diff (libssh first-to-fail, Packet len too high)
    #   * same step        -> no Status diff, only a Knowledge/Claim DifferentTypes
    #                         (AlignedTranscript vs () — one decrypted, the other not)
    # Both shapes are GUARDED so a one-side-SUCCESS case can never be masked:
    #   - Status shape requires wolfSSH ALSO errored (StatusC WOLFSSH first_to_fail=False)
    #   - Knowledge shape requires BOTH_ERROR
    "benign_kex_packet_len_too_high/": AllC(
        StatusC(LIBSSH, in_error="read_packet(): Packet len too high"),
        StatusC(WOLFSSH, first_to_fail=False),
    ),
    "benign_kex_decrypt_transcript_presence/": AllC(
        AnyC(
            KnowledgeDiffC(first_type_name="()", second_type_name="sshpuffin::ssh::transcript::AlignedTranscript"),
            KnowledgeDiffC(first_type_name="sshpuffin::ssh::transcript::AlignedTranscript", second_type_name="()"),
        ),
        BOTH_ERROR,
    ),
}

if __name__ == "__main__":
    objective_folder = sys.argv[1] if len(sys.argv) > 1 else "objective"
    run_triaging(
        buckets,
        FIRST_PUT,
        SECOND_PUT,
        source_folder=objective_folder,
        target_folder=objective_folder,
        parallelism=PARALLELISM,
    )
