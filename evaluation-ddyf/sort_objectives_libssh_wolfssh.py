import sys
from .diff_analyzer import (
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
)

LIBSSH = 1
WOLFSSH = 2
FIRST_PUT = "libssh0114-asan"
SECOND_PUT = "wolfssh-asan"
PARALLELISM = 24

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
    # AUDITED
    "libssh_packet_filter_rejected_type_7/": AllC(StatusC(LIBSSH, in_error="type 7)"), TermContainsC(LIBSSH, in_term="fn_packet")),

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
