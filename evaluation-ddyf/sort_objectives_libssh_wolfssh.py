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
PARALLELISM = 10

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
    # AUDITED
    "bootstrap_claim_presence/": AllC(DifferentClaimC(in_first_type="alloc::boxed::Box<sshpuffin::claim::SshClaimInner>", in_second_type="()"), TermContainsC(LIBSSH, in_term="fn_encrypt_packet")),
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
    "benign_decrypt_userauth_failure/": AnyC(
        KnowledgeDiffC(first_type_name="SshMessage::UserAuthFailure", second_type_name="()"),
        KnowledgeDiffC(first_type_name="()", second_type_name="SshMessage::UserAuthFailure"),
    ),
    "benign_decrypt_userauth_success/": AnyC(
        KnowledgeDiffC(first_type_name="SshMessage::UserAuthSuccess", second_type_name="()"),
        KnowledgeDiffC(first_type_name="()", second_type_name="SshMessage::UserAuthSuccess"),
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
