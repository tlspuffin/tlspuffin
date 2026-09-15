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
