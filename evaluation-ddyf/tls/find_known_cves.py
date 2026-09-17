import sys
from .diff_analyzer import (
    TrueC,
    run_triaging,
    BucketCondition,
    AllC,
    NotC,
    StatusC,
    CheckAgentC,
    TermContainsC,
    ClaimContainsC,
)

OSSL = 1
WOLF = 2
FIRST_PUT = "openssl340"
SECOND_PUT = "wolfssl510"
PARALLELISM = 20

buckets: dict[str, BucketCondition] = {
    "CVE-2023-3724/": AllC(
        CheckAgentC(["protocol_config", "typ"], "Client"),
        StatusC(
            OSSL,
            in_error="final_key_share:no suitable key share",
        ),
    ),
    "CVE-2023-6937/": AllC(
        CheckAgentC(["protocol_config", "typ"], "Client"),
        StatusC(
            OSSL,
            in_error="tls_process_server_hello:not on record boundary",
        ),
        TermContainsC(WOLF, "fn_coalesced_flight"),
    ),
    "CVE-2022-25638/": AllC(
        CheckAgentC(["protocol_config", "typ"], "Server"),
        StatusC(
            OSSL,
            in_error="tls12_check_peer_sigalg:wrong signature type",
        ),
        ClaimContainsC(WOLF, r".*master_secret: \[[1-9][0-9]*,.*"),
        NotC(ClaimContainsC(OSSL, r".*master_secret: \[[1-9][0-9]*,.*")),
    ),
    "CVE-2022-25640/": AllC(
        CheckAgentC(["protocol_config", "typ"], "Server"),
        StatusC(
            OSSL,
            in_error="ossl_statem_server_read_transition:unexpected message",
        ),
        ClaimContainsC(WOLF, r".*master_secret: \[[1-9][0-9]*,.*"),
        NotC(ClaimContainsC(OSSL, r".*master_secret: \[[1-9][0-9]*,.*")),
    ),
    "trash/": TrueC(),
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
