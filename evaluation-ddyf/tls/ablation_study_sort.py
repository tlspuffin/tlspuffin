import sys
from DDYF.diff_analyzer import (
    BucketCondition,
    NoDiffC,
    run_triaging,
)

OSSL = 1
WOLF = 2
FIRST_PUT = "openssl340"
SECOND_PUT = "wolfssl580"
PARALLELISM = 20

buckets: dict[str, BucketCondition] = {
    # No differences reported
    "no_errors/": NoDiffC(),
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
