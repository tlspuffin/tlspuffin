import sys

from .diff_analyzer import (
    BucketCondition,
    NoDiffC,
    run_triaging,
)

PARALLELISM = 20

buckets: dict[str, BucketCondition] = {
    # No differences reported
    "no_errors/": NoDiffC(),
}

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(
            f"Usage: {sys.argv[0]} <first_put> <second_put> [objective_folder]",
            file=sys.stderr,
        )
        sys.exit(1)
    first_put = sys.argv[1]
    second_put = sys.argv[2]
    objective_folder = sys.argv[3] if len(sys.argv) > 3 else "objective"
    run_triaging(
        buckets,
        first_put,
        second_put,
        source_folder=objective_folder,
        target_folder=objective_folder,
        parallelism=PARALLELISM,
    )
