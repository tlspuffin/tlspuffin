"""The root-cause census of an SSH objective folder: the key (ssh_rootcause.root_cause_key) of every
objective, which gen_rootcause_table.py turns into rootcause_table.ROWS.

From the repository root, once Phase 0 has run on the folder (phase0_produce_metadata.sh):
    ln -sfn evaluation-ddyf evaluation_ddyf   # once: `python -m` needs an importable name
    PUFFIN_PATH=target/release/sshpuffin \\
        python3 -m evaluation_ddyf.ssh.rootcause_census <objective folder> <census.jsonl>

Each objective is read from its Phase-0 differential record (metadata_diff_<trace>.json) and replayed
on each PUT (display-execute --json --uniformise), as the sort does. Environment: SSHPUFFIN_FIRST_PUT
(libssh0114), SSHPUFFIN_SECOND_PUT (wolfssh150), SSHPUFFIN_TRIAGE_PARALLELISM (processes, 24),
PUFFIN_TRIAGE_TIMEOUT (seconds per execution, 5; more on a loaded machine).

One JSON object per objective: `trace`, `key` (null when a replay or a classifier failed, with
`error`, and `classifier` when it was one), `named` (every documented mechanism the objective
exhibits, the first being its key), `libssh_accepted` (for an AES-GCM key), the two statuses of the
differential record and each PUT's own error (from which the generator names error codes).
"""

import json
import os
import sys
from collections import Counter
from multiprocessing import Pool

from .. import diff_analyzer
from . import ssh_rootcause

FIRST_PUT = os.environ.get("SSHPUFFIN_FIRST_PUT", "libssh0114")
SECOND_PUT = os.environ.get("SSHPUFFIN_SECOND_PUT", "wolfssh150")
os.environ.setdefault("PUFFIN_TRIAGE_UNIFORMISE", "1")


def objectives(folder):
    """The traces of `folder` and of its bucket folders, without LibAFL's hidden companion files."""
    for root, _dirs, files in os.walk(folder):
        for name in sorted(files):
            if name.endswith(".trace") and not name.startswith("."):
                yield os.path.join(root, name)


def census_of(path):
    row = {
        "trace": os.path.relpath(path),
        "key": None,
        "named": [],
        "libssh_accepted": None,
        "first_status": None,
        "second_status": None,
        "first_error": None,
        "second_error": None,
        "error": None,
    }
    try:
        es = diff_analyzer.ExecutionStatus(path, FIRST_PUT, SECOND_PUT)
        status = ssh_rootcause.diff_status(es)
        if status is not None:
            row["first_status"], row["second_status"] = status["first_status"], status["second_status"]
        row["key"] = ssh_rootcause.root_cause_key(es)
        row["named"] = getattr(es, "_rc_named", [])
        row["libssh_accepted"] = getattr(es, "_rc_libssh_accepted", None)
        row["first_error"], row["second_error"] = es.put1().get("error"), es.put2().get("error")
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as e:  # get_status raises a bare BaseException on a failed replay
        row["key"] = None
        row["error"] = f"{type(e).__name__}: {e}"[:300]
        failed = [name for trace, name, _ in ssh_rootcause.CLASSIFIER_ERRORS if trace == path]
        if failed:
            row["classifier"] = failed[-1]
    return row


def main(folder, out):
    keys = Counter()
    parallelism = int(os.environ.get("SSHPUFFIN_TRIAGE_PARALLELISM", "24"))
    with Pool(parallelism) as pool, open(out, "w") as fh:
        for row in pool.imap(census_of, objectives(folder), chunksize=16):
            fh.write(json.dumps(row) + "\n")
            keys[row["key"] or "ERROR"] += 1
    print(f"{sum(keys.values())} objectives, {len(keys)} keys; {keys['ERROR']} without a key", file=sys.stderr)
    return 1 if keys["ERROR"] else 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1], sys.argv[2]))
