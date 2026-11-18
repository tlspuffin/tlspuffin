"""Offline triaging of libssh-vs-wolfSSH differential objectives into ROOT-CAUSE buckets.

RE-CUT 2026-09-24 on the 09-23 libssh0114-vs-wolfssh150 corpus. The previous hand-written
bucket set (72 buckets inherited from the 09-18/09-19 campaigns) was validated only on SERVER-role
corpora; on this corpus (19% client-role objectives) it mixed several root causes per bucket
(outcome-keyed buckets holding 36 different wolfSSH rejection checks, status buckets holding
transcript-only divergences via isolated-replay errors, the wolfSSH-client unsolicited
USERAUTH_SUCCESS finding spread over 15 buckets, 6,098 libssh-only authentications inside
"both reject" buckets). That bucket set was never committed; this re-cut replaces it.

Every objective is now mapped to exactly ONE root-cause key -- its observable FIRST divergence,
qualified by role -- by `ssh_rootcause.root_cause_key` (read that module's docstring for the key
families and precedence). Each bucket is "all objectives whose key is K" (RootCauseC), so:
  * buckets are DISJOINT by construction (dict order cannot move a trace between buckets);
  * every bucket holds one observable cause, one role;
  * a PUT-vs-PUT authentication disagreement lands in a benign bucket ONLY if it is a consequence
    of that bucket's cause (the non-authenticating PUT died strictly before the attacker's auth
    step); otherwise it is a named mechanism or the diverge_auth_asymmetry_unexplained_* audit pile.
The bucket list (name, key, tag, explanation, census count) is `rootcause_table.ROWS`, generated
from the full-population census and reviewed. Keys below the census threshold are deliberately
left UNBUCKETED (fail-open residual, top level of objective/).

Usage
-----
    ln -sfn evaluation-ddyf evaluation_ddyf   # once
    PUFFIN_PATH=target/release/sshpuffin python -m evaluation_ddyf.ssh.sort_objectives_libssh_wolfssh [objective_folder]

Environment: SSHPUFFIN_FIRST_PUT (libssh0114), SSHPUFFIN_SECOND_PUT (wolfssh150),
SSHPUFFIN_TRIAGE_PARALLELISM (24), PUFFIN_TRIAGE_UNIFORMISE (1; the keys REQUIRE uniformised
per-PUT replays), PUFFIN_TRIAGE_NO_CACHE (unset).

The in-fuzzer shadow predicates (sshpuffin/src/ssh/differential.rs)
--------------------------------------------------------------------
A difference a shadow predicate drops in the fuzzer never becomes an objective, so it has no
bucket here; each predicate is documented next to its code. A trace whose shadowed difference
comes WITH another difference is an objective, keyed by its first divergence like any other.
    is_banner_length_diff                  SHADOW_KNOWN_BUGS     libssh's banner length limit (libssh-mirror#376)
    is_version_strictness_diff             SHADOW_KNOWN_BENIGN   version-string strictness
    is_banner_induced_transcript_presence  with either above     a transcript present on one side after a banner reject
    is_userauth_failure_only_diff          SHADOW_KNOWN_BENIGN   USERAUTH_FAILURE count, when it is the only delta
    is_fwd_reqsuccess_port_echo_diff       SHADOW_KNOWN_BUGS     wolfssh#1246 (a trace with only this difference, taken
                                                                 with the shadow off, is named:known_wolfssh_1246_fwd_port_echo)
    is_rekey_ext_info_s_diff               SHADOW_KNOWN_BUGS     wolfSSH 1.6.0's ext-info-s in a rekey KEXINIT

"""

import os
import sys

from ..diff_analyzer import BucketCondition, run_triaging
from .ssh_rootcause import CLASSIFIER_ERRORS, root_cause_key
from .rootcause_table import ROWS

LIBSSH = 1
WOLFSSH = 2
FIRST_PUT = os.environ.get("SSHPUFFIN_FIRST_PUT", "libssh0114")
SECOND_PUT = os.environ.get("SSHPUFFIN_SECOND_PUT", "wolfssh150")
PARALLELISM = int(os.environ.get("SSHPUFFIN_TRIAGE_PARALLELISM", "24"))
os.environ.setdefault("PUFFIN_TRIAGE_UNIFORMISE", "1")


class RootCauseC(BucketCondition):
    """True iff the objective's root-cause key (ssh_rootcause.root_cause_key) equals `key`."""

    def __init__(self, key: str):
        self.key = key

    def check_condition(self, exec_stat) -> bool:
        # get_status() raises BaseException on an unparseable/timed-out replay; such a trace must
        # stay in the visible residual, not abort the sort (and not be forced into a bucket).
        try:
            return root_cause_key(exec_stat) == self.key
        except (KeyboardInterrupt, SystemExit):
            raise
        except BaseException:
            return False


buckets: dict[str, BucketCondition] = {f"{name}/": RootCauseC(key) for name, key, _tag, _expl, _n in ROWS}

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
    if CLASSIFIER_ERRORS:
        # Each of these traces stays unbucketed: a classifier failed on it (ssh_rootcause.named_mechanisms).
        print(f"WARNING: {len(CLASSIFIER_ERRORS)} classifier error(s); the traces stay unbucketed:", file=sys.stderr)
        for trace, classifier, error in CLASSIFIER_ERRORS[:20]:
            print(f"  {trace}: {classifier}: {error}", file=sys.stderr)
