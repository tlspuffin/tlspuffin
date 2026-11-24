import json
import subprocess
import os
from pathlib import Path
from typing import Callable, Any
import re
from multiprocessing.pool import ThreadPool as Pool
# from pathos.multiprocessing import Pool
from functools import reduce
from functools import partial


OSSL = 1
WOLF = 2
PUFFIN_PATH = Path(os.environ.get("PUFFIN_PATH", "target/release/tlspuffin"))

# Traces whose differential execution could not be parsed (timeout, sanitizer
# abort, no JSON on stdout). Collected across threads and reported as a warning
# at the end of run_triaging so a few bad executions do not go unnoticed.
SKIPPED_TRACES: list[str] = []

# Recorded by TranscriptPhaseAtLeastC when an `extra_knowledges` entry advertises an
# "order:" list but no AlignmentKey parses out of it. That means the Rust Debug rendering
# the regex is coupled to has changed, and every affected condition would silently go
# False -- migrating traces into whichever bucket NOTs it. Surfaced loudly at end of run
# (see run_triaging) rather than failing silently. Audit 1 round 3 note 2, 2026-09-20.
TRANSCRIPT_PARSE_ANOMALIES: list[str] = []


def execution_timeout() -> float:
    """Seconds one execution of a trace may take: PUFFIN_TRIAGE_TIMEOUT, 5 by default. A loaded
    machine can need more; a trace that takes longer is skipped (get_diff) or fails (get_status)."""
    return float(os.environ.get("PUFFIN_TRIAGE_TIMEOUT", "5"))


def get_diff(trace: str, first_put: str, second_put: str) -> list[dict]:
    """
    Get the differential-execute diffs between `first_put` and `second_put` for `trace`.

    Prefers the Phase-0 cache (`metadata_diff_<trace>.json`, co-located with the trace):
    that file is the stdout of `differential-execute --json` pre-baked by
    phase0_produce_metadata.sh, so reading it avoids a live re-execution per trace and
    honours the "preprocess once, then text-only analysis" design of Phase 0. Falls back to
    executing the binary when the cache is absent (older campaigns / trace not yet
    preprocessed), unreadable/partial, or when PUFFIN_TRIAGE_NO_CACHE is set (force a fresh
    run, e.g. after rebuilding the binary without re-running Phase 0).
    """
    cached = os.path.join(
        os.path.dirname(trace), f"metadata_diff_{os.path.basename(trace)}.json"
    )
    if not os.environ.get("PUFFIN_TRIAGE_NO_CACHE") and os.path.isfile(cached):
        try:
            with open(cached) as fh:
                return json.load(fh)
        except Exception:
            # Empty / partial / stale-format cache: fall through to a live run rather
            # than mis-classifying on garbage.
            pass
    try:
        # subprocess.run must be INSIDE the try: on timeout it raises
        # subprocess.TimeoutExpired (not a JSON error), and that must be recorded
        # and skipped like any other un-parseable execution rather than aborting
        # the whole thread-pool run.
        result = subprocess.run(
            [PUFFIN_PATH, "differential-execute", "--json", first_put, second_put, trace],
            timeout=execution_timeout(),
            capture_output=True,
        )
        return json.loads(result.stdout)
    except Exception:
        # A single un-parseable execution (timeout, sanitizer abort, no JSON on
        # stdout) must not abort the whole triaging run: record and skip it so it
        # is surfaced in the end-of-run warning instead of crashing the pool.
        SKIPPED_TRACES.append(trace)
        return None


def uniformise_single_runs() -> bool:
    """
    Whether the per-PUT re-executions (get_status) apply the differential config
    uniformisation (`display-execute --uniformise`), i.e. run each PUT under the SAME
    config as the `differential-execute` that produced the objective. Without it a
    per-PUT run can take a different path (another negotiated suite, hence another
    error), so status-based buckets are evaluated on a run the objective never had.
    Opt-in via PUFFIN_TRIAGE_UNIFORMISE=1 (the SSH triage sets it) so existing
    pipelines keep their results until re-validated.
    """
    return os.environ.get("PUFFIN_TRIAGE_UNIFORMISE", "0") == "1"


def get_status(trace: str, put: str) -> dict:
    """
    Execute `trace` on `put` and get terms, knowledges, decryption, status and claims
    """
    result = None
    try:
        # subprocess.run inside the try so a timeout (subprocess.TimeoutExpired)
        # is handled the same as a JSON-decode failure below.
        result = subprocess.run(
            [
                PUFFIN_PATH,
                "--put",
                put,
                "display-execute",
                "--json",
                "-t",
                "-k",
                "-c",
                "-p",
                *(["--uniformise"] if uniformise_single_runs() else []),
                trace,
            ],
            timeout=execution_timeout(),
            capture_output=True,
        )
        return json.loads(result.stdout)
    except Exception as e:
        print(e, ":", result.stdout if result is not None else "<no output (timeout)>")
        raise BaseException


def get_error_from_status(status: dict) -> tuple[str, int]:
    error = status.get("first_status")
    put = 1
    if status.get("first_executed_steps") > status.get("second_executed_steps"):
        error = status.get("second_status")
        put = 2
    return (error, put)


def get_error(errors) -> str:
    if len(errors) == 0:
        return "unknown"
    err = errors[0]
    if err.get("Status") is not None:
        status = err.get("Status")
        (error, put_num) = get_error_from_status(status)
        if put_num == 1:
            error = error[32:]
        return error
    elif err.get("Knowledges") is not None:
        if err.get("Knowledges").get("InnerDifference") is not None:
            diff = err.get("Knowledges").get("InnerDifference")
            return f"Knowledge::Inner[{diff.get('type')}]:{diff.get('diff')}"
        elif err.get("Knowledges").get("DifferentTypes") is not None:
            diff = err.get("Knowledges").get("DifferentTypes")
            return f"Knowledge::Different[{diff.get('first_type')}][{diff.get('second_type')}]"
    elif err.get("Claims") is not None:
        if err.get("Claims").get("InnerDifference") is not None:
            diff = err.get("Claims").get("InnerDifference")
            return f"Claim::Inner:{diff.get('diff')}"
        elif err.get("Claims").get("DifferentTypes") is not None:
            diff = err.get("Claims").get("DifferentTypes")
            return (
                f"Claim::Different[{diff.get('first_type')}][{diff.get('second_type')}]"
            )
    return "unknown"


class ExecutionStatus:
    errors: list[dict] = []
    put1_status: dict | None = None
    put2_status: dict | None = None
    filepath: str = ""
    first_put_name: str = ""
    second_put_name: str = ""

    def __init__(self, filepath: str, first_put: str, second_put: str):
        self.errors = get_diff(filepath, first_put, second_put)

        self.filepath = filepath
        self.first_put_name = first_put
        self.second_put_name = second_put

    def put1(self) -> dict:
        if self.put1_status is None:
            self.put1_status = get_status(self.filepath, self.first_put_name)
        return self.put1_status

    def put2(self) -> dict:
        if self.put2_status is None:
            self.put2_status = get_status(self.filepath, self.second_put_name)
        return self.put2_status


class BucketCondition:
    """
    All conditions must inherit this class.

    EXISTENTIAL-SEMANTICS WARNING (audit_4_verdict.md, 2026-09-20): every `*ContainsC` /
    `TermContainsC` / `TermContainsReC` / `KnowledgeContainsC` / `ClaimContainsC` condition below is
    EXISTENTIAL over the steps/claims/knowledges it scans -- it means "at least one occurrence
    matches", not "the/this occurrence matches". Consequently `NotC(SomeContainsC(...))` means "NO
    occurrence anywhere in the trace matches", not "this particular occurrence does not match". On
    a trace with multiple occurrences of the same kind of thing (e.g. two separate
    SERVICE_REQUEST sends, one mutated and one correct, in a compound-retry pattern),
    `NotC(ContainsC(X))` will incorrectly exclude the trace merely because ONE occurrence
    happens to be an X, even though another occurrence is the very thing you were trying to
    detect. This has caused three separate misclassifications in this campaign: an empty
    `ClaimContainsC(auth_method: "")` matching an early empty claim instead of the intended later
    one (round 2), and twice in the SERVICE_REQUEST service-name-gap bucket (once via a
    whitespace-unaware literal substring, once via a `\\s*`-then-lookahead regex that could
    backtrack past the intended anchor -- see `sort_objectives_libssh_wolfssh.py`'s
    `diverge_libssh_accepts_wolfssh_rejects_service_request_svcname_gap/` bucket comment for the
    full history of both). To detect "at least one occurrence has property P" where other
    occurrences with a different property may coexist, write a POSITIVE condition for P directly
    (do not negate a condition for "not P") -- and if using a regex-based `*ReC` primitive with a
    lookahead, anchor the lookahead immediately at the position of interest with no quantifier
    between the anchor and the lookahead, since a greedy quantifier ahead of a lookahead can
    backtrack to a shorter match that spuriously satisfies a negative lookahead one character short
    of the real content.
    """

    def check_condition(self, exec_stat: ExecutionStatus) -> bool:
        return False


class NoDiffC(BucketCondition):
    """
    True if there are no differences between the execution
    """

    def check_condition(self, exec_stat: ExecutionStatus) -> bool:
        return len(exec_stat.errors) == 0


class StepC(BucketCondition):
    """
    Check condition on execution step
    """

    # a function of first executed step, second executed step and total step
    cond: Callable[[int, int, int], bool]

    def check_condition(self, exec_stat: ExecutionStatus) -> bool:
        if exec_stat.errors[0].get("Status") is not None:
            status = exec_stat.errors[0].get("Status")
            (error, put_num) = get_error_from_status(status)
            first: int = status.get("first_executed_steps")
            second: int = status.get("second_executed_steps")
            total: int = status.get("total_step")

            return self.cond(first, second, total)
        return False

    def __init__(self, cond: Callable[[int, int, int], bool]):
        self.cond = cond


class CheckAgentC(BucketCondition):
    key: list[str]
    value: Any

    def __init__(self, key: list[str], value: Any):
        self.key = key
        self.value = value

    def check_condition(self, exec_stat: ExecutionStatus) -> bool:
        first_agent = exec_stat.put1().get("execution").get("agents")[0]
        v = reduce(dict.__getitem__, self.key, first_agent)
        return v == self.value


class StatusC(BucketCondition):
    """
    Check the error status of a PUT and the number of executed steps

    `first_to_fail` checks that `put_num` is the first PUT to fail when executing the trace
    """
    put_num: int
    in_error: str | None
    first_executed_steps: Callable[[int], bool] | None
    second_executed_steps: Callable[[int], bool] | None
    first_to_fail: bool

    def __init__(
        self,
        put_num: int,
        in_error: str | None = None,
        first_executed_steps: Callable[[int], bool] | None = None,
        second_executed_steps: Callable[[int], bool] | None = None,
        first_to_fail: bool = True
    ):
        self.put_num = put_num
        self.in_error = in_error
        self.first_executed_steps = first_executed_steps
        self.second_executed_steps = second_executed_steps
        self.first_to_fail = first_to_fail

    def check_condition(self, exec_stat: ExecutionStatus) -> bool:
        status = exec_stat.put1()
        if self.put_num == 2:
            status = exec_stat.put2()

        error = status["error"]

        if self.first_to_fail:
            if len(exec_stat.errors) > 0:
                s= exec_stat.errors[0].get("Status")
                if s is None:
                    return False
                (error, put_num) = get_error_from_status(s)
                if put_num != self.put_num:
                    return False
            else:
                return False


        if error is None:
            return False

        if (self.in_error is not None) and (self.in_error not in error):
            return False
        elif (
            self.first_executed_steps is not None
        ) and not self.first_executed_steps(exec_stat.put1()["execution"]["executed_until"]):
            return False
        elif (
            self.second_executed_steps is not None
        ) and not self.second_executed_steps(exec_stat.put2()["execution"]["executed_until"]):
            return False
        return True


class InnerKnowledgeC(BucketCondition):
    type_name: str | None
    diff_contains: str

    def __init__(
        self,
        diff_contains: str,
        type_name: str | None = None,
    ):
        self.type_name = type_name
        self.diff_contains = diff_contains

    def check_condition(self, exec_stat: ExecutionStatus) -> bool:
        for err in exec_stat.errors:
            if err.get("Knowledges") is not None and err.get("Knowledges").get(
                "InnerDifference"
            ):
                diff = err.get("Knowledges").get("InnerDifference")
                if (
                    self.type_name is None or self.type_name in diff.get("type_name")
                ) and self.diff_contains in diff.get("diff"):
                    return True
        return False


class InnerKnowledgeReC(BucketCondition):
    """
    Like `InnerKnowledgeC`, but the WHOLE inner-difference string must match the
    regular expression `pattern` (`re.fullmatch`). Use it when a bucket must pin the
    exact shape of the difference, e.g. "the only transcript change is this one added
    message", so that a mixed case with additional changes does not match.
    """

    type_name: str | None
    pattern: "re.Pattern[str]"

    def __init__(self, pattern: str, type_name: str | None = None):
        self.type_name = type_name
        self.pattern = re.compile(pattern, re.DOTALL)

    def check_condition(self, exec_stat: ExecutionStatus) -> bool:
        for err in exec_stat.errors:
            inner = (err.get("Knowledges") or {}).get("InnerDifference")
            if inner is None:
                continue
            if self.type_name is not None and self.type_name not in inner.get("type_name"):
                continue
            if self.pattern.fullmatch(inner.get("diff")):
                return True
        return False


class ByKeyMsgsSubsetC(BucketCondition):
    """
    True iff the decrypted-transcript inner difference has at least one ByKey
    presence/content op on an AlignmentKey, and EVERY such op's `msg_number` is in
    `allowed_msgs` (and its op kind is in `allowed_ops`, when given).

    Only ByKey entries are matched: they carry `AlignmentKey {`, whereas the `Order`
    list carries `AlignmentKeyDesc {`, so the regex below cannot pick up reordering
    entries. Use this to pin "the only per-message differences are on these message
    numbers" without having to spell out a full-diff regex.
    """

    allowed_msgs: set[int]
    allowed_ops: set[str] | None

    def __init__(self, allowed_msgs, allowed_ops=None):
        self.allowed_msgs = set(allowed_msgs)
        self.allowed_ops = set(allowed_ops) if allowed_ops is not None else None

    def check_condition(self, exec_stat: ExecutionStatus) -> bool:
        for err in exec_stat.errors:
            inner = (err.get("Knowledges") or {}).get("InnerDifference")
            if inner is None:
                continue
            ops = re.findall(
                r"(Added|Removed|Changed)\(AlignmentKey \{ channel: \d+, msg_number: (\d+)",
                inner.get("diff", ""),
            )
            if not ops:
                continue
            if self.allowed_ops is not None and any(o not in self.allowed_ops for o, _ in ops):
                return False
            return all(int(n) in self.allowed_msgs for _, n in ops)
        return False


class OnlyDiffKindsC(BucketCondition):
    """
    True iff every difference of the objective is of one of the given kinds (the
    top-level keys of the diff entries: "Status", "Claims", "Knowledges",
    "SecurityClaim", ...) and there is at least one difference.
    """

    kinds: set[str]

    def __init__(self, *kinds: str):
        self.kinds = set(kinds)

    def check_condition(self, exec_stat: ExecutionStatus) -> bool:
        return len(exec_stat.errors) > 0 and all(
            next(iter(err)) in self.kinds for err in exec_stat.errors
        )


class KnowledgeDiffC(BucketCondition):
    first_type_name: str
    second_type_name: str

    def __init__(
        self,
        first_type_name: str,
        second_type_name: str,
    ):
        self.first_type_name = first_type_name
        self.second_type_name = second_type_name

    def check_condition(self, exec_stat: ExecutionStatus) -> bool:
        for err in exec_stat.errors:
            if err.get("Knowledges") is not None and err.get("Knowledges").get(
                "DifferentTypes"
            ):
                diff = err.get("Knowledges").get("DifferentTypes")
                if (
                    diff.get("first_type") == self.first_type_name
                    and diff.get("second_type") == self.second_type_name
                ):
                    return True
        return False


class OnlyKnowledgeC(BucketCondition):
    def check_condition(self, exec_stat: ExecutionStatus) -> bool:
        for err in exec_stat.errors:
            if err.get("Knowledges") is None:
                return False
        return True


class SecurityClaimC(BucketCondition):
    def check_condition(self, exec_stat: ExecutionStatus) -> bool:
        for err in exec_stat.errors:
            if err.get("SecurityClaim") is not None:
                return True
        return False


class DifferentClaimC(BucketCondition):
    in_first_type: str | None
    in_second_type: str | None

    def __init__(
        self,
        in_first_type: str | None = None,
        in_second_type: str | None = None,
    ):
        self.in_first_type = in_first_type
        self.in_second_type = in_second_type

    def check_condition(self, exec_stat: ExecutionStatus) -> bool:
        for err in exec_stat.errors:
            if (
                err.get("Claims") is not None
                and err.get("Claims").get("DifferentTypes") is not None
            ):
                diff = err.get("Claims").get("DifferentTypes")
                if (self.in_first_type is not None) and (
                    self.in_first_type not in diff.get("first_type")
                ):
                    return False
                if (self.in_second_type is not None) and (
                    self.in_second_type not in diff.get("second_type")
                ):
                    return False
                return True
        return False


class OnlyClaimC(BucketCondition):
    def check_condition(self, exec_stat: ExecutionStatus) -> bool:
        for err in exec_stat.errors:
            if err.get("Claims") is None:
                return False
        return True


class TermContainsC(BucketCondition):
    """
    Check if a specific input step contains a specific term/symbol
    """

    put_num: int
    in_term: str
    check_first_input: bool
    last_input_executed: bool

    def __init__(
        self,
        put_num: int,
        in_term: str,
        check_first_input: bool = False,
        last_input_executed: bool = False,
    ):
        self.put_num = put_num
        self.in_term = in_term
        self.check_first_input = check_first_input
        self.last_input_executed = last_input_executed

    def check_condition(self, exec_stat: ExecutionStatus) -> bool:
        status = exec_stat.put1() if self.put_num == 1 else exec_stat.put2()
        executed_until = status.get("execution").get("executed_until")
        is_first_input = True
        for i, s in enumerate(status.get("execution").get("steps")):
            action = s.get("action")
            if type(action) is str:
                continue
            input_term = action.get("Input")
            if self.check_first_input and not is_first_input:
                return False
            if self.last_input_executed and i != executed_until:
                continue
            if input_term is not None:
                if self.in_term in input_term.get("recipe"):
                    return True
            is_first_input = False

        return False


class TermContainsReC(BucketCondition):
    """
    Check if a specific input step contains a specific term/symbol expressed with a regex
    """

    put_num: int
    in_term: str
    check_first_input: bool
    last_input_executed: bool

    def __init__(
        self,
        put_num: int,
        in_term: str,
        check_first_input: bool = False,
        last_input_executed: bool = False,
    ):
        self.put_num = put_num
        self.in_term = in_term
        self.check_first_input = check_first_input
        self.last_input_executed = last_input_executed

    def check_condition(self, exec_stat: ExecutionStatus) -> bool:
        exp = re.compile(self.in_term, re.MULTILINE)
        status = exec_stat.put1() if self.put_num == 1 else exec_stat.put2()
        executed_until = status.get("execution").get("executed_until")
        is_first_input = True
        for i, s in enumerate(status.get("execution").get("steps")):
            action = s.get("action")
            if type(action) is str:
                continue
            input_term = action.get("Input")
            if self.check_first_input and not is_first_input:
                return False
            if self.last_input_executed and i != executed_until:
                continue
            if input_term is not None:
                if exp.search(input_term.get("recipe")):
                    return True
            is_first_input = False
        return False


class RekeyWindowViolationC(BucketCondition):
    """
    True iff, in put_num's OWN decrypted transcript (the extra_knowledges AlignedTranscript's
    `order` list, in message-emission order), that PUT sends a message forbidden by RFC 4253
    section 7.1 while a rekey it is party to (a KEXINIT at ordinal>=1) is still outstanding (the
    matching NEWKEYS at the same ordinal has not yet been sent).

    RFC 4253 section 7.1 (verbatim): "Once a party has sent a SSH_MSG_KEXINIT message for key
    exchange or re-exchange, until it has sent a SSH_MSG_NEWKEYS message, it MUST NOT send any
    messages other than: Transport layer generic messages (1 to 19) (but SSH_MSG_SERVICE_REQUEST
    and SSH_MSG_SERVICE_ACCEPT MUST NOT be sent); Algorithm negotiation messages (20 to 29) (but
    further SSH_MSG_KEXINIT messages MUST NOT be sent); Specific key exchange method messages
    (30 to 49)." This is a live, per-agent, order-sensitive check that the DSL's substring-based
    primitives (InnerKnowledgeC etc.) cannot express -- added specifically because a cold-eye
    audit (2026-09-19) found the two named-bucket approximations for this class (claim-shape and
    error-string based) captured only 29/1,256 and 0/1,256 of the true corpus-wide population.

    This reads status["execution"]["extra_knowledges"] via exec_stat.put1()/put2() -- the SAME
    live per-PUT re-execution ClaimContainsC/KnowledgeContainsC use (not the cached differential
    diff) -- so it is a live-backed, not cache-backed, condition; see get_status()/get_diff()
    docstrings for the two-execution-source distinction this engine has (a cold-eye audit, F7,
    flagged the general risk of mixing the two families within one AllC; this class intentionally
    matches the family of the OTHER live-backed primitives it will most often be combined with).

    SCOPING CAVEAT (audit_4_verdict.md, 2026-09-20): the window only opens on `msg == 20 and
    ordinal >= 1`, i.e. on a re-exchange KEXINIT. A section 7.1 violation during the INITIAL key
    exchange (ordinal 0, before the first NEWKEYS) is invisible to this check, even though the RFC
    text quoted above covers "key exchange OR re-exchange" -- this is a deliberate scope choice for
    a rekey-named class, not an oversight, but any caller expecting this to also police the initial
    handshake should not use it for that.

    Also note: `_order_list` returns the FIRST `extra_knowledges` entry whose value contains
    "order:" -- if a trace ever produced two AlignedTranscripts for the same PUT, only the first
    would be inspected. Harmless against every trace seen in this corpus (each PUT produces exactly
    one), but not structurally guaranteed.
    """

    PERMITTED = (set(range(1, 20)) - {5, 6}) | (set(range(20, 30)) - {20}) | set(range(30, 50))
    _ORDER_ENTRY_RE = re.compile(
        r"AlignmentKey\s*\{\s*channel:\s*\d+,\s*msg_number:\s*(\d+),\s*ordinal:\s*(\d+)\s*\}"
    )

    def __init__(self, put_num: int):
        self.put_num = put_num

    def _order_list(self, status: dict) -> list[tuple[int, int]] | None:
        for entry in status.get("execution", {}).get("extra_knowledges", []):
            value = entry[1] if len(entry) > 1 else ""
            idx = value.find("order:")
            if idx == -1:
                continue
            return [
                (int(msg), int(ordinal))
                for msg, ordinal in self._ORDER_ENTRY_RE.findall(value[idx:])
            ]
        return None

    def check_condition(self, exec_stat: ExecutionStatus) -> bool:
        status = exec_stat.put1() if self.put_num == 1 else exec_stat.put2()
        if status is None:
            return False
        order = self._order_list(status)
        if not order:
            return False
        open_ordinal = None
        for msg, ordinal in order:
            if open_ordinal is None:
                if msg == 20 and ordinal >= 1:
                    open_ordinal = ordinal
            else:
                if msg == 21 and ordinal == open_ordinal:
                    open_ordinal = None
                elif msg not in self.PERMITTED:
                    return True
        return False


class DiffStatusSuccessC(BucketCondition):
    """
    True iff the DIFFERENTIAL record reports `put_num` as "Success".

    Reads `exec_stat.errors[0]["Status"]["{first,second}_status"]` -- i.e. the status produced
    by the `differential-execute` run that created the objective in the first place. That is
    the authoritative oracle for "did this PUT accept the trace".

    WHY THIS EXISTS (Orchestrator, 2026-09-21). `BOTH_ERROR` is built from
    `StatusC(PUT, first_to_fail=False)`, which reads the LIVE standalone
    `display-execute --json` run via `get_status()`. That answers a different question --
    "does this PUT error when run alone" -- and the two disagree. Measured on
    `bootstrap_unknown_error_code/` (668,440 traces), sample 6,000:

        cached (differential) libssh first_status == "Success" :    24  (0.40%)
        live libssh error is not None                          : 6,000
        BOTH_ERROR's libssh half passes (i.e. "errored")       : 6,000  -- including all 24

    So `BOTH_ERROR` does NOT evict differential-run one-side successes, and the module
    docstring's guarantee that this family is "AND-ed with BOTH_ERROR so a one-side success
    can never be masked" does not hold as written. An earlier attempt at this fix simply
    appended `BOTH_ERROR` to the bucket and was a **no-op** (0 traces moved), which is how
    the discrepancy surfaced.

    Scope measured across the BOTH_ERROR family on this corpus: the gap bites only where the
    other clauses let wolfSSH be first-to-fail. `bootstrap_unknown_error_code/` has ~2,841
    estimated; `bootstrap_claim_presence/`, `benign_wolfssh_internal_reject/`,
    `benign_mapper_malformed_or_unbound/`, `benign_libssh_kex_crypto_reject/` and
    `benign_wolfssh_negotiation_mismatch/` each returned 0/4,000.

    Use `NotC(DiffStatusSuccessC(PUT))` to assert "this PUT did NOT accept the trace"
    according to the differential oracle.
    """

    def __init__(self, put_num: int):
        self.put_num = put_num

    def check_condition(self, exec_stat: ExecutionStatus) -> bool:
        """
        Scans ALL diff entries for the first `Status` record rather than assuming index 0.

        Audit 2 latent note (2026-09-21): an earlier version read `errors[0]["Status"]`.
        Measured 96,281/96,281 with `Status` at index 0, so it was correct on this corpus --
        but it is an assumption, not a guarantee. If a future `filter_diff` ever emits a
        `Claims`/`Knowledges` entry ahead of `Status`, the guard would silently return False,
        i.e. fail-CLOSED, silently re-opening the exact one-side-success leak it exists to
        close. Scanning costs nothing.
        """
        for entry in exec_stat.errors or []:
            status = entry.get("Status")
            if status is None:
                continue
            key = "first_status" if self.put_num == 1 else "second_status"
            return str(status.get(key)) == "Success"
        return False


class TranscriptPhaseAtLeastC(BucketCondition):
    """
    True iff `put_num`'s OWN decrypted transcript (the `extra_knowledges` AlignedTranscript)
    contains at least one message whose SSH message number is >= `min_msg_number`.

    Phases, RFC 4250 section 4.1.2, in chronological order:
        transport generic  1-19   (includes SERVICE_REQUEST 5 / SERVICE_ACCEPT 6)
        KEX                20-49
        userauth           50-79
        connection         80-127

    Added for Audit 1 round 2 (2026-09-20, audit_1_round2_verdict.md section 0). The question
    "was this PUT truncated BEFORE or AFTER the point at which it would have decided to emit
    SERVICE_ACCEPT?" CANNOT be expressed with `executed_steps`: SERVICE_ACCEPT is recovered by
    post-hoc decryption of the whole server-to-client flight and carries no step attribution at
    all (measured: 0/10,968 traces have it as a step-level knowledge; 10,968/10,968 have it only
    in `extra_knowledges`). There is therefore no step index to bound against.

    The measurable equivalent is one level down: did the PUT's own transcript reach a phase
    strictly AFTER the SERVICE_ACCEPT window? With `min_msg_number=50` (userauth) this asserts
    nothing about either library's internals -- it reads only what that PUT's own decrypted
    transcript contains. Because the fold is keyed by `msg_number` over the whole s2c flight, a
    msg 6 the PUT had emitted would appear in the same transcript; its absence alongside a msg 52
    is therefore conclusive, and a later mapper abort cannot retract a message already absent
    from a window the transcript covers.

    Reads `status["execution"]["extra_knowledges"]` via `exec_stat.put1()/put2()` -- the same
    LIVE per-PUT re-execution family as `RekeyWindowViolationC` / `KnowledgeContainsC`, not the
    cached differential (see get_status()/get_diff()).
    """

    _ORDER_ENTRY_RE = re.compile(
        r"AlignmentKey\s*\{\s*channel:\s*\d+,\s*msg_number:\s*(\d+),\s*ordinal:\s*(\d+)\s*\}"
    )

    def __init__(self, put_num: int, min_msg_number: int):
        self.put_num = put_num
        self.min_msg_number = min_msg_number

    def _msg_numbers(self, status: dict) -> list[int]:
        """
        ACCUMULATE across every `extra_knowledges` entry carrying an "order:" list.

        Audit 1 round 3 note 1 (2026-09-20): an earlier version returned at the FIRST such
        entry. Every trace in this corpus has exactly one (10,968/10,968), so it was moot
        here -- but a trace with two AlignedTranscripts (a completed rekey is the obvious
        way) would have been silently half-read. Accumulating costs nothing and removes the
        hazard.
        """
        out: list[int] = []
        for entry in status.get("execution", {}).get("extra_knowledges", []):
            value = entry[1] if len(entry) > 1 else ""
            idx = value.find("order:")
            if idx == -1:
                continue
            found = self._ORDER_ENTRY_RE.findall(value[idx:])
            if not found:
                # Audit 1 round 3 note 2: an "order:" list that parses to nothing means the
                # Rust Debug rendering has drifted from _ORDER_ENTRY_RE. Failing silently
                # here would send traces into whichever bucket NOTs this condition.
                TRANSCRIPT_PARSE_ANOMALIES.append(value[idx : idx + 120])
                continue
            out.extend(int(m) for m, _o in found)
        return out

    def check_condition(self, exec_stat: ExecutionStatus) -> bool:
        status = exec_stat.put1() if self.put_num == 1 else exec_stat.put2()
        if status is None:
            return False
        return any(m >= self.min_msg_number for m in self._msg_numbers(status))


class KnowledgeContainsC(BucketCondition):
    """
    Check if a specific knowledges contains a specific value
    """

    put_num: int
    in_knowledge: str
    check_first_input: bool
    last_input_executed: bool
    check_extra: bool

    def __init__(
        self,
        put_num: int,
        in_knowledge: str,
        check_first_input: bool = False,
        last_input_executed: bool = False,
        check_extra: bool = True,
    ):
        self.put_num = put_num
        self.in_knowledge = in_knowledge
        self.check_first_input = check_first_input
        self.last_input_executed = last_input_executed
        self.check_extra = check_extra

    def check_condition(self, exec_stat: ExecutionStatus) -> bool:
        status = exec_stat.put1() if self.put_num == 1 else exec_stat.put2()
        if status is None:
            return False
        executed_until = status.get("execution").get("executed_until")
        is_first_input = True
        for i, s in enumerate(status.get("execution").get("steps")):
            knowledges = s.get("knowledges")
            if self.check_first_input and not is_first_input:
                return False
            if self.last_input_executed and i != executed_until:
                continue
            for k in knowledges:
                if self.in_knowledge in k:
                    return True
            is_first_input = False
        if self.check_extra:
            for k in status.get("execution").get("extra_knowledges"):
                if self.in_knowledge in k[1]:
                    return True

        return False


class ClaimContainsC(BucketCondition):
    """
    Check if a specific claim contains a specific value
    """

    put_num: int
    in_claim: str
    check_first_input: bool
    last_input_executed: bool

    def __init__(
        self,
        put_num: int,
        in_claim: str,
        check_first_input: bool = False,
        last_input_executed: bool = False,
    ):
        self.put_num = put_num
        self.in_claim = in_claim
        self.check_first_input = check_first_input
        self.last_input_executed = last_input_executed

    def check_condition(self, exec_stat: ExecutionStatus) -> bool:
        exp = re.compile(self.in_claim, re.MULTILINE)
        status = exec_stat.put1() if self.put_num == 1 else exec_stat.put2()
        executed_until = status.get("execution").get("executed_until")
        is_first_input = True
        for i, s in enumerate(status.get("execution").get("steps")):
            claims = s.get("claims")
            if self.check_first_input and not is_first_input:
                return False
            if self.last_input_executed and i != executed_until:
                continue
            for c in claims:
                if exp.search(c):
                    return True
            is_first_input = False

        return False


class AllC(BucketCondition):
    """
    True if all the given conditions are true
    """
    conditions: list[BucketCondition]

    def __init__(self, *conditions: BucketCondition):
        self.conditions = list(conditions)

    def check_condition(self, exec_stat: ExecutionStatus) -> bool:
        for c in self.conditions:
            if not c.check_condition(exec_stat):
                return False
        return True


class AnyC(BucketCondition):
    """
    True if any of the given conditions is true
    """
    conditions: list[BucketCondition]

    def __init__(self, *conditions: BucketCondition):
        self.conditions = list(conditions)

    def check_condition(self, exec_stat: ExecutionStatus) -> bool:
        for c in self.conditions:
            if c.check_condition(exec_stat):
                return True
        return False


class NotC(BucketCondition):
    """
    Not operator on a condition
    """
    condition: BucketCondition

    def __init__(self, condition: BucketCondition):
        self.condition = condition

    def check_condition(self, exec_stat: ExecutionStatus) -> bool:
        return not (self.condition.check_condition(exec_stat))


class TrueC(BucketCondition):
    def check_condition(self, exec_stat: ExecutionStatus) -> bool:
        return True


# Match trace files while skipping LibAFL hidden lock/sidecar files
# (e.g. ".<name>.trace"), whose basename starts with a dot.
VALID = re.compile(r"^[^.].*\.trace(-[0-9]+)?$")


def sort_obj(
    source,
    target,
    buckets: dict[str, BucketCondition],
    first_put: str,
    second_put: str,
    file,
) -> str | None:
    # check that the file is a valid trace
    if VALID.search(file) is not None:
        filepath = os.path.join(source, file)
        print(f"Trace : {file}")
        exec_stat = ExecutionStatus(filepath, first_put, second_put)
        if exec_stat.errors is None:
            print(f"diff is None for {file}")
            return "None"
        for bucket, condition in buckets.items():
            if condition.check_condition(exec_stat):
                print(f"{file} checked {bucket} conditions")
                trace_and_metadata = [
                    filepath,
                    f"{filepath}_ossl.json",
                    f"{filepath}_wolf.json",
                    f"{filepath}_diff.json",
                ]
                # Also co-locate the Phase-0 metadata logs, which use a
                # `metadata_<put>_<trace>.log` PREFIX naming (see
                # phase0_produce_metadata.sh). Built directly from first_put/second_put
                # (already parameters here) rather than glob(): a glob() with a wildcard
                # component forces a full scan of `source` per call, and `source` still
                # holds the full un-triaged corpus while this runs -- for a large corpus
                # that makes the whole triaging pass O(N^2) instead of O(N) (observed:
                # ~6/min instead of ~44,000/min on a 511k-trace corpus). first_put/
                # second_put already give the exact filenames with no wildcard needed, and
                # os.rename's existing try/except OSError below already tolerates a file
                # that doesn't exist, so this is a strict improvement, not a narrowing.
                trace_and_metadata += [
                    os.path.join(source, f"metadata_{first_put}_{file}.log"),
                    os.path.join(source, f"metadata_{second_put}_{file}.log"),
                    # Also move the Phase-0 differential cache (metadata_diff_<trace>.json
                    # and .log, read by get_diff) so buckets stay self-contained and
                    # incremental re-runs find the cache co-located with the trace.
                    os.path.join(source, f"metadata_diff_{file}.json"),
                    os.path.join(source, f"metadata_diff_{file}.log"),
                ]
                for file_path in trace_and_metadata:
                    try:
                        os.rename(
                            file_path,
                            os.path.join(target, bucket, os.path.basename(file_path)),
                        )
                    except OSError as _:
                        pass
                break
        return get_error(exec_stat.errors)


def run_triaging(
    buckets: dict[str, BucketCondition],
    first_put: str,
    second_put: str,
    source_folder: str = "objective",
    target_folder: str = "objective",
    parallelism: int = 4,
):
    if not os.path.isdir(source_folder):
        print(f"objective folder {source_folder} does not exist")

    # F6 precondition (audit_4_verdict.md, 2026-09-20): this function walks
    # os.listdir(source_folder) NON-recursively, so when source_folder == target_folder,
    # traces already filed inside a bucket subdirectory from a PRIOR run are invisible to
    # THIS run -- the on-disk layout silently becomes a superposition of whichever bucket
    # script version produced each trace's current location, with no error raised and every
    # count quietly wrong (this produced 44 misplaced traces before it was caught by a
    # cold-eye audit). Refuse to start in that configuration rather than silently corrupt
    # the census; the caller must flatten source_folder back to one level first (move every
    # bucket subdirectory's contents up, then remove the empty subdirectories).
    if os.path.abspath(source_folder) == os.path.abspath(target_folder):
        nonempty_bucket_dirs = []
        for k in buckets:
            bucket_dir = os.path.join(target_folder, os.path.dirname(k) or k)
            if os.path.isdir(bucket_dir) and os.listdir(bucket_dir):
                nonempty_bucket_dirs.append(bucket_dir)
        if nonempty_bucket_dirs:
            raise RuntimeError(
                "run_triaging refused to start: source_folder == target_folder and "
                f"{len(nonempty_bucket_dirs)} bucket subdirector"
                f"{'y is' if len(nonempty_bucket_dirs) == 1 else 'ies are'} already "
                "non-empty (e.g. "
                f"{nonempty_bucket_dirs[0]!r}). Traces already filed there are invisible "
                "to this run's os.listdir(source_folder) walk and would be silently "
                "excluded from re-classification. Flatten source_folder back to one level "
                "(move every bucket subdirectory's files up, then remove the empty "
                "subdirectories) before re-running."
            )

    # Create all buckets
    for k, _ in buckets.items():
        os.makedirs(os.path.dirname(os.path.join(target_folder, k)), exist_ok=True)

    # read all files in the objective directory
    func_wrapper = partial(
        sort_obj, source_folder, target_folder, buckets, first_put, second_put
    )
    # Using threadpool instead of a process pool to allow Python to pickle lambda functions
    with Pool(parallelism) as p:
        errs = p.map(func_wrapper, os.listdir(source_folder))
        err_count = {}
        for e in errs:
            if e is not None:
                err_count[e] = err_count.get(e, 0) + 1
        err_count = dict(
            sorted(err_count.items(), key=lambda item: item[1], reverse=True)
        )
        for k, v in err_count.items():
            print(k, ": ", v)

    if TRANSCRIPT_PARSE_ANOMALIES:
        print(
            f"\nWARNING: {len(TRANSCRIPT_PARSE_ANOMALIES)} transcript 'order:' list(s) "
            f"parsed to ZERO AlignmentKeys. TranscriptPhaseAtLeastC's regex is coupled to "
            f"the Rust Debug rendering; if that changed, every phase condition silently "
            f"evaluates False and traces migrate into whichever bucket negates it. "
            f"Investigate before trusting this run's phase-gated buckets. First 3:"
        )
        for a in TRANSCRIPT_PARSE_ANOMALIES[:3]:
            print(f"  {a!r}")

    if SKIPPED_TRACES:
        print(
            f"\nWARNING: skipped {len(SKIPPED_TRACES)} trace(s) whose differential "
            f"execution could not be parsed (timeout / sanitizer abort / no JSON on "
            f"stdout). These were NOT classified:"
        )
        for t in SKIPPED_TRACES:
            print(f"  {t}")


if __name__ == "__main__":
    pass
