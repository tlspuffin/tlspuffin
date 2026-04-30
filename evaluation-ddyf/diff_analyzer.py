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
PUFFIN_PATH = Path("target/release/tlspuffin")


def get_diff(trace: str, first_put: str, second_put: str) -> list[dict]:
    """
    execute `trace` and get differences between `first_put` and `second_put`
    """
    result = subprocess.run(
        [PUFFIN_PATH, "differential-execute", "--json", first_put, second_put, trace],
        timeout=5,  # 5 second timeout
        capture_output=True,
    )

    try:
        return json.loads(result.stdout)
    except Exception as e:
        print(e)
        raise BaseException


def get_status(trace: str, put: str) -> dict:
    """
    Execute `trace` on `put` and get terms, knowledges, decryption, status and claims
    """
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
            trace,
        ],
        timeout=5,  # 5 second timeout
        capture_output=True,
    )

    try:
        return json.loads(result.stdout)
    except Exception as e:
        print(e, ":", result.stdout)
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
            return f"Knowledge::Inner[{diff.get('type_name')}]:{diff.get('diff')}"
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
    All conditions must inherit this class
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


VALID = re.compile(r"^[^\.].+\.trace(-[0-9]+)?$")


def sort_obj(
    source,
    target,
    buckets: dict[str, BucketCondition],
    first_put: str,
    second_put: str,
    file,
) -> str | None:
    # check that the file is a valid trace
    try:
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
    except:
        return None


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


if __name__ == "__main__":
    pass
