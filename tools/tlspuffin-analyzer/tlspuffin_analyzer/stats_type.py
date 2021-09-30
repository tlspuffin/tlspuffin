from dataclasses import dataclass
from typing import Optional

from dict_to_dataclass import DataclassFromDict, field_from_dict


@dataclass
class CoverageStatistics(DataclassFromDict):
    discovered: int = field_from_dict()
    max: int = field_from_dict()


@dataclass
class IntrospectFeatures(DataclassFromDict):
    get_input_from_corpus: float = field_from_dict()
    mutate: float = field_from_dict()
    mutate_post_exec: float = field_from_dict()
    target_execution: float = field_from_dict()
    pre_exec: float = field_from_dict()
    post_exec: float = field_from_dict()
    pre_exec_observers: float = field_from_dict()
    post_exec_observers: float = field_from_dict()
    get_feedback_interesting_all: float = field_from_dict()
    get_objectives_interesting_all: float = field_from_dict()


@dataclass
class IntrospectStatistics(DataclassFromDict):
    scheduler: Optional[float] = field_from_dict()  # Remove optional
    manager: Optional[float] = field_from_dict()
    elapsed_cycles: int = field_from_dict()
    introspect_features: IntrospectFeatures = field_from_dict()


@dataclass
class SystemTime(DataclassFromDict):
    secs_since_epoch: int = field_from_dict()


@dataclass
class ErrorStatistics(DataclassFromDict):
    fn_error: int = field_from_dict()
    term_error: int = field_from_dict()
    ssl_error: int = field_from_dict()
    io_error: int = field_from_dict()
    ag_error: int = field_from_dict()
    str_error: int = field_from_dict()
    ext_error: int = field_from_dict()


@dataclass
class TraceStatistics(DataclassFromDict):
    min_trace_length: Optional[int] = field_from_dict()
    max_trace_length: Optional[int] = field_from_dict()
    mean_trace_length: Optional[int] = field_from_dict()

    min_term_size: Optional[int] = field_from_dict()
    max_term_size: Optional[int] = field_from_dict()
    mean_term_size: Optional[int] = field_from_dict()


@dataclass
class ClientStatistics(DataclassFromDict):
    id: int = field_from_dict()
    time: SystemTime = field_from_dict()
    errors: ErrorStatistics = field_from_dict()
    coverage: CoverageStatistics = field_from_dict()

    corpus_size: int = field_from_dict()
    objective_size: int = field_from_dict()
    total_execs: int = field_from_dict()
    exec_per_sec: int = field_from_dict()

    # May not be available in old stats.json, therefore can be None
    intro: Optional[IntrospectStatistics] = field_from_dict(default_factory=lambda: None)
    trace: Optional[TraceStatistics] = field_from_dict(default_factory=lambda: None)
