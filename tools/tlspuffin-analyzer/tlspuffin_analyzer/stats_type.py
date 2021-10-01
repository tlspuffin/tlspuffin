from dataclasses import dataclass
from typing import Optional


@dataclass
class CoverageStatistics:
    discovered: int
    max: int


@dataclass
class IntrospectFeatures:
    get_input_from_corpus: float
    mutate: float
    mutate_post_exec: float
    target_execution: float
    pre_exec: float
    post_exec: float
    pre_exec_observers: float
    post_exec_observers: float
    get_feedback_interesting_all: float
    get_objectives_interesting_all: float


@dataclass
class IntrospectStatistics:
    scheduler: Optional[float]  # Remove optional
    manager: Optional[float]
    elapsed_cycles: int
    introspect_features: IntrospectFeatures


@dataclass
class SystemTime:
    secs_since_epoch: int


@dataclass
class ErrorStatistics:
    fn_error: int
    term_error: int
    ssl_error: int
    io_error: int
    ag_error: int
    str_error: int
    ext_error: int


@dataclass
class TraceStatistics:
    min_trace_length: Optional[int]
    max_trace_length: Optional[int]
    mean_trace_length: Optional[int]

    min_term_size: Optional[int]
    max_term_size: Optional[int]
    mean_term_size: Optional[int]


@dataclass
class ClientStatistics:
    id: int
    time: SystemTime
    errors: ErrorStatistics
    coverage: CoverageStatistics

    corpus_size: int
    objective_size: int
    total_execs: int
    exec_per_sec: int

    # May not be available in old stats.json, therefore can be None
    intro: Optional[IntrospectStatistics]
    trace: Optional[TraceStatistics]
