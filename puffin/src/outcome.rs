//! The outcome of a trace execution, and its signature: what an objective is, in one definition
//! shared by the tests, the CLI (`execute --outcome`) and the bench.
//!
//! A trace runs in a forked child process. The child reports how the trace ended through its exit
//! code (0: the trace ran to its end, 10: security violation, 2: error of the trace or of the PUT)
//! and a small result file (the violation or error message); its stderr is captured so that a crash
//! is described by its AddressSanitizer report and panic message. The parent turns all of it into
//! an [`Outcome`].
//!
//! The [`Signature`] of an objective is its outcome without what differs between variants of one
//! bug: the stack frames, the access (READ/WRITE of N bytes) and the addresses. It is matched
//! against the oracle of a catalogue entry ([`puffin_build::catalogue::Oracle`]).

use std::fmt;
use std::io::{Read, Seek, Write};
use std::time::Duration;

use puffin_build::catalogue::{Oracle, OracleKind};
use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::execution::{run_in_subprocess_raw, ForkError, RawStatus, Runner, TraceRunner};
use crate::protocol::ProtocolBehavior;
use crate::trace::{ConfigTrace, Trace};

/// Exit code of the forked child when the trace ran to its end.
pub const EXIT_OK: i32 = 0;
/// Exit code of the forked child when the trace failed (error of the trace or of the PUT).
pub const EXIT_ERROR: i32 = 2;
/// Exit code of the forked child when the panic of a trace was caught (it then aborts: kept for
/// older runtimes).
pub const EXIT_PANIC: i32 = 3;
/// Exit code of the forked child when the security oracle reported a violation.
pub const EXIT_SECURITY_VIOLATION: i32 = 10;

/// How a trace execution ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "lowercase")]
pub enum Outcome {
    /// The trace ran to its end
    None,
    /// The security oracle reported a claim violation (an objective)
    Claim { violation: String },
    /// The execution crashed (an objective)
    Crash {
        /// Signal that ended the process (e.g. "SIGABRT")
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signal: Option<String>,
        /// Exit code, when the process exited instead (AddressSanitizer without `abort_on_error`)
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exit_code: Option<i32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        asan: Option<AsanReport>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        panic: Option<String>,
    },
    /// The execution did not end in time
    Timeout,
    /// The trace or the PUT failed before any objective (not an objective)
    Error { message: String },
}

/// The essentials of an AddressSanitizer report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsanReport {
    /// Type of the report (e.g. "heap-buffer-overflow", "SEGV", "double-free"): the first word
    /// after "SUMMARY: AddressSanitizer:", or after "ERROR: AddressSanitizer:" when there is
    /// no summary
    #[serde(rename = "type")]
    pub kind: String,
    /// The first frames of the crashing stack, outside the sanitizer runtime and the mem*/str*
    /// interceptors (shown, never used to decide)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub frames: Vec<String>,
}

/// The signature of an objective: its outcome without frames, accesses or addresses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub kind: OracleKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asan: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub violation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub panic: Option<String>,
}

impl Outcome {
    /// Whether the outcome is an objective (a crash or a claim violation).
    pub fn is_objective(&self) -> bool {
        matches!(self, Outcome::Claim { .. } | Outcome::Crash { .. })
    }

    /// The signature of an objective (`None` for other outcomes).
    pub fn signature(&self) -> Option<Signature> {
        match self {
            Outcome::Claim { violation } => Some(Signature {
                kind: OracleKind::Claim,
                signal: None,
                asan: None,
                violation: Some(violation.clone()),
                panic: None,
            }),
            Outcome::Crash {
                signal,
                asan,
                panic,
                ..
            } => Some(Signature {
                kind: OracleKind::Crash,
                signal: signal.clone(),
                asan: asan.as_ref().map(|a| a.kind.clone()),
                violation: None,
                panic: panic.clone(),
            }),
            _ => None,
        }
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Outcome::None => write!(f, "no objective"),
            Outcome::Claim { violation } => write!(f, "claim violation \"{violation}\""),
            Outcome::Crash {
                signal,
                exit_code,
                asan,
                panic,
            } => {
                write!(f, "crash")?;
                if let Some(signal) = signal {
                    write!(f, " ({signal})")?;
                }
                if let Some(code) = exit_code {
                    write!(f, " (exit code {code})")?;
                }
                if let Some(asan) = asan {
                    write!(f, ", ASan {}", asan.kind)?;
                    if !asan.frames.is_empty() {
                        write!(f, " in {}", asan.frames.join(" < "))?;
                    }
                }
                if let Some(panic) = panic {
                    write!(f, ", panic \"{panic}\"")?;
                }
                Ok(())
            }
            Outcome::Timeout => write!(f, "timeout"),
            Outcome::Error { message } => write!(f, "error: {message}"),
        }
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind)?;
        for (name, value) in [
            ("signal", &self.signal),
            ("asan", &self.asan),
            ("violation", &self.violation),
            ("panic", &self.panic),
        ] {
            if let Some(value) = value {
                write!(f, " {name}=\"{value}\"")?;
            }
        }
        Ok(())
    }
}

/// Whether an objective's signature matches an oracle: same kind, and every field the oracle gives
/// is the signature's. The `asan` field of the oracle is only checked when the PUT has
/// AddressSanitizer (`asan_available`): without it, a memory bug shows as a plain crash, or not at
/// all.
pub fn matches(oracle: &Oracle, signature: &Signature, asan_available: bool) -> bool {
    let field = |wanted: &Option<String>, got: &Option<String>| match wanted {
        None => true,
        Some(wanted) => got.as_deref() == Some(wanted.as_str()),
    };
    // an oracle that is an AddressSanitizer report cannot be recognised without ASan
    if oracle.asan.is_some() && !asan_available {
        return false;
    }

    oracle.kind == signature.kind
        && field(&oracle.signal, &signature.signal)
        && field(&oracle.asan, &signature.asan)
        && field(&oracle.violation, &signature.violation)
        // a Rust panic (of the harness, of the trace) is not the library's crash, unless the oracle
        // is that panic
        && match &oracle.panic {
            None => signature.panic.is_none(),
            Some(wanted) => signature.panic.as_deref() == Some(wanted.as_str()),
        }
}

/// One execution of a trace with its configuration.
#[derive(Debug, Clone)]
pub struct Execution<PT: crate::protocol::ProtocolTypes> {
    pub trace: Trace<PT>,
    pub config: ConfigTrace,
}

/// The result of a forked execution: its outcome and what the child wrote on stderr.
#[derive(Debug, Clone)]
pub struct ExecutionReport {
    pub outcome: Outcome,
    pub stderr: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "lowercase")]
enum ChildResult {
    Ok,
    Violation { message: String },
    Error { message: String },
    Panic { message: String },
}

/// Run `executions` in order in one forked child process (the earlier ones prepare the state of the
/// PUTs, e.g. fill a session cache) and return the outcome of the last one. An error in an earlier
/// execution is the outcome.
pub fn execute_outcome<PB: ProtocolBehavior>(
    runner: &Runner<PB>,
    executions: &[Execution<PB::ProtocolTypes>],
    timeout: impl Into<Option<Duration>>,
) -> Result<ExecutionReport, ForkError> {
    let fork_error =
        |e: std::io::Error| ForkError::new(format!("cannot create a temporary file: {e}"));
    let mut result_file = tempfile::tempfile().map_err(fork_error)?;
    let mut stderr_file = tempfile::tempfile().map_err(fork_error)?;

    let status = run_in_subprocess_raw(
        || {
            use std::os::fd::AsRawFd;

            // the child's stderr goes to the capture file (the parent reprints it)
            let _ = std::io::stderr().flush();
            let _ = nix::unistd::dup2(stderr_file.as_raw_fd(), libc::STDERR_FILENO);

            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                for (n, execution) in executions.iter().enumerate() {
                    let last = n + 1 == executions.len();
                    match runner.execute_config(&execution.trace, execution.config, &mut 0) {
                        Ok(_) => (),
                        Err(e @ Error::SecurityClaim(message)) if last => {
                            // the line the bench's replays have always parsed
                            log::info!("{}", e);
                            return ChildResult::Violation {
                                message: message.to_string(),
                            };
                        }
                        Err(e) => {
                            // the line the bench's replays have always parsed
                            log::info!("{}", e);
                            return ChildResult::Error {
                                message: if last {
                                    e.to_string()
                                } else {
                                    format!(
                                        "execution {} of {} failed: {e}",
                                        n + 1,
                                        executions.len()
                                    )
                                },
                            };
                        }
                    }
                }
                ChildResult::Ok
            }));

            let result = result.unwrap_or_else(|payload| ChildResult::Panic {
                message: payload
                    .downcast_ref::<&str>()
                    .map(|s| s.to_string())
                    .or_else(|| payload.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "non-string panic payload".into()),
            });

            let _ = serde_json::to_writer(&mut result_file, &result);
            let _ = result_file.flush();
            let _ = std::io::stderr().flush();

            match result {
                ChildResult::Ok => std::process::exit(EXIT_OK),
                ChildResult::Violation { .. } => std::process::exit(EXIT_SECURITY_VIOLATION),
                ChildResult::Error { .. } => std::process::exit(EXIT_ERROR),
                // a panic is a crash: end the way `panic = "abort"` does
                ChildResult::Panic { .. } => std::process::abort(),
            }
        },
        timeout,
    )?;

    let read = |file: &mut std::fs::File| {
        let mut content = String::new();
        let _ = file.rewind();
        let _ = file.read_to_string(&mut content);
        content
    };
    let child_result: Option<ChildResult> = serde_json::from_str(&read(&mut result_file)).ok();
    let stderr = read(&mut stderr_file);

    Ok(ExecutionReport {
        outcome: outcome_of(status, child_result, &stderr),
        stderr,
    })
}

fn outcome_of(status: RawStatus, child_result: Option<ChildResult>, stderr: &str) -> Outcome {
    let asan = parse_asan_report(stderr);
    let panic = match &child_result {
        Some(ChildResult::Panic { message }) => Some(message.clone()),
        _ => parse_panic(stderr),
    };

    match (status, child_result) {
        (RawStatus::Timeout, _) => Outcome::Timeout,
        (RawStatus::Signaled(signal), _) => Outcome::Crash {
            signal: Some(signal),
            exit_code: None,
            asan,
            panic,
        },
        (RawStatus::Exited(EXIT_OK), Some(ChildResult::Ok)) => Outcome::None,
        (RawStatus::Exited(EXIT_SECURITY_VIOLATION), Some(ChildResult::Violation { message })) => {
            Outcome::Claim { violation: message }
        }
        (RawStatus::Exited(EXIT_ERROR), Some(ChildResult::Error { message })) => {
            Outcome::Error { message }
        }
        // AddressSanitizer without abort_on_error exits with its own code (1 by default)
        (RawStatus::Exited(code), _) if asan.is_some() || panic.is_some() => Outcome::Crash {
            signal: None,
            exit_code: Some(code),
            asan,
            panic,
        },
        (RawStatus::Exited(code), _) => Outcome::Error {
            message: format!("the execution exited with code {code} without reporting its result"),
        },
    }
}

/// Parse the first AddressSanitizer report of `stderr` (see [`AsanReport`]).
pub fn parse_asan_report(stderr: &str) -> Option<AsanReport> {
    const MAX_FRAMES: usize = 8;

    let lines: Vec<&str> = stderr.lines().collect();
    let error_line = lines
        .iter()
        .position(|l| l.contains("ERROR: AddressSanitizer: "))?;

    let summary_kind = lines
        .iter()
        .skip(error_line)
        .find_map(|l| l.split_once("SUMMARY: AddressSanitizer: "))
        .and_then(|(_, rest)| rest.split_whitespace().next())
        .map(String::from);
    let error_kind = || {
        let rest = lines[error_line].split_once("ERROR: AddressSanitizer: ")?.1;
        let mut words = rest.split_whitespace();
        let first = words.next()?;
        // "attempting double-free on 0x...", "attempting free on address which was not malloc()-ed"
        Some(match (first, words.next()) {
            ("attempting", Some("free")) => "bad-free".to_string(),
            ("attempting", Some(next)) => next.to_string(),
            _ => first.trim_end_matches(':').to_string(),
        })
    };
    let kind = summary_kind.or_else(error_kind)?;

    let skip = |f: &str| {
        let runtime = [
            "__asan",
            "__interceptor",
            "__sanitizer",
            "__lsan",
            "__ubsan",
            "___interceptor",
        ];
        let interceptors = [
            "memcpy", "memmove", "memset", "memcmp", "strlen", "strcpy", "strncpy", "strcmp",
            "strncmp", "strcat", "bcmp",
        ];
        runtime.iter().any(|p| f.starts_with(p)) || interceptors.contains(&f)
    };

    let mut frames = vec![];
    let mut seen = false;
    for line in &lines[error_line + 1..] {
        let trimmed = line.trim_start();
        let is_frame = trimmed.starts_with('#')
            && trimmed[1..].starts_with(|c: char| c.is_ascii_digit())
            && trimmed.contains(" 0x");
        if !is_frame {
            if seen && trimmed.is_empty() {
                break;
            }
            continue;
        }
        seen = true;
        if frames.len() == MAX_FRAMES {
            continue;
        }
        // "#1 0x55... in AddPacketInfo file.c:12" or "#1 0x55... (/path/module+0x1234)"
        let frame = if let Some((_, rest)) = trimmed.split_once(" in ") {
            rest.split_whitespace().next().unwrap_or("").to_string()
        } else if let Some((_, rest)) = trimmed.split_once('(') {
            let module = rest.split(['+', ')']).next().unwrap_or("");
            let module = module.rsplit('/').next().unwrap_or(module).to_string();
            if module.starts_with("libclang_rt.") || module.starts_with("libasan") {
                continue;
            }
            module
        } else {
            continue;
        };
        if !frame.is_empty() && !skip(&frame) {
            frames.push(frame);
        }
    }

    Some(AsanReport { kind, frames })
}

/// The message of the first Rust panic in `stderr`: `thread 'x' panicked at <location>:\n<message>`
/// (Rust >= 1.73), or `thread 'x' panicked at '<message>', <location>` (older).
pub fn parse_panic(stderr: &str) -> Option<String> {
    let mut lines = stderr.lines();
    while let Some(line) = lines.next() {
        let Some((_, rest)) = line.split_once("panicked at ") else {
            continue;
        };
        if let Some(quoted) = rest.strip_prefix('\'') {
            if let Some((message, _)) = quoted.rsplit_once("', ") {
                return Some(message.to_string());
            }
        }
        if rest.trim_end().ends_with(':') {
            return lines.next().map(|m| m.trim().to_string());
        }
        return Some(rest.trim().to_string());
    }
    None
}

impl<PB: ProtocolBehavior> Runner<PB> {
    /// Execute `trace` in a forked process and return its outcome.
    pub fn execute_outcome(
        &self,
        trace: Trace<PB::ProtocolTypes>,
        config: ConfigTrace,
        timeout: impl Into<Option<Duration>>,
    ) -> Result<ExecutionReport, ForkError> {
        execute_outcome(self, &[Execution { trace, config }], timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ASAN_HEAP: &str = "\
=================================================================
==614416==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x62900000f1fb at pc 0x7ffff75079a5 bp 0x7fffffff0010 sp 0x7ffffffef7d0
READ of size 16956 at 0x62900000f1fb thread T0
    #0 0x7ffff75079a4 in __asan_memcpy (/nix/store/x-clang-wrapper-14.0.6/resource-root/lib/linux/libclang_rt.asan-x86_64.so+0x1079a4)
    #1 0x555555ddc98b in AddPacketInfo cryptocb.c
    #2 0x55555604394e in DoTls13HandShakeMsgType cryptocb.c
    #3 0x555556051e51 in DoTls13HandShakeMsg cryptocb.c

0x62900000f1fb is located 5 bytes to the left of 16951-byte region [0x62900000f200,0x629000013437)
allocated by thread T0 here:
    #0 0x7ffff750987f in malloc (/nix/store/x/libclang_rt.asan-x86_64.so+0x10987f)
    #1 0x555555cbdf04 in wolfSSL_Malloc cryptocb.c
SUMMARY: AddressSanitizer: heap-buffer-overflow (/nix/store/x/libclang_rt.asan-x86_64.so+0x1079a4) in __asan_memcpy
";

    #[test]
    fn asan_reports_give_their_type_and_first_frames() {
        let report = parse_asan_report(ASAN_HEAP).unwrap();
        assert_eq!(report.kind, "heap-buffer-overflow");
        assert_eq!(
            report.frames,
            vec![
                "AddPacketInfo",
                "DoTls13HandShakeMsgType",
                "DoTls13HandShakeMsg"
            ]
        );
    }

    #[test]
    fn asan_types_without_summary_come_from_the_error_line() {
        let double_free = "==1==ERROR: AddressSanitizer: attempting double-free on 0x602 in thread T0:\n    #0 0x1 in free x.c\n    #1 0x2 in wolfSSL_Free x.c\n";
        assert_eq!(parse_asan_report(double_free).unwrap().kind, "double-free");
        let bad_free = "==1==ERROR: AddressSanitizer: attempting free on address which was not malloc()-ed: 0x6\n";
        assert_eq!(parse_asan_report(bad_free).unwrap().kind, "bad-free");
        let segv = "==1==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x1 bp 0x2 sp 0x3 T0)\n    #0 0x1 in tls1_save_u16 t1_lib.c:1\n\nSUMMARY: AddressSanitizer: SEGV t1_lib.c:1 in tls1_save_u16\n";
        let report = parse_asan_report(segv).unwrap();
        assert_eq!(report.kind, "SEGV");
        assert_eq!(report.frames, vec!["tls1_save_u16"]);
        assert_eq!(parse_asan_report("no report here\n"), None);
    }

    #[test]
    fn unsymbolized_frames_give_their_module() {
        let report = "==1==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7\n    #0 0x1 (/lib/libclang_rt.asan-x86_64.so+0x10)\n    #1 0x2 (/path/to/tlspuffin+0x2153)\n";
        assert_eq!(parse_asan_report(report).unwrap().frames, vec!["tlspuffin"]);
    }

    #[test]
    fn panic_messages_are_found_in_both_formats() {
        assert_eq!(
            parse_panic("thread 'main' panicked at src/x.rs:10:5:\nthe message\nnote: ...")
                .as_deref(),
            Some("the message")
        );
        assert_eq!(
            parse_panic("thread 'main' panicked at 'old style', src/x.rs:10:5").as_deref(),
            Some("old style")
        );
        assert_eq!(parse_panic("nothing"), None);
    }

    fn crash(asan: Option<&str>) -> Signature {
        Outcome::Crash {
            signal: Some("SIGABRT".into()),
            exit_code: None,
            asan: asan.map(|kind| AsanReport {
                kind: kind.into(),
                frames: vec!["RefineSuites".into()],
            }),
            panic: None,
        }
        .signature()
        .unwrap()
    }

    #[test]
    fn signatures_match_the_fields_an_oracle_gives() {
        let buf = Oracle {
            kind: OracleKind::Crash,
            signal: None,
            asan: Some("stack-buffer-overflow".into()),
            violation: None,
            panic: None,
        };
        assert!(matches(&buf, &crash(Some("stack-buffer-overflow")), true));
        assert!(!matches(&buf, &crash(Some("heap-buffer-overflow")), true));
        assert!(!matches(&buf, &crash(None), true));
        // without ASan, an oracle that is an ASan report cannot be recognised: no crash is it
        assert!(!matches(&buf, &crash(None), false));
        // a Rust panic is not the library's crash, unless the oracle is that panic
        let abort = Oracle {
            kind: OracleKind::Crash,
            signal: Some("SIGABRT".into()),
            asan: None,
            violation: None,
            panic: None,
        };
        let panicked = Outcome::Crash {
            signal: Some("SIGABRT".into()),
            exit_code: None,
            asan: None,
            panic: Some("index out of bounds".into()),
        }
        .signature()
        .unwrap();
        assert!(matches(&abort, &crash(None), false));
        assert!(!matches(&abort, &panicked, false));
        assert!(matches(
            &Oracle {
                panic: Some("index out of bounds".into()),
                ..abort.clone()
            },
            &panicked,
            false
        ));

        let sig = Oracle {
            kind: OracleKind::Claim,
            signal: None,
            asan: None,
            violation: Some("Authentication bypass".into()),
            panic: None,
        };
        let claim = |v: &str| {
            Outcome::Claim {
                violation: v.into(),
            }
            .signature()
            .unwrap()
        };
        assert!(matches(&sig, &claim("Authentication bypass"), true));
        assert!(!matches(&sig, &claim("Downgrade"), true));
        assert!(!matches(&sig, &crash(None), true));
    }

    #[test]
    fn non_objectives_have_no_signature() {
        assert_eq!(Outcome::None.signature(), None);
        assert_eq!(Outcome::Timeout.signature(), None);
        assert_eq!(
            Outcome::Error {
                message: "error in PUT".into()
            }
            .signature(),
            None
        );
    }

    #[test]
    fn outcomes_serialize_to_a_stable_json() {
        let outcome = Outcome::Crash {
            signal: Some("SIGABRT".into()),
            exit_code: None,
            asan: Some(AsanReport {
                kind: "heap-buffer-overflow".into(),
                frames: vec!["AddPacketInfo".into()],
            }),
            panic: None,
        };
        assert_eq!(
            serde_json::to_string(&outcome).unwrap(),
            r#"{"outcome":"crash","signal":"SIGABRT","asan":{"type":"heap-buffer-overflow","frames":["AddPacketInfo"]}}"#
        );
        assert_eq!(
            serde_json::to_string(&Outcome::Claim {
                violation: "Authentication bypass".into()
            })
            .unwrap(),
            r#"{"outcome":"claim","violation":"Authentication bypass"}"#
        );
        assert_eq!(
            serde_json::to_string(&Outcome::None).unwrap(),
            r#"{"outcome":"none"}"#
        );
    }

    #[test]
    fn child_statuses_become_outcomes() {
        assert_eq!(
            outcome_of(RawStatus::Exited(0), Some(ChildResult::Ok), ""),
            Outcome::None
        );
        assert_eq!(
            outcome_of(
                RawStatus::Exited(EXIT_SECURITY_VIOLATION),
                Some(ChildResult::Violation {
                    message: "Authentication bypass".into()
                }),
                ""
            ),
            Outcome::Claim {
                violation: "Authentication bypass".into()
            }
        );
        assert!(matches!(
            outcome_of(RawStatus::Signaled("SIGABRT".into()), None, ASAN_HEAP),
            Outcome::Crash {
                signal: Some(_),
                asan: Some(_),
                ..
            }
        ));
        // ASan without abort_on_error
        assert!(matches!(
            outcome_of(RawStatus::Exited(1), None, ASAN_HEAP),
            Outcome::Crash {
                exit_code: Some(1),
                asan: Some(_),
                ..
            }
        ));
        assert!(matches!(
            outcome_of(RawStatus::Exited(1), None, ""),
            Outcome::Error { .. }
        ));
        assert_eq!(outcome_of(RawStatus::Timeout, None, ""), Outcome::Timeout);
    }
}
