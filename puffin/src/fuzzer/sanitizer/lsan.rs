//! Per-execution memory leak detection with LeakSanitizer, in the spirit of libFuzzer's
//! `-detect_leaks=1`.
//!
//! The fuzzer runs every input in the same process, so LeakSanitizer's usual check at process exit
//! cannot tell which input leaked. Instead, [`check_leaks`] records the allocations made while a
//! trace runs (sanitizer malloc/free hooks, cheap) and runs a full LeakSanitizer check
//! (`__lsan_do_recoverable_leak_check`, expensive) only when some of them are still live afterwards.
//! Most traces free everything they allocate and never pay for the full check.
//!
//! Counting mallocs and frees is not enough: a trace also frees memory allocated before it (e.g.
//! the trace itself), which would hide its own leaks. So the hooks keep the live pointers allocated
//! during the execution in a fixed-size table (the hooks run inside malloc and cannot allocate).
//!
//! LeakSanitizer reads `detect_leaks` once at process start: when it is off, the full check does
//! nothing. [`leak_detection_asan_options`] gives the options to start the process with, and
//! [`enable_leak_detection`] refuses to enable the detection without them.
//!
//! The sanitizer functions are looked up at run time, so binaries built without ASan still link;
//! enabling the detection fails there.

use std::ffi::{c_int, c_void, CStr};
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU32, AtomicUsize, Ordering};
use std::sync::OnceLock;

static TRACKING: AtomicBool = AtomicBool::new(false);

/// Open-addressing table of the live pointers allocated while tracking (0: empty slot).
const SLOTS: usize = 1 << 18;
const MAX_PROBES: usize = 64;
const TOMBSTONE: usize = 1;
static TABLE: [AtomicUsize; SLOTS] = [const { AtomicUsize::new(0) }; SLOTS];
/// Indices of the table slots used while tracking, to clear only those afterwards.
static USED: [AtomicU32; SLOTS] = [const { AtomicU32::new(0) }; SLOTS];
static USED_LEN: AtomicUsize = AtomicUsize::new(0);
/// Allocations made while tracking and not freed yet.
static LIVE: AtomicIsize = AtomicIsize::new(0);
/// The table was full: the live allocations are unknown.
static OVERFLOW: AtomicBool = AtomicBool::new(false);

/// Executions checked, and those that needed a full LeakSanitizer check (logged periodically).
static EXECUTIONS: AtomicUsize = AtomicUsize::new(0);
static FULL_CHECKS: AtomicUsize = AtomicUsize::new(0);
const LOG_STATS_EVERY: usize = 1 << 14;

/// `__lsan_do_recoverable_leak_check`, once leak detection is enabled.
static LEAK_CHECK: OnceLock<unsafe extern "C" fn() -> c_int> = OnceLock::new();

type MallocHook = unsafe extern "C" fn(*const c_void, usize);
type FreeHook = unsafe extern "C" fn(*const c_void);
type InstallHooks = unsafe extern "C" fn(MallocHook, FreeHook) -> c_int;

fn slot_of(ptr: usize, probe: usize) -> usize {
    ((ptr >> 4).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 40).wrapping_add(probe) % SLOTS
}

fn insert(ptr: usize) {
    for probe in 0..MAX_PROBES {
        let idx = slot_of(ptr, probe);
        let current = TABLE[idx].load(Ordering::Relaxed);
        if (current == 0 || current == TOMBSTONE)
            && TABLE[idx]
                .compare_exchange(current, ptr, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            if current == 0 {
                // First use of this slot while tracking: remember to clear it
                let n = USED_LEN.fetch_add(1, Ordering::Relaxed);
                if n < SLOTS {
                    USED[n].store(idx as u32, Ordering::Relaxed);
                } else {
                    OVERFLOW.store(true, Ordering::Relaxed);
                }
            }
            LIVE.fetch_add(1, Ordering::Relaxed);
            return;
        }
    }
    OVERFLOW.store(true, Ordering::Relaxed);
}

fn remove(ptr: usize) {
    for probe in 0..MAX_PROBES {
        let idx = slot_of(ptr, probe);
        let current = TABLE[idx].load(Ordering::Relaxed);
        if current == 0 {
            return; // Not allocated while tracking
        }
        if current == ptr
            && TABLE[idx]
                .compare_exchange(ptr, TOMBSTONE, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            LIVE.fetch_sub(1, Ordering::Relaxed);
            return;
        }
    }
}

/// Clears the table and returns whether allocations made while tracking may still be live.
fn reset() -> bool {
    let used = USED_LEN.swap(0, Ordering::Relaxed).min(SLOTS);
    for n in 0..used {
        TABLE[USED[n].load(Ordering::Relaxed) as usize].store(0, Ordering::Relaxed);
    }
    let live = LIVE.swap(0, Ordering::Relaxed);
    let overflow = OVERFLOW.swap(false, Ordering::Relaxed);
    live > 0 || overflow
}

// Called by the sanitizer runtime from inside malloc/free: must not allocate.
unsafe extern "C" fn malloc_hook(ptr: *const c_void, _size: usize) {
    if TRACKING.load(Ordering::Relaxed) && !ptr.is_null() {
        insert(ptr as usize);
    }
}

unsafe extern "C" fn free_hook(ptr: *const c_void) {
    if TRACKING.load(Ordering::Relaxed) && !ptr.is_null() {
        remove(ptr as usize);
    }
}

fn lookup(name: &CStr) -> Option<*mut c_void> {
    let sym = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
    (!sym.is_null()).then_some(sym)
}

/// ASan options to start the process with for [`check_leaks`] to work: LeakSanitizer on, but
/// no check at process exit (the leaks are checked per execution, and fuzzer processes exit with
/// allocations of their own still around).
pub const LEAK_DETECTION_ASAN_OPTIONS: [&str; 2] = ["detect_leaks=1", "leak_check_at_exit=0"];

/// Returns `asan_options` with the options of [`LEAK_DETECTION_ASAN_OPTIONS`] set.
pub fn leak_detection_asan_options(asan_options: &str) -> String {
    asan_options
        .split(':')
        .filter(|opt| {
            !opt.is_empty()
                && !opt.starts_with("detect_leaks=")
                && !opt.starts_with("leak_check_at_exit=")
        })
        .chain(LEAK_DETECTION_ASAN_OPTIONS)
        .collect::<Vec<_>>()
        .join(":")
}

/// Whether `asan_options` turns LeakSanitizer on (the last `detect_leaks` setting wins).
pub fn asan_options_detect_leaks(asan_options: &str) -> bool {
    asan_options
        .split(':')
        .filter_map(|opt| opt.strip_prefix("detect_leaks="))
        .last()
        .is_some_and(|value| matches!(value, "1" | "true"))
}

/// Enables [`check_leaks`] in this process.
///
/// `startup_asan_options` must be the `ASAN_OPTIONS` the process was started with: LeakSanitizer
/// must have been on from the start.
pub fn enable_leak_detection(startup_asan_options: &str) -> Result<(), String> {
    if LEAK_CHECK.get().is_some() {
        return Ok(());
    }

    if !asan_options_detect_leaks(startup_asan_options) {
        return Err(format!(
            "leak detection needs the process to start with ASAN_OPTIONS containing detect_leaks=1 \
             (started with ASAN_OPTIONS={startup_asan_options:?})"
        ));
    }

    let (Some(install_hooks), Some(leak_check)) = (
        lookup(c"__sanitizer_install_malloc_and_free_hooks"),
        lookup(c"__lsan_do_recoverable_leak_check"),
    ) else {
        return Err("leak detection needs a binary built with ASan".to_owned());
    };

    let (install_hooks, leak_check) = unsafe {
        (
            std::mem::transmute::<*mut c_void, InstallHooks>(install_hooks),
            std::mem::transmute::<*mut c_void, unsafe extern "C" fn() -> c_int>(leak_check),
        )
    };

    if unsafe { install_hooks(malloc_hook, free_hook) } == 0 {
        return Err("failed to install the sanitizer malloc/free hooks".to_owned());
    }

    let _ = LEAK_CHECK.set(leak_check);
    Ok(())
}

/// Whether [`enable_leak_detection`] succeeded in this process.
pub fn leak_detection_enabled() -> bool {
    LEAK_CHECK.get().is_some()
}

/// Runs `f` and returns its result, and whether LeakSanitizer found leaked memory after it.
///
/// Everything `f` allocates for the execution must be freed when it returns (e.g. drop the trace
/// context inside `f`). Always reports no leak if leak detection is not enabled.
///
/// A leak is only looked for when allocations made by `f` are still live, and LeakSanitizer then
/// reports every unreachable allocation of the process, which is attributed to `f`. Callers abort
/// the process on a leak, so earlier leaks cannot be reported again.
pub fn check_leaks<R>(f: impl FnOnce() -> R) -> (R, bool) {
    let Some(leak_check) = LEAK_CHECK.get() else {
        return (f(), false);
    };

    reset();
    TRACKING.store(true, Ordering::SeqCst);
    let result = f();
    TRACKING.store(false, Ordering::SeqCst);

    let executions = EXECUTIONS.fetch_add(1, Ordering::Relaxed) + 1;
    if executions % LOG_STATS_EVERY == 0 {
        log::info!(
            "Leak detection: {} of {executions} executions needed a full LeakSanitizer check",
            FULL_CHECKS.load(Ordering::Relaxed)
        );
    }

    if !reset() {
        return (result, false);
    }
    FULL_CHECKS.fetch_add(1, Ordering::Relaxed);

    log::trace!("allocations still live after the execution: running LeakSanitizer");
    // Prints the leak report to stderr when leaks are found
    let leaked = unsafe { leak_check() } != 0;
    (result, leaked)
}

/// Aborts the process after a leak found by [`check_leaks`], so that the fuzzer saves the input as
/// an objective (like an ASan error with `abort_on_error=1`).
pub fn abort_on_leak() -> ! {
    log::error!("LeakSanitizer found leaked memory (see the report on stderr): aborting");
    log::logger().flush();
    std::process::abort();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leak_detection_asan_options() {
        assert_eq!(
            leak_detection_asan_options("verify_asan_link_order=1:detect_leaks=0:abort_on_error=1"),
            "verify_asan_link_order=1:abort_on_error=1:detect_leaks=1:leak_check_at_exit=0"
        );
        assert_eq!(
            leak_detection_asan_options(""),
            "detect_leaks=1:leak_check_at_exit=0"
        );
    }

    #[test]
    fn test_asan_options_detect_leaks() {
        assert!(asan_options_detect_leaks("a=1:detect_leaks=1"));
        assert!(!asan_options_detect_leaks("detect_leaks=1:detect_leaks=0"));
        assert!(!asan_options_detect_leaks("abort_on_error=1"));
        assert!(!asan_options_detect_leaks(""));
    }
}
