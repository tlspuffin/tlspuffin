//! sshpuffin/src/ssh/differential.rs
//!
//! DDYF-specific (differential) support split out of `protocol.rs` (WS2): the shadow
//! master-switches, the benign/known-bug divergence predicates, and the RFC 4253 §7.1
//! AES-GCM counter-renumbering pass. The DDYF oracle trait-method impls stay in
//! `protocol.rs` and call the `pub(crate)` fns here.


use puffin::agent::AgentName;
use puffin::algebra::atoms::Function;
use puffin::algebra::{DYTerm, Term};
use puffin::protocol::{
    OpaqueProtocolMessageFlight, ProtocolMessageFlight, ProtocolTypes,
};
use puffin::trace::{Action, Step, Trace};


use crate::protocol::SshProtocolTypes;

/// Master switch for shadowing documented-BENIGN divergence classes — divergences
/// investigated to a benign (non-bug) conclusion, so suppressing them removes
/// NOISE, not findings (see `differential_fuzzing_filter_diff`). Currently:
///   * `is_banner_strictness_diff`         — Finding A, pre-auth banner strictness;
///   * `is_userauth_failure_only_diff`     — Finding 3, USERAUTH_FAILURE-only delta;
///   * `is_banner_induced_transcript_presence` — the banner reject's induced transcript-presence
///     diff (context-aware co-drop, banner-gated).
/// Set `SSHPUFFIN_SHADOW_KNOWN_BENIGN=0` in the environment (no rebuild) to re-surface
/// every benign class as an objective. This does NOT control the known-bugs shadow below —
/// the two categories are independent. Defaults to `true` (shadow on).
pub(crate) fn shadow_known_benign() -> bool {
    static V: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *V.get_or_init(|| shadow_env("SSHPUFFIN_SHADOW_KNOWN_BENIGN"))
}

/// Master switch for shadowing documented, root-caused REAL BUGS that we have
/// already reported/recorded and do not want long campaigns to KEEP re-reporting.
/// Distinct from `SHADOW_KNOWN_BENIGN` on purpose: these ARE genuine
/// implementation defects (not benign noise), so they are gated separately and can
/// be re-surfaced INDEPENDENTLY for a bug-focused re-audit (flip THIS to `false`
/// while leaving the benign shadows on). Each such shadow must reference the
/// finding's writeup and be surgically guarded so it can never mask a NEW or
/// more-dangerous divergence. Currently:
///   * `is_fwd_reqsuccess_port_echo_diff` — wolfSSH tcpip-forward REQUEST_SUCCESS bound-port echo
///     for a non-zero requested port, RFC 4254 §7.1
///     (findings_phase3/WOLFSSH_TCPIP_FORWARD_PORT_ECHO.md). Still live on wolfSSH master; LOW
///     severity. The diverging `forwarding` seed + PoC remain the permanent record; this switch
///     only silences campaign re-reporting.
/// `true` by default (documented, LOW-severity, already recorded). Set
/// `SSHPUFFIN_SHADOW_KNOWN_BUGS=0` in the environment (no rebuild) to re-surface the filed
/// known-bug classes as objectives — a bug-focused re-audit, or the port-echo shadow-off demo.
pub(crate) fn shadow_known_bugs() -> bool {
    static V: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *V.get_or_init(|| shadow_env("SSHPUFFIN_SHADOW_KNOWN_BUGS"))
}

/// Read a shadow master-switch from the environment. Absent — or any value other than
/// `0`/`false`/`off`/`no` (case-insensitive) — means the shadow is ON (the safe default), so a
/// plain campaign run is unaffected and only an explicit `=0` re-surfaces the class.
fn shadow_env(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => !matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false" | "off" | "no"),
        Err(_) => true,
    }
}

/// Finding A — pre-auth banner/version strictness (documented benign in
/// BUG_HUNTING.md / REPORT_triaging.md). libssh caps the client identification
/// string at 127 bytes and requires a usable version, rejecting banners that
/// wolfSSH (255-byte `WOLFSSH_PROTOID_LIMIT`, bounded banner-lines) accepts.
/// Investigated benign: wolfSSH's parsing is O(1)-bounded and RFC 4253 §4.2
/// compliant (no memory-safety issue), and both stacks derive an identical
/// V_C/V_S for any mutually-accepted banner (no exchange-hash divergence).
///
/// Matched SURGICALLY so it cannot mask an unrelated bug: a `Status` diff where
/// ONE side carries libssh's specific banner/version rejection string AND the
/// OTHER side accepted (`Success`) or progressed strictly further. It never
/// drops a both-reject pair, never drops any other error kind, and is symmetric
/// in which PUT is libssh (so it still holds if the PUT order is flipped). A
/// real downstream divergence on the accepting side still surfaces through its
/// own Knowledges/Claims diff or an ASAN crash — those `TraceDifference` entries
/// are filtered independently of this Status entry.
pub(crate) fn is_banner_strictness_diff(diff: &puffin::differential::TraceDifference) -> bool {
    use puffin::differential::TraceDifference;
    let TraceDifference::Status(s) = diff else {
        return false;
    };
    let is_banner_reject = |st: &str| {
        st.contains("too large banner") || st.contains("No version of SSH protocol usable")
    };
    // The non-rejecting side must have clearly accepted or gone strictly further.
    let progressed = |other: &str, other_steps: usize, rejecter_steps: usize| {
        other == "Success" || other_steps > rejecter_steps
    };
    (is_banner_reject(&s.first_status)
        && progressed(
            &s.second_status,
            s.second_executed_steps,
            s.first_executed_steps,
        ))
        || (is_banner_reject(&s.second_status)
            && progressed(
                &s.first_status,
                s.first_executed_steps,
                s.second_executed_steps,
            ))
}

/// The KNOWLEDGE-layer form of a banner-strictness divergence: one side rejected
/// the banner so it never decrypted a transcript, yielding a `AlignedTranscript`
/// vs `()` presence difference. Matched ONLY to co-drop it alongside a shadowed
/// banner *status* reject (see `differential_fuzzing_filter_diffs`) — never on its
/// own, because the same shape is a genuine "one stack completes, the other does
/// not" divergence when no banner reject explains it.
pub(crate) fn is_banner_induced_transcript_presence(diff: &puffin::differential::TraceDifference) -> bool {
    use puffin::differential::{KnowledgeDiff, TraceDifference};
    let TraceDifference::Knowledges(KnowledgeDiff::DifferentTypes {
        first_type,
        second_type,
        ..
    }) = diff
    else {
        return false;
    };
    let is_transcript = |t: &str| t.contains("AlignedTranscript");
    (first_type == "()" && is_transcript(second_type))
        || (second_type == "()" && is_transcript(first_type))
}

/// Finding 3 — one stack's decrypted transcript carries a USERAUTH_FAILURE
/// (SSH msg 51: a method-list advertisement / auth rejection) that the other
/// does not. Investigated benign by a 272-objective auth-outcome scan
/// (2026-09-02): 0 success-asymmetry — no objective reaches USERAUTH_SUCCESS on
/// either stack, so this is never an accept-vs-reject (auth-policy) divergence;
/// auth fails on both and the stacks merely differ in which rejection packet
/// they emit.
///
/// GUARDED so it can NEVER mask a real user-auth divergence: it matches an
/// `AlignedTranscript` `InnerDifference` whose delta mentions `UserAuthFailure`
/// AND does NOT mention `UserAuthSuccess`. If a future trace ever produces a
/// delta touching USERAUTH_SUCCESS (one side authenticates, the other does not),
/// this returns false and the objective is KEPT. The delta is the only content
/// exposed by the `comparable` Map diff; a USERAUTH_SUCCESS present on ONE side
/// necessarily appears in the delta as an Added/Removed entry, so this guard is
/// complete.
pub(crate) fn is_userauth_failure_only_diff(diff: &puffin::differential::TraceDifference) -> bool {
    use puffin::differential::{KnowledgeDiff, TraceDifference};
    let TraceDifference::Knowledges(KnowledgeDiff::InnerDifference {
        type_name, diff, ..
    }) = diff
    else {
        return false;
    };
    type_name.contains("AlignedTranscript")
        && diff.contains("UserAuthFailure")
        && !diff.contains("UserAuthSuccess")
}

/// wolfSSH tcpip-forward REQUEST_SUCCESS port-echo (findings_phase3/
/// WOLFSSH_TCPIP_FORWARD_PORT_ECHO.md). Both stacks ACCEPT an authorized
/// tcpip-forward (both emit SSH_MSG_REQUEST_SUCCESS), but wolfSSH appends the
/// bound port even for a non-zero requested port, while libssh sends a bare reply;
/// so the `comparable` transcript diff is a single `Changed` on the REQUEST_SUCCESS
/// (msg 81) key whose ONLY delta is a purely-additive `response_data` byte run (the
/// echoed port). RFC 4254 §7.1 returns the port only for a port-0 dynamic request
/// (OpenSSH + libssh agree); a documented, root-caused, LOW-severity conformance
/// deviation. Shadowed so long campaigns stop re-reporting it; the diverging
/// `forwarding` seed + PoC remain the record.
///
/// VERY STRICT — matches ONLY that exact shape, so it can never mask a real
/// forwarding divergence:
///   * `BothRequestSuccess`  => both ACCEPTED (an accept-vs-reject forward, i.e. RequestSuccess vs
///     RequestFailure, is NOT "BothRequestSuccess" -> KEPT);
///   * the ONLY changed field is `response_data` (`RequestSuccessMessageChange`);
///   * EXACTLY ONE changed alignment key, and it is msg 81 (no other message present/absent/changed
///     -> a diff touching anything else is KEPT);
///   * the response_data delta is PURELY ADDITIVE and short (a uint32-ish port echo): only `Added(`
///     entries, no `Removed(`/`Changed(` -> a both-non-empty or otherwise-shaped response_data
///     difference is KEPT.
/// Not keyed to a specific port value, so a mutated forward port is still shadowed
/// but nothing broader is.
pub(crate) fn is_fwd_reqsuccess_port_echo_diff(diff: &puffin::differential::TraceDifference) -> bool {
    use puffin::differential::{KnowledgeDiff, TraceDifference};
    let TraceDifference::Knowledges(KnowledgeDiff::InnerDifference {
        type_name, diff, ..
    }) = diff
    else {
        return false;
    };
    // count of `Added(` entries inside the response_data delta (the echoed bytes)
    let added = diff.matches("Added(").count();
    type_name.contains("AlignedTranscript")
        // both accepted the forward (guards against masking accept-vs-reject)
        && diff.contains("BothRequestSuccess")
        // the only delta is the response_data field of the REQUEST_SUCCESS
        && diff.contains("RequestSuccessMessageChange")
        && diff.contains("response_data")
        // EXACTLY ONE changed alignment key, and it is REQUEST_SUCCESS (msg 81);
        // any additional present/absent/changed message keeps the objective
        && diff.matches("Changed(AlignmentKey").count() == 1
        && diff.contains("msg_number: 81")
        && !diff.contains("Added(AlignmentKey")
        && !diff.contains("Removed(AlignmentKey")
        // purely-additive, short port echo: some Added bytes, no Removed, no
        // nested Changed inside response_data (both-non-empty differences KEPT)
        && added >= 1
        && added <= 8
        && !diff.contains("Removed(")
}

// ── AES-GCM packet-counter renumbering (RFC 4253 §7.1 auto-discovery) ────────
//
// Function symbols the renumbering pass keys on. Matched by NAME (symbol), never
// by evaluated value, so `fn_u32_auto`'s sentinel value is never actually read.
const AUTO_COUNTER_FN: &str = "fn_u32_auto";
const AESGCM_ENCRYPT_FN: &str = "fn_encrypt_packet_aesgcm";
const NEWKEYS_FN: &str = "fn_new_keys";
const PACKET_FN: &str = "fn_packet";

/// A `Function::name()` is the full Rust path (`std::any::type_name`), e.g.
/// `sshpuffin::ssh::fn_impl::fn_constants::fn_u32_auto`. Compare the LAST `::`
/// segment against the short symbol name.
fn fn_name_is(full: &str, symbol: &str) -> bool {
    full.rsplit("::").next().unwrap_or(full) == symbol
}

/// Whether a `Term`'s root application is the named function symbol.
fn term_root_is(term: &Term<SshProtocolTypes>, symbol: &str) -> bool {
    matches!(&term.term, DYTerm::Application(f, _) if fn_name_is(f.name(), symbol))
}

/// Whether any sub-term is the given symbol (read-only DAG walk; no allocation).
fn term_contains_symbol(term: &Term<SshProtocolTypes>, symbol: &str) -> bool {
    match &term.term {
        DYTerm::Variable(_) => false,
        DYTerm::Application(f, args) => {
            fn_name_is(f.name(), symbol) || args.iter().any(|a| term_contains_symbol(a, symbol))
        }
    }
}

/// Fast-path predicate for [`SshProtocolTypes::preprocess_trace`]: does this step's
/// input recipe carry the auto-counter sentinel anywhere?
pub(crate) fn step_has_auto_counter(step: &Step<SshProtocolTypes>) -> bool {
    match &step.action {
        Action::Input(input) => term_contains_symbol(&input.recipe, AUTO_COUNTER_FN),
        Action::Output(_) => false,
    }
}

/// Arg-index path (from the recipe root) to the OUTERMOST aes-gcm encrypt node,
/// i.e. the one that seals the wire packet this step emits. Pre-order search:
/// the first match encountered is the closest to the root. `Some(vec![])` means
/// the root itself is the encrypt (the shape every current seed uses).
fn find_outermost_aesgcm_path(term: &Term<SshProtocolTypes>) -> Option<Vec<usize>> {
    if term_root_is(term, AESGCM_ENCRYPT_FN) {
        return Some(vec![]);
    }
    if let DYTerm::Application(_, args) = &term.term {
        for (i, a) in args.iter().enumerate() {
            if let Some(mut rest) = find_outermost_aesgcm_path(a) {
                let mut path = Vec::with_capacity(rest.len() + 1);
                path.push(i);
                path.append(&mut rest);
                return Some(path);
            }
        }
    }
    None
}

/// Follow an arg-index path to a mutable sub-term.
fn term_at_path_mut<'a>(
    term: &'a mut Term<SshProtocolTypes>,
    path: &[usize],
) -> Option<&'a mut Term<SshProtocolTypes>> {
    let mut cur = term;
    for &i in path {
        let DYTerm::Application(_, args) = &mut cur.term else {
            return None;
        };
        cur = args.get_mut(i)?;
    }
    Some(cur)
}

/// A plaintext NEWKEYS step, `fn_packet(fn_new_keys)` — the first key-epoch
/// boundary (before any encryption). Consumes no AES-GCM counter itself.
fn recipe_is_plaintext_newkeys(term: &Term<SshProtocolTypes>) -> bool {
    if !term_root_is(term, PACKET_FN) {
        return false;
    }
    let DYTerm::Application(_, args) = &term.term else {
        return false;
    };
    args.first().is_some_and(|a| term_root_is(a, NEWKEYS_FN))
}

/// Build the `fn_u32_<n>` constant leaf by name lookup in the signature. The
/// rewritten trace is a throwaway executed immediately (never serialised), so this
/// only needs to EVALUATE to `n`; reusing the registered constant guarantees an
/// exact type/shape match. Returns `None` for `n` beyond the registered range
/// (single-epoch traces stay small), leaving the sentinel in place so the packet
/// simply fails to decrypt rather than silently carrying a wrong counter.
fn u32_leaf(n: u32) -> Option<Term<SshProtocolTypes>> {
    const NAMES: [&str; 16] = [
        "fn_u32_0",
        "fn_u32_1",
        "fn_u32_2",
        "fn_u32_3",
        "fn_u32_4",
        "fn_u32_5",
        "fn_u32_6",
        "fn_u32_7",
        "fn_u32_8",
        "fn_u32_9",
        "fn_u32_10",
        "fn_u32_11",
        "fn_u32_12",
        "fn_u32_13",
        "fn_u32_14",
        "fn_u32_15",
    ];
    let want = *NAMES.get(n as usize)?;
    // `functions_by_name` is keyed by the full type-name path, so match on the
    // short last-segment symbol instead.
    let sig = SshProtocolTypes::signature();
    let (shape, dyn_fn) = sig
        .functions
        .iter()
        .find(|(shape, _)| fn_name_is(shape.name, want))?;
    Some(Term {
        term: DYTerm::Application(Function::new(shape.clone(), dyn_fn.clone()), vec![]),
        payloads: None,
    })
}

/// Rewrite every c2s `fn_encrypt_packet_aesgcm` counter argument that is the
/// `fn_u32_auto` sentinel to the packet's true wire position.
///
/// One `InputAction` == one wire packet (`trace.rs`, "force output after each
/// InputAction step"), so the c2s invocation counter is simply the ordered index
/// of that packet since the last NEWKEYS. Packets feeding a server agent are
/// client→server, so the counter is tracked per agent and reset to 0 at each
/// NEWKEYS boundary (RFC 5647 re-initialises the AES-GCM invocation counter when
/// keys rotate). An explicit `fn_u32_N` counter is NOT the sentinel and is left
/// untouched — so adversarial / Terrapin counter manipulation stays a fuzzing
/// target while sentinel-tagged packets auto-renumber.
pub(crate) fn renumber_aesgcm_counters(trace: &mut Trace<SshProtocolTypes>) {
    use std::collections::HashMap;

    let mut counters: HashMap<AgentName, u32> = HashMap::new();
    for step in trace.steps.iter_mut() {
        let agent = step.agent;
        let Action::Input(input) = &mut step.action else {
            continue;
        };
        let counter = counters.entry(agent).or_insert(0);

        if let Some(path) = find_outermost_aesgcm_path(&input.recipe) {
            // encrypted packet: enc = fn_encrypt_packet_aesgcm(msg, key, iv, ctr)
            let enc = term_at_path_mut(&mut input.recipe, &path)
                .expect("path just found immutably must resolve");
            let DYTerm::Application(_, args) = &mut enc.term else {
                continue;
            };
            // an ENCRYPTED NEWKEYS (msg arg 0) closes the epoch AFTER its own
            // counter (it is the last packet under the old keys).
            let is_encrypted_newkeys = args.first().is_some_and(|m| term_root_is(m, NEWKEYS_FN));
            if let Some(ctr) = args.get_mut(3) {
                if term_root_is(ctr, AUTO_COUNTER_FN) {
                    if let Some(leaf) = u32_leaf(*counter) {
                        *ctr = leaf;
                    }
                }
            }
            *counter += 1;
            if is_encrypted_newkeys {
                *counter = 0;
            }
        } else if recipe_is_plaintext_newkeys(&input.recipe) {
            // plaintext NEWKEYS: first epoch boundary; next packet starts at 0.
            *counter = 0;
        }
    }
}

impl std::fmt::Display for SshProtocolTypes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "")
    }
}


#[cfg(test)]
mod filter_diff_tests {
    use puffin::differential::{StatusDiff, TraceDifference};
    use puffin::protocol::ProtocolTypes;

    use crate::protocol::SshProtocolTypes;

    fn status(first: &str, second: &str) -> TraceDifference {
        TraceDifference::Status(StatusDiff {
            first_executed_steps: 0,
            first_status: first.to_string(),
            second_executed_steps: 0,
            second_status: second.to_string(),
            total_step: 9,
        })
    }

    fn keep(diff: &TraceDifference) -> bool {
        SshProtocolTypes::differential_fuzzing_filter_diff(diff)
    }

    // NOTE: an earlier `status_diff_kept_only_on_acceptance_disagreement` test
    // asserted that a both-reject Status diff is DROPPED. The differential is now
    // deliberately fail-closed — every Status diff is kept (both-reject noise is
    // filtered downstream, in decrypt-only mode or the triaging BENIGN buckets,
    // rather than in filter_diff) — so that assertion tested removed behaviour and
    // was deleted. The important property (acceptance divergences are always kept)
    // is covered by `cross_vendor_acceptance_divergences_are_all_kept` below.

    /// Regression guard locking in the conservative keep-behavior against the
    /// ACTUAL diff classes triaged from a libssh-vs-wolfSSH cross-vendor campaign
    /// (2026-06-28). The filter must NEVER be loosened to drop any of these:
    /// each is a genuine cross-vendor acceptance divergence (a stack accepts an
    /// input the other refuses) — the precise differential signal that finds
    /// bugs (e.g. wolfSSH accepting an oversized banner / unusable version that
    /// libssh rejects, or libssh accepting what wolfSSH refuses). A false
    /// negative here means a missed bug, so when in doubt we KEEP.
    #[test]
    fn cross_vendor_acceptance_divergences_are_all_kept() {
        // libssh's own socket-level error on the input vs wolfSSH success. This
        // is libssh's behaviour on that trace (its own error string), NOT a
        // harness/term/IO artifact (those never reach the filter — the engine
        // emits a StatusDiff only when a side is Error::Put, and both-non-Success
        // pairs are dropped above). We deliberately do NOT string-match and drop
        // it: that would be the "too loose" condition that risks hiding a real
        // libssh robustness bug.
        assert!(keep(&status("Socket error: File exists", "Success")));
        // libssh accepts, wolfSSH rejects — libssh leniency.
        assert!(keep(&status("Success", "Unknown error code")));
    }

    /// Finding A — pre-auth banner/version strictness — is documented benign
    /// (BUG_HUNTING.md / REPORT_triaging.md) and deliberately SHADOWED so
    /// campaigns stop re-reporting a closed finding. Pairs where one side rejects
    /// the banner/version and the other accepts/progresses MUST now be dropped.
    /// This is the single, precise exception to fail-closed; everything else
    /// (guarded by `cross_vendor_acceptance_divergences_are_all_kept`) is unchanged.
    #[test]
    fn banner_strictness_is_shadowed() {
        // libssh rejects an oversized banner, wolfSSH accepts — shadowed.
        assert!(!keep(&status(
            "Receiving banner: too large banner",
            "Success"
        )));
        // libssh rejects an unusable version, wolfSSH accepts — shadowed.
        assert!(!keep(&status(
            "No version of SSH protocol usable (banner: xxx)",
            "Success"
        )));
        // But a both-reject pair (neither side progressed) is STILL kept: the
        // shadow only fires on an acceptance/progress divergence, never on
        // two differing rejections.
        assert!(keep(&status(
            "Receiving banner: too large banner",
            "No version of SSH protocol usable (banner: yyy)"
        )));
    }

    fn transcript_inner_diff(diff_str: &str) -> TraceDifference {
        use puffin::differential::KnowledgeDiff;
        use puffin::trace::Source;
        TraceDifference::Knowledges(KnowledgeDiff::InnerDifference {
            index: 0,
            type_name: "sshpuffin::ssh::transcript::AlignedTranscript".to_string(),
            diff: diff_str.to_string(),
            source: Source::Label(Some("Decryption".into())),
        })
    }

    /// Finding 3 — a USERAUTH_FAILURE-only transcript delta (one stack emits an
    /// auth-method-advertisement / rejection the other does not) is documented
    /// benign (2026-09-02 auth scan: 0 success-asymmetry, auth fails on both) and
    /// SHADOWED. The CRITICAL companion assertion is `_kept` below: a delta that
    /// touches USERAUTH_SUCCESS is the genuinely dangerous accept-vs-reject
    /// divergence and MUST survive — the guard is what makes shadowing this class
    /// safe.
    #[test]
    fn userauth_failure_only_diff_is_shadowed() {
        assert!(!keep(&transcript_inner_diff(
            "AlignedTranscriptChange([Added(AlignmentKey { channel: 0, msg_number: 51, ordinal: 0 }, \
             UserAuthFailure(UserAuthFailureMessageDesc { authentications_that_can_continue: \
             NameListDesc { comparable_names: [\"password\", \"publickey\"] }, partial_success: false }))])"
        )));
    }

    /// SAFETY GUARD: an accept-vs-reject auth divergence — a delta where one
    /// stack reaches USERAUTH_SUCCESS — is NEVER shadowed, even if a
    /// USERAUTH_FAILURE also appears in the same delta.
    #[test]
    fn userauth_success_asymmetry_is_always_kept() {
        // one side authenticates (SUCCESS), the other does not
        assert!(keep(&transcript_inner_diff(
            "AlignedTranscriptChange([Added(AlignmentKey { channel: 0, msg_number: 52, ordinal: 0 }, \
             UserAuthSuccess)])"
        )));
        // SUCCESS and FAILURE both in the delta — still kept (guard wins)
        assert!(keep(&transcript_inner_diff(
            "AlignedTranscriptChange([Added(..., UserAuthSuccess), Removed(..., UserAuthFailure(...))])"
        )));
    }

    /// wolfSSH tcpip-forward REQUEST_SUCCESS port-echo — the EXACT diff produced by
    /// `seed_client_attacker_forwarding` (both accept the forward; wolfSSH appends
    /// the bound port to REQUEST_SUCCESS, libssh sends a bare reply). Documented
    /// benign (WOLFSSH_TCPIP_FORWARD_PORT_ECHO.md) and SHADOWED.
    #[test]
    fn fwd_reqsuccess_port_echo_is_shadowed() {
        assert!(!keep(&transcript_inner_diff(
            "[ByKey([Changed(AlignmentKey { channel: 0, msg_number: 81, ordinal: 0 }, \
             BothRequestSuccess(RequestSuccessMessageChange { response_data: \
             [Added(0, 0), Added(1, 0), Added(2, 0), Added(3, 22)] }))])]"
        )));
    }

    /// SAFETY GUARD: an accept-vs-reject FORWARD divergence — one stack accepts the
    /// tcpip-forward (REQUEST_SUCCESS), the other refuses it (REQUEST_FAILURE) — is
    /// the genuinely interesting case and MUST survive. It is NOT a
    /// `BothRequestSuccess` change, so the port-echo shadow never touches it.
    #[test]
    fn fwd_accept_vs_reject_is_always_kept() {
        // one side REQUEST_SUCCESS, the other REQUEST_FAILURE (msg 81 vs 82)
        assert!(keep(&transcript_inner_diff(
            "[ByKey([Added(AlignmentKey { channel: 0, msg_number: 82, ordinal: 0 }, \
             RequestFailure), Removed(AlignmentKey { channel: 0, msg_number: 81, ordinal: 0 })])]"
        )));
        // both accept BUT another message also diverges (channel-open asymmetry):
        // more than one changed key => KEPT (shadow requires exactly msg 81 alone)
        assert!(keep(&transcript_inner_diff(
            "[ByKey([Changed(AlignmentKey { channel: 0, msg_number: 81, ordinal: 0 }, \
             BothRequestSuccess(RequestSuccessMessageChange { response_data: [Added(0, 22)] })), \
             Added(AlignmentKey { channel: 0, msg_number: 91, ordinal: 0 }, ChannelOpenConfirmation)])]"
        )));
    }

    /// Completion-claim presence/absence (one PUT reaches the handshake/auth
    /// completion claim, the other does not) is an acceptance divergence and
    /// MUST be kept — it is how an asymmetric *security-state* acceptance
    /// surfaces even though raw Status is filtered for both-reject.
    #[test]
    fn claim_presence_difference_is_kept() {
        use puffin::differential::ClaimDiff;

        let presence = TraceDifference::Claims(ClaimDiff::DifferentTypes {
            agent: 1,
            index: 0,
            first_type: "alloc::boxed::Box<sshpuffin::claim::SshClaimInner>".into(),
            second_type: "()".into(),
        });
        assert!(keep(&presence));
    }

    /// Filter policy: FULLY fail-closed. Every difference kind is kept — including
    /// the ones the old code dropped as "seed-benign framing"
    /// (ChannelOpenConfirmation / ChannelSuccess). Those are no longer a filter
    /// concern: with the AlignedTranscript's key-based alignment the two stacks'
    /// channel replies align on a canonical channel (so ChannelOpenConfirmation no
    /// longer diverges at all), and any genuine residual is a real objective for a
    /// human to classify downstream — never silently dropped here.
    #[test]
    fn fully_fail_closed_keeps_every_kind() {
        use puffin::differential::KnowledgeDiff;
        use puffin::trace::Source;

        let decryption = || Source::Label(Some("Decryption".into()));

        // Presence differences of EVERY kind are kept (nothing is whitelisted).
        let presence = |kind: &str| {
            TraceDifference::Knowledges(KnowledgeDiff::DifferentTypes {
                index: 0,
                first_type: kind.into(),
                second_type: "()".into(),
                first_source: decryption(),
                second_source: Source::Label(None),
            })
        };
        for kind in [
            "SshMessage::UserAuthSuccess",
            "SshMessage::ServiceAccept",
            "SshMessage::ChannelOpenConfirmation",
            "SshMessage::ChannelSuccess",
            "sshpuffin::ssh::transcript::AlignedTranscript",
        ] {
            assert!(keep(&presence(kind)), "{kind} presence must be kept");
        }

        // Content differences are always kept.
        let content = TraceDifference::Knowledges(KnowledgeDiff::InnerDifference {
            index: 0,
            type_name: "sshpuffin::ssh::transcript::AlignedTranscript".into(),
            diff: "Changed([Removed(UserAuthSuccess)])".into(),
            source: decryption(),
        });
        assert!(keep(&content));
    }

    fn transcript_presence() -> TraceDifference {
        use puffin::differential::KnowledgeDiff;
        use puffin::trace::Source;
        TraceDifference::Knowledges(KnowledgeDiff::DifferentTypes {
            index: 0,
            first_type: "()".into(),
            second_type: "sshpuffin::ssh::transcript::AlignedTranscript".into(),
            first_source: Source::Label(None),
            second_source: Source::Label(Some("Decryption".into())),
        })
    }

    /// Context-aware co-drop: when a banner-strictness status reject is shadowed,
    /// the `AlignedTranscript vs ()` presence diff it induces on the accepting
    /// side is the SAME divergence and is dropped TOGETHER (not re-reported).
    #[test]
    fn banner_reject_co_drops_its_transcript_presence() {
        let set = vec![
            status("Receiving banner: too large banner", "Success"),
            transcript_presence(),
        ];
        let kept = SshProtocolTypes::differential_fuzzing_filter_diffs(set);
        assert!(
            kept.is_empty(),
            "a shadowed banner reject and the transcript-presence it induces must both drop, got {kept:?}"
        );
    }

    /// SAFETY GUARD: the SAME `AlignedTranscript vs ()` presence diff, WITHOUT a
    /// co-occurring banner reject, is a genuine "one stack completed, the other
    /// did not" divergence and MUST survive — the co-drop is banner-gated only.
    #[test]
    fn transcript_presence_without_banner_is_kept() {
        let kept = SshProtocolTypes::differential_fuzzing_filter_diffs(vec![transcript_presence()]);
        assert_eq!(
            kept.len(),
            1,
            "transcript presence must survive when no banner reject explains it"
        );
    }
}

/// Positive control for the differential *knowledge* comparison (store level).
///
/// The fold recipe (`differential_fuzzing_terms_to_eval`) feeds ONE
/// `AlignedTranscript` per PUT into a `KnowledgeStore`, and the two stores are
/// compared by puffin's upstream `KnowledgeStore::compare`. Reporting "zero
/// differences across a campaign" is only meaningful if that comparison actually
/// *fires* when the transcripts differ — otherwise a null result is a false
/// negative from an inert detector (e.g. the transcript type being dropped by the
/// whitelist). These tests lock the detector in through the REAL store path: two
/// different transcripts MUST yield a `Knowledges` difference, two equal ones MUST
/// yield none, and the whitelist MUST admit `AlignedTranscript`.
#[cfg(test)]
mod knowledge_compare_positive_control {
    use puffin::differential::TraceDifference;
    use puffin::trace::{KnowledgeStore, Source};

    use crate::protocol::SshProtocolTypes;
    use crate::ssh::message::SshMessage;
    use crate::ssh::transcript::AlignedTranscript;

    fn transcript_store(msgs: Vec<SshMessage>) -> KnowledgeStore<SshProtocolTypes> {
        let mut store = KnowledgeStore::new();
        // Mirror how trace.rs::compare stores the folded recipe output.
        store.add_raw_knowledge(
            AlignedTranscript::from_messages(msgs),
            None,
            Source::Label(Some("Decryption".into())),
            None,
        );
        store
    }

    /// Gate A (must fire): an auth-state divergence — one stack authenticates
    /// (USERAUTH_SUCCESS), the other rejects (USERAUTH_FAILURE) — surfaces through
    /// the real store comparison.
    #[test]
    fn diverging_auth_outcome_produces_a_knowledges_diff() {
        use crate::ssh::message::{NameList, UserAuthFailureMessage};

        let authed = transcript_store(vec![SshMessage::UserAuthSuccess]);
        let rejected =
            transcript_store(vec![SshMessage::UserAuthFailure(UserAuthFailureMessage {
                authentications_that_can_continue: NameList::empty(),
                partial_success: false,
            })]);

        let diffs = authed
            .compare(&rejected)
            .expect_err("an auth-outcome divergence must be detected");
        assert!(
            diffs
                .iter()
                .any(|d| matches!(d, TraceDifference::Knowledges(_))),
            "expected a Knowledges difference, got {diffs:?}"
        );
    }

    /// Gate A (must fire): a Terrapin-shaped presence divergence — one stack emits
    /// a message the other does not, at the same logical position.
    #[test]
    fn single_sided_message_produces_a_knowledges_diff() {
        let with_success = transcript_store(vec![SshMessage::NewKeys, SshMessage::UserAuthSuccess]);
        let without = transcript_store(vec![SshMessage::NewKeys]);
        assert!(
            with_success.compare(&without).is_err(),
            "a message present on only one side must surface as a difference"
        );
    }

    /// No false positive: identical transcripts compare equal (and this also
    /// proves the whitelist ADMITS AlignedTranscript — a dropped type would make
    /// even differing transcripts compare equal, which the Gate-A tests forbid).
    #[test]
    fn equal_transcripts_produce_no_diff() {
        let a = transcript_store(vec![SshMessage::NewKeys, SshMessage::UserAuthSuccess]);
        let b = transcript_store(vec![SshMessage::NewKeys, SshMessage::UserAuthSuccess]);
        assert!(
            a.compare(&b).is_ok(),
            "identical transcripts must not be flagged (no false positive)"
        );
    }
}

/// Unit tests for the AES-GCM packet-counter renumbering pass
/// ([`SshProtocolTypes::preprocess_trace`] / `renumber_aesgcm_counters`).
///
/// The pass is the mechanism that makes the RFC 4253 §7.1 incomplete-rekey state
/// fuzz-discoverable: a seed authors its c2s AES-GCM counters as the `fn_u32_auto`
/// sentinel, and this pass resolves each to its true wire position so that
/// step-deleting / reordering mutations keep the GCM nonce sequence valid. These
/// tests lock in the four required properties: consecutive numbering, gapless
/// renumbering after a deletion, explicit `fn_u32_N` left untouched, and reset at
/// each NEWKEYS epoch boundary.
#[cfg(test)]
mod preprocess_trace_tests {
    use puffin::agent::AgentName;
    use puffin::algebra::{DYTerm, Term};
    use puffin::protocol::ProtocolTypes;
    use puffin::term;
    use puffin::trace::{Action, InputAction, Trace};

    use crate::protocol::SshProtocolTypes;
    use crate::ssh::fn_impl::*;

    /// A c2s AES-GCM packet whose counter is the auto sentinel. Key/IV are typed
    /// placeholders — the pass rewrites by SYMBOL and never evaluates the term.
    fn auto_pkt(msg: Term<SshProtocolTypes>) -> Term<SshProtocolTypes> {
        term! {
            fn_encrypt_packet_aesgcm(
                (@msg), (fn_placeholder_32bytes), (fn_placeholder_32bytes), (fn_u32_auto))
        }
    }

    fn svc() -> Term<SshProtocolTypes> {
        term! { fn_service_request((fn_ssh_userauth)) }
    }

    fn trace_of(steps: Vec<Term<SshProtocolTypes>>) -> Trace<SshProtocolTypes> {
        let server = AgentName::first();
        Trace {
            prior_traces: vec![],
            descriptors: vec![],
            steps: steps
                .into_iter()
                .map(|t| InputAction::new_step(server, t))
                .collect(),
            ..Default::default()
        }
    }

    /// Root fn-name of a step's outermost aes-gcm counter argument (index 3), or
    /// `None` if the step is not an aes-gcm packet.
    fn last_seg(name: &str) -> &str {
        name.rsplit("::").next().unwrap_or(name)
    }

    fn counter_name(trace: &Trace<SshProtocolTypes>, step: usize) -> Option<String> {
        let Action::Input(input) = &trace.steps[step].action else {
            return None;
        };
        let DYTerm::Application(f, args) = &input.recipe.term else {
            return None;
        };
        if last_seg(f.name()) != "fn_encrypt_packet_aesgcm" {
            return None;
        }
        match &args.get(3)?.term {
            DYTerm::Application(cf, _) => Some(last_seg(cf.name()).to_string()),
            DYTerm::Variable(_) => None,
        }
    }

    #[test]
    fn consecutive_auto_counters_renumber_from_zero() {
        let trace = trace_of(vec![auto_pkt(svc()), auto_pkt(svc()), auto_pkt(svc())]);
        let out = SshProtocolTypes::preprocess_trace(&trace).expect("sentinel present -> Some");
        assert_eq!(counter_name(&out, 0).as_deref(), Some("fn_u32_0"));
        assert_eq!(counter_name(&out, 1).as_deref(), Some("fn_u32_1"));
        assert_eq!(counter_name(&out, 2).as_deref(), Some("fn_u32_2"));
    }

    #[test]
    fn deleting_a_middle_step_renumbers_survivors_gaplessly() {
        // Author 4 packets, then delete the 2nd (as SkipMutator would): survivors
        // must renumber to a gapless 0,1,2 — the crux that keeps nonces valid.
        let mut trace = trace_of(vec![
            auto_pkt(svc()),
            auto_pkt(svc()),
            auto_pkt(svc()),
            auto_pkt(svc()),
        ]);
        trace.steps.remove(1);
        let out = SshProtocolTypes::preprocess_trace(&trace).expect("sentinel present -> Some");
        assert_eq!(counter_name(&out, 0).as_deref(), Some("fn_u32_0"));
        assert_eq!(counter_name(&out, 1).as_deref(), Some("fn_u32_1"));
        assert_eq!(counter_name(&out, 2).as_deref(), Some("fn_u32_2"));
    }

    #[test]
    fn explicit_counter_is_left_untouched() {
        // A packet with an explicit fn_u32_N is NOT the sentinel: preserve it so
        // adversarial / Terrapin counter manipulation stays a fuzzing target. The
        // trace has NO sentinel at all -> the fast path returns None (no rewrite).
        let explicit = term! {
            fn_encrypt_packet_aesgcm(
                (fn_service_request((fn_ssh_userauth))),
                (fn_placeholder_32bytes), (fn_placeholder_32bytes), (fn_u32_5))
        };
        let trace = trace_of(vec![explicit]);
        assert!(
            SshProtocolTypes::preprocess_trace(&trace).is_none(),
            "no sentinel anywhere -> None (hot path stays allocation-free)"
        );
    }

    #[test]
    fn explicit_counter_preserved_when_mixed_with_sentinel() {
        // When a sentinel forces a rewrite, an explicit fn_u32_N in the SAME trace
        // must still be left as-is (only sentinels renumber).
        let explicit = term! {
            fn_encrypt_packet_aesgcm(
                (fn_service_request((fn_ssh_userauth))),
                (fn_placeholder_32bytes), (fn_placeholder_32bytes), (fn_u32_max))
        };
        let trace = trace_of(vec![auto_pkt(svc()), explicit, auto_pkt(svc())]);
        let out = SshProtocolTypes::preprocess_trace(&trace).expect("sentinel present -> Some");
        assert_eq!(counter_name(&out, 0).as_deref(), Some("fn_u32_0"));
        // step 1 is explicit fn_u32_max -> untouched (its wire slot still consumes
        // a counter, so the next sentinel is 2, not 1).
        assert_eq!(counter_name(&out, 1).as_deref(), Some("fn_u32_max"));
        assert_eq!(counter_name(&out, 2).as_deref(), Some("fn_u32_2"));
    }

    #[test]
    fn counter_resets_after_plaintext_newkeys() {
        // svc(0), auth(1), plaintext NEWKEYS (no counter), then next epoch: 0,1.
        let newkeys = term! { fn_packet((fn_new_keys)) };
        let trace = trace_of(vec![
            auto_pkt(svc()),
            auto_pkt(svc()),
            newkeys,
            auto_pkt(svc()),
            auto_pkt(svc()),
        ]);
        let out = SshProtocolTypes::preprocess_trace(&trace).expect("sentinel present -> Some");
        assert_eq!(counter_name(&out, 0).as_deref(), Some("fn_u32_0"));
        assert_eq!(counter_name(&out, 1).as_deref(), Some("fn_u32_1"));
        assert_eq!(counter_name(&out, 2), None); // plaintext newkeys, not a gcm pkt
        assert_eq!(counter_name(&out, 3).as_deref(), Some("fn_u32_0"));
        assert_eq!(counter_name(&out, 4).as_deref(), Some("fn_u32_1"));
    }

    #[test]
    fn counter_resets_after_encrypted_newkeys() {
        // An ENCRYPTED NEWKEYS (a rekey completion) carries its own epoch-final
        // counter, then the epoch resets: svc(0), NEWKEYS(1), next-epoch svc(0).
        let enc_newkeys = auto_pkt(term! { fn_new_keys });
        let trace = trace_of(vec![auto_pkt(svc()), enc_newkeys, auto_pkt(svc())]);
        let out = SshProtocolTypes::preprocess_trace(&trace).expect("sentinel present -> Some");
        assert_eq!(counter_name(&out, 0).as_deref(), Some("fn_u32_0"));
        assert_eq!(counter_name(&out, 1).as_deref(), Some("fn_u32_1"));
        assert_eq!(counter_name(&out, 2).as_deref(), Some("fn_u32_0"));
    }

    #[test]
    fn no_sentinel_trace_is_untouched_fast_path() {
        let trace = trace_of(vec![term! { fn_packet((fn_new_keys)) }]);
        assert!(SshProtocolTypes::preprocess_trace(&trace).is_none());
    }
}
