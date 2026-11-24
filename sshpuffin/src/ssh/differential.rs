//! sshpuffin/src/ssh/differential.rs
//!
//! DDYF-specific (differential) support split out of `protocol.rs` (WS2): the shadow
//! master-switches, the benign/known-bug divergence predicates, and the RFC 4253 §7.1
//! AES-GCM counter-renumbering pass. The DDYF oracle trait-method impls stay in
//! `protocol.rs` and call the `pub(crate)` fns here.

use puffin::agent::AgentName;
use puffin::algebra::atoms::Function;
use puffin::algebra::{DYTerm, Term};
use puffin::term;
use puffin::trace::{Action, Step, Trace};

use crate::protocol::SshProtocolTypes;
use crate::ssh::fn_impl::*;

/// Master switch for shadowing documented-BENIGN divergence classes — divergences
/// investigated to a benign (non-bug) conclusion, so suppressing them removes
/// NOISE, not findings (see `differential_fuzzing_filter_diff`). Currently:
///   * `is_version_strictness_diff`        — libssh's stricter protocol-version check;
///   * `is_userauth_failure_only_diff`     — a USERAUTH_FAILURE-only transcript delta;
///   * `is_banner_induced_transcript_presence` — the banner reject's induced transcript-presence
///     diff (context-aware co-drop, gated like the banner reject it follows).
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
///   * `is_banner_length_diff` — libssh rejects identification strings longer than 129 bytes, RFC
///     4253 §4.2 allows 255 (libssh-mirror#376, live on libssh master);
///   * `is_fwd_reqsuccess_port_echo_diff` — wolfSSH tcpip-forward REQUEST_SUCCESS bound-port echo
///     for a non-zero requested port, RFC 4254 §7.1 (wolfSSL/wolfssh#1246; fixed on wolfSSH master
///     in 24c2139a, still in the pinned v1.5.0). LOW severity. The diverging `forwarding` seed
///     remains the permanent record; this switch only silences campaign re-reporting.
///   * `is_rekey_ext_info_s_diff` — wolfSSH 1.6.0 re-advertises `ext-info-s` in its rekey KEXINIT,
///     RFC 8308 §2.1 (LOW severity). The `rekey` seeds keep it on record on pairs with wolfSSH
///     1.6.0 when this switch is off.
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
///
/// Each switch is read once per process (the `OnceLock`s above), so it is fixed for the
/// whole campaign: set the variable before launching. All broker clients see the same
/// value: the LibAFL launcher forks its clients from the launching process, and a crashed
/// client is respawned (forked again) by its restarting manager, so every client inherits
/// the launcher's environment.
fn shadow_env(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => !matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "off" | "no"
        ),
        Err(_) => true,
    }
}

/// Banner-length strictness (pre-auth, a filed libssh bug). libssh rejects a client
/// identification string longer than 129 bytes ("too large banner") where RFC 4253
/// §4.2 allows 255 and wolfSSH (255-byte `WOLFSSH_PROTOID_LIMIT`) carries on; filed as
/// libssh-mirror#376. With the version class below, the largest divergence class of
/// the early differential campaigns. No memory-safety issue, and both stacks derive
/// the same V_C/V_S for any banner both accept (no exchange-hash divergence).
pub(crate) fn is_banner_length_diff(diff: &puffin::differential::TraceDifference) -> bool {
    is_banner_reject_diff(diff, "too large banner")
}

/// Protocol-version strictness (pre-auth, benign). libssh requires protocol version
/// `2.0` (or `1.99`) in the identification string ("No version of SSH protocol
/// usable"), while wolfSSH only compares the first 7 bytes against `SSH-2.0`, case
/// insensitively, and carries on. Both reject every identification string that no
/// honest peer sends; not reported.
pub(crate) fn is_version_strictness_diff(diff: &puffin::differential::TraceDifference) -> bool {
    is_banner_reject_diff(diff, "No version of SSH protocol usable")
}

/// Whether `diff` is libssh rejecting the client identification string with the
/// error `reject` while the other stack accepted it.
///
/// Matched SURGICALLY so it cannot mask an unrelated bug: a `Status` diff where
/// ONE side carries libssh's specific banner rejection string AND the
/// OTHER side accepted (`Success`) or progressed strictly further. It never
/// drops a both-reject pair, never drops any other error kind, and is symmetric
/// in which PUT is libssh (so it still holds if the PUT order is flipped). A
/// real downstream divergence on the accepting side still surfaces through its
/// own Knowledges/Claims diff or an ASAN crash — those `TraceDifference` entries
/// are filtered independently of this Status entry.
fn is_banner_reject_diff(diff: &puffin::differential::TraceDifference, reject: &str) -> bool {
    use puffin::differential::TraceDifference;
    let TraceDifference::Status(s) = diff else {
        return false;
    };
    let is_banner_reject = |st: &str| st.contains(reject);
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

/// The KNOWLEDGE-layer form of a banner-length / version divergence: one side rejected
/// the banner so it never decrypted a transcript, yielding a `AlignedTranscript`
/// vs `()` presence difference. Matched ONLY to co-drop it alongside a shadowed
/// banner *status* reject (see `differential_fuzzing_filter_diffs`) — never on its
/// own, because the same shape is a genuine "one stack completes, the other does
/// not" divergence when no banner reject explains it.
///
/// NOTE (does NOT silence the banner reject end-to-end): the accepting side only produces an
/// `AlignedTranscript` because it emitted an `SshClaimInner` (`fn_fold_s2c_transcript` sources
/// the keys from the claim's exchange hash). So whenever this knowledge presence diff exists, a
/// CLAIM presence diff (`Box<SshClaimInner>` vs `()`) co-exists — and claim diffs are kept
/// fail-closed ([`crate::protocol`]'s `claim_presence_difference_is_kept`). This co-drop therefore
/// only removes the redundant *knowledge* form; a banner reject against a KEX-completing peer
/// still surfaces as a claim-layer objective. The match is thus effectively a no-op in real
/// executions and is retained only as a defensive, cheap narrowing.
pub(crate) fn is_banner_induced_transcript_presence(
    diff: &puffin::differential::TraceDifference,
) -> bool {
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

/// USERAUTH_FAILURE presence-only transcript delta: the SECOND stack's decrypted transcript carries
/// extra USERAUTH_FAILURE(s) (SSH msg 51: a method-list advertisement / auth rejection) that the
/// first does NOT, and nothing else differs. Investigated benign by a 272-objective auth-outcome
/// scan (2026-09-02): 0 success-asymmetry — no objective reaches USERAUTH_SUCCESS on either stack,
/// so this is never an accept-vs-reject (auth-policy) divergence; auth fails on both and the stacks
/// merely differ in which rejection packet they emit.
///
/// STRICT and presence-only, so it can NEVER mask a real divergence (F-07). The delta is the
/// `comparable` crate's Debug string of the `AlignedTranscript` comparison, shaped
/// `[ByKey([...]), Order([...])]`. It is shadowed ONLY when ALL of:
///   * it mentions `UserAuthFailure` but NOT `UserAuthSuccess` (msg 52 is the accept-vs-reject
///     divergence and is always kept);
///   * it contains NO `Changed(` anywhere. A `Changed(` is either a key whose CONTENT differs —
///     e.g. `partial_success` flipped, `BothUserAuthFailure([PartialSuccess(BoolChange(..))])` — or
///     an emission-`Order` transposition (`Order([Changed(..)])`, `MsgNumber(U8Change(..))`), both
///     genuine divergences. A pure presence/absence asymmetry prints only `Added(` / `Removed(`;
///   * it contains NO `partial_success: true`. A failure present on one side only that reports
///     partial success (RFC 4252 §5.1: that side ACCEPTED the request but wants another method) is
///     an auth-state divergence, not a mere difference in rejection packets;
///   * every `AlignmentKey` it mentions is a USERAUTH_FAILURE (msg 51). A co-occurring message
///     present on one side only (SERVICE_ACCEPT 6, CHANNEL_OPEN_CONFIRMATION 91, …) contributes a
///     non-51 `msg_number:` and keeps the whole delta.
///
/// Only the second stack's extra failures can be shadowed. `comparable` prints a key present on
/// the second side only as `Added(key, value)`, whose value names `UserAuthFailure`, but a key
/// present on the first side only as `Removed(key)`, the key alone. That mirror case fails the
/// `UserAuthFailure` condition and is kept (fail-closed).
///
/// (The earlier form only required the delta to mention `UserAuthFailure` and not
/// `UserAuthSuccess`, which masked `partial_success` flips, `Order` transpositions and any change
/// co-occurring with a USERAUTH_FAILURE — F-07.)
pub(crate) fn is_userauth_failure_only_diff(diff: &puffin::differential::TraceDifference) -> bool {
    use puffin::differential::{KnowledgeDiff, TraceDifference};
    let TraceDifference::Knowledges(KnowledgeDiff::InnerDifference {
        type_name, diff, ..
    }) = diff
    else {
        return false;
    };
    if !type_name.contains("AlignedTranscript") || !diff.contains("UserAuthFailure") {
        return false;
    }
    // Any `Changed(` (a content change such as a `partial_success` flip, or an emission-`Order`
    // transposition), any `UserAuthSuccess` (the accept-vs-reject divergence) and any one-sided
    // failure reporting `partial_success: true` (that side ACCEPTED the request) keep the delta. A
    // benign presence/absence asymmetry prints only `Added(` / `Removed(` entries.
    if diff.contains("Changed(")
        || diff.contains("UserAuthSuccess")
        || diff.contains("partial_success: true")
    {
        return false;
    }
    // Every `AlignmentKey` mentioned (an `Added(`/`Removed(` entry) must be a USERAUTH_FAILURE (msg
    // 51); a single non-51 key (another message present on one side only) keeps the whole delta.
    let mut saw_key = false;
    let mut rest = diff.as_str();
    while let Some(pos) = rest.find("msg_number:") {
        rest = &rest[pos + "msg_number:".len()..];
        let number: String = rest
            .trim_start()
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        saw_key = true;
        if number != "51" {
            return false;
        }
    }
    // Require at least one parsed key (otherwise we cannot prove it is a USERAUTH_FAILURE
    // asymmetry).
    saw_key
}

/// wolfSSH tcpip-forward REQUEST_SUCCESS port-echo (wolfSSL/wolfssh#1246).
/// Both stacks ACCEPT an authorized
/// tcpip-forward (both emit SSH_MSG_REQUEST_SUCCESS), but wolfSSH appends the
/// bound port even for a non-zero requested port, while libssh sends a bare reply;
/// so the `comparable` transcript diff is a single `Changed` on the REQUEST_SUCCESS
/// (msg 81) key whose ONLY delta is a purely-additive `response_data` byte run (the
/// echoed port). RFC 4254 §7.1 returns the port only for a port-0 dynamic request
/// (OpenSSH + libssh agree); a documented, root-caused, LOW-severity conformance
/// deviation. Shadowed so long campaigns stop re-reporting it; the diverging
/// `forwarding` seed remains the record.
///
/// VERY STRICT — matches ONLY that exact shape, so it can never mask a real
/// forwarding divergence:
///   * `BothRequestSuccess`  => both ACCEPTED (an accept-vs-reject forward, i.e. RequestSuccess vs
///     RequestFailure, is NOT "BothRequestSuccess" -> KEPT);
///   * the ONLY changed field is `response_data` (`RequestSuccessMessageChange`);
///   * EXACTLY ONE changed alignment key, and it is msg 81 (no other message present/absent/changed
///     -> a diff touching anything else is KEPT);
///   * the response_data delta is a whole port against nothing: exactly `Added(0..=3, _)` (wolfSSH
///     is the second PUT) or exactly `Removed(0..=3, _)` (it is the first), i.e. one side sent no
///     data and the other the 4 bytes of a uint32, and no `Changed(` inside it -> a both-non-empty,
///     longer, shorter or otherwise-shaped response_data difference is KEPT.
///
/// Not keyed to a specific port value, so a mutated forward port is still shadowed
/// but nothing broader is.
pub(crate) fn is_fwd_reqsuccess_port_echo_diff(
    diff: &puffin::differential::TraceDifference,
) -> bool {
    use puffin::differential::{KnowledgeDiff, TraceDifference};
    let TraceDifference::Knowledges(KnowledgeDiff::InnerDifference {
        type_name, diff, ..
    }) = diff
    else {
        return false;
    };
    // the response_data delta is the 4 bytes of a port, on one side only, against no data
    let port_echo = |entry: &str, other: &str| {
        diff.matches(&format!("{entry}(")).count() == 4
            && (0..4).all(|index| diff.contains(&format!("{entry}({index}, ")))
            && !diff.contains(&format!("{other}("))
    };
    type_name.contains("AlignedTranscript")
        // both accepted the forward (guards against masking accept-vs-reject)
        && diff.contains("BothRequestSuccess")
        // the only delta is the response_data field of the REQUEST_SUCCESS
        && diff.contains("RequestSuccessMessageChange")
        && diff.contains("response_data")
        // EXACTLY ONE changed alignment key, and it is REQUEST_SUCCESS (msg 81);
        // any additional present/absent/changed message keeps the objective
        && diff.matches("Changed(AlignmentKey").count() == 1
        // ... and no other `Changed(`: a byte both stacks sent differently is KEPT
        && diff.matches("Changed(").count() == 1
        && diff.contains("msg_number: 81")
        && !diff.contains("Added(AlignmentKey")
        && !diff.contains("Removed(AlignmentKey")
        // a port echo, on one side
        && (port_echo("Added", "Removed") || port_echo("Removed", "Added"))
}

/// wolfSSH 1.6.0 re-advertises `ext-info-s` in the KEXINIT of every rekey (F-18). Its
/// `SendKexInit` (src/internal.c) appends `,ext-info-s` to the server's kex-algorithms list in
/// every KEXINIT, and the strict-KEX markers only while the session id is empty, i.e. in the
/// first key exchange. RFC 8308 §2.1 asks for the indicator in the first key exchange, and an
/// EXT_INFO can only follow the first NEWKEYS (§2.4), so a rekey indicator announces nothing.
/// The libssh and wolfSSH 1.5.0 servers do not advertise `ext-info-s` at all. A LOW-severity
/// deviation, not a vulnerability; shadowed so that long campaigns on wolfSSH 1.6.0 stop
/// re-reporting it.
///
/// VERY STRICT: the whole transcript delta must be exactly ONE changed KEXINIT that is not the
/// first (ordinal >= 1), whose only change is ONE name appended to the SECOND stack's
/// kex-algorithms list, and that name is `ext-info-s`. Hence every other delta is kept:
///   * any other message changed, present on one side only, or emitted in another order;
///   * any other field of that KEXINIT, or another list, that differs as well;
///   * a second appended name, a name changed or removed, or another one (`ext-info-c`,
///     `kex-strict-*`, an algorithm);
///   * the indicator on the FIRST stack's side, printed `Removed(index, "ext-info-s")`: the shadow
///     is one-directional, only `differential-execute <other> <wolfSSH 1.6.0>` pairs are shadowed;
///   * the indicator at index 0, a list holding nothing else: wolfSSH 1.6.0 appends it after its
///     algorithms.
///
/// The match is on the exact `comparable` Debug text: a change of that format stops the shadow
/// (fail-closed) rather than widening it.
pub(crate) fn is_rekey_ext_info_s_diff(diff: &puffin::differential::TraceDifference) -> bool {
    use puffin::differential::{KnowledgeDiff, TraceDifference};
    let TraceDifference::Knowledges(KnowledgeDiff::InnerDifference {
        type_name, diff, ..
    }) = diff
    else {
        return false;
    };
    if !type_name.contains("AlignedTranscript") {
        return false;
    }
    let digits = |s: &str| s.chars().take_while(char::is_ascii_digit).count();
    let positive = |s: &str| s.parse::<u32>().is_ok_and(|n| n > 0);
    let Some(rest) =
        diff.strip_prefix("[ByKey([Changed(AlignmentKey { channel: 0, msg_number: 20, ordinal: ")
    else {
        return false;
    };
    let ordinal_len = digits(rest);
    if !positive(&rest[..ordinal_len]) {
        return false;
    }
    let Some(rest) = rest[ordinal_len..].strip_prefix(
        " }, BothKexInit([KexAlgorithms(KexAlgorithmsChange(NameListChange { comparable_names: \
         [Added(",
    ) else {
        return false;
    };
    let index_len = digits(rest);
    positive(&rest[..index_len]) && &rest[index_len..] == ", \"ext-info-s\")] }))]))])]"
}

// ── AES-GCM packet-counter renumbering (RFC 4253 §7.1 auto-discovery) ────────
//
// The pass keys on function SYMBOLS (`fn_u32_auto`, `fn_encrypt_packet_aesgcm`,
// `fn_new_keys`, `fn_packet`), never on evaluated values, so `fn_u32_auto`'s
// sentinel value is never actually read.

/// Whether `f` is the function symbol `sym`. `Function::name()` is the symbol's
/// `std::any::type_name` (see `DescribableFunction::shape`), so the comparison is tied
/// to the symbol itself: renaming or removing it breaks the build, not the match.
fn is_symbol<F>(f: &Function<SshProtocolTypes>, _sym: F) -> bool {
    f.name() == std::any::type_name::<F>()
}

/// Whether a `Term`'s root application is the function symbol `sym`.
fn term_root_is<F>(term: &Term<SshProtocolTypes>, sym: F) -> bool {
    matches!(&term.term, DYTerm::Application(f, _) if is_symbol(f, sym))
}

/// Whether any sub-term is the function symbol `sym` (read-only DAG walk; no allocation).
fn term_contains_symbol<F: Copy>(term: &Term<SshProtocolTypes>, sym: F) -> bool {
    match &term.term {
        DYTerm::Variable(_) => false,
        DYTerm::Application(f, args) => {
            is_symbol(f, sym) || args.iter().any(|a| term_contains_symbol(a, sym))
        }
    }
}

/// Fast-path predicate for [`preprocess_trace`](puffin::protocol::ProtocolTypes::preprocess_trace):
/// does this step's input recipe carry the auto-counter sentinel anywhere?
pub(crate) fn step_has_auto_counter(step: &Step<SshProtocolTypes>) -> bool {
    match &step.action {
        Action::Input(input) => term_contains_symbol(&input.recipe, fn_u32_auto),
        Action::Output(_) => false,
    }
}

/// Arg-index path (from the recipe root) to the OUTERMOST aes-gcm encrypt node,
/// i.e. the one that seals the wire packet this step emits. Pre-order search:
/// the first match encountered is the closest to the root. `Some(vec![])` means
/// the root itself is the encrypt (the shape every current seed uses).
fn find_outermost_aesgcm_path(term: &Term<SshProtocolTypes>) -> Option<Vec<usize>> {
    if term_root_is(term, fn_encrypt_packet_aesgcm) {
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
    if !term_root_is(term, fn_packet) {
        return false;
    }
    let DYTerm::Application(_, args) = &term.term else {
        return false;
    };
    args.first().is_some_and(|a| term_root_is(a, fn_new_keys))
}

/// The `fn_u32_<n>` constant leaf for counter `n`. The rewritten trace is a throwaway
/// executed immediately (never serialised), so this only needs to EVALUATE to `n`.
/// Returns `None` for `n` beyond the registered range (single-epoch traces stay small),
/// leaving the sentinel in place so the packet simply fails to decrypt rather than
/// silently carrying a wrong counter.
fn u32_leaf(n: u32) -> Option<Term<SshProtocolTypes>> {
    Some(match n {
        0 => term! { fn_u32_0 },
        1 => term! { fn_u32_1 },
        2 => term! { fn_u32_2 },
        3 => term! { fn_u32_3 },
        4 => term! { fn_u32_4 },
        5 => term! { fn_u32_5 },
        6 => term! { fn_u32_6 },
        7 => term! { fn_u32_7 },
        8 => term! { fn_u32_8 },
        9 => term! { fn_u32_9 },
        10 => term! { fn_u32_10 },
        11 => term! { fn_u32_11 },
        12 => term! { fn_u32_12 },
        13 => term! { fn_u32_13 },
        14 => term! { fn_u32_14 },
        15 => term! { fn_u32_15 },
        _ => return None,
    })
}

/// Whether `term` carries a payload that a bit-level mutation changed.
fn has_mutated_payload(term: &Term<SshProtocolTypes>) -> bool {
    term.payloads
        .as_ref()
        .is_some_and(|p| p.has_changed() || p.payload != p.payload_0)
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
///
/// A sentinel whose payload a bit-level mutation changed is left untouched too: it is
/// the fuzzer's counter, and the `[opaque]` encryption reads it from the payload. An
/// unchanged payload only holds the number `MakeMessage` evaluated, the packet's
/// position at that time, so the sentinel is renumbered as if it had none: deleting
/// or inserting a step before it later moves its counter.
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
            let is_encrypted_newkeys = args.first().is_some_and(|m| term_root_is(m, fn_new_keys));
            if let Some(ctr) = args.get_mut(3) {
                if term_root_is(ctr, fn_u32_auto) && !has_mutated_payload(ctr) {
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

#[cfg(test)]
mod filter_diff_tests {
    use comparable::{Changed, Comparable};
    use puffin::differential::{KnowledgeDiff, StatusDiff, TraceDifference};
    use puffin::protocol::ProtocolTypes;

    use super::{
        is_banner_length_diff, is_fwd_reqsuccess_port_echo_diff, is_rekey_ext_info_s_diff,
        is_version_strictness_diff,
    };
    use crate::protocol::SshProtocolTypes;
    use crate::ssh::message::{
        ChannelOpenConfirmationMessage, CompressionAlgorithms, EncryptionAlgorithms, KexAlgorithms,
        KexInitMessage, MacAlgorithms, NameList, RequestSuccessMessage, ServiceAcceptMessage,
        SignatureSchemes, SshBytes, SshMessage, UserAuthFailureMessage,
    };
    use crate::ssh::transcript::AlignedTranscript;

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

    /// Banner-length strictness (libssh-mirror#376, known bug) and version
    /// strictness (benign) are deliberately SHADOWED so campaigns stop
    /// re-reporting known classes. Pairs where one side rejects
    /// the banner/version and the other accepts/progresses MUST now be dropped.
    /// This is the single, precise exception to fail-closed; everything else
    /// (guarded by `cross_vendor_acceptance_divergences_are_all_kept`) is unchanged.
    #[test]
    fn banner_length_and_version_are_separate_classes() {
        // The length class is a filed bug (SHADOW_KNOWN_BUGS), the version class is
        // benign (SHADOW_KNOWN_BENIGN): each predicate must match only its own.
        let length = status("Receiving banner: too large banner", "Success");
        let version = status("No version of SSH protocol usable (banner: x)", "Success");
        assert!(is_banner_length_diff(&length) && !is_version_strictness_diff(&length));
        assert!(is_version_strictness_diff(&version) && !is_banner_length_diff(&version));
    }

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

    /// Build the REAL `comparable` Debug delta between two transcripts, exactly as the differential
    /// engine does (`format!("{:?}", changes)` over `a.comparison(b)`; see
    /// `puffin::protocol`), then wrap it in a knowledge `InnerDifference`. `b` is the "other"
    /// (PUT 2) stack, so a message present only in `b` prints as `Added(key, value)` (carrying the
    /// value name), and one present only in `a` as `Removed(key)` (key only).
    fn real_transcript_diff(a: &AlignedTranscript, b: &AlignedTranscript) -> TraceDifference {
        let diff = match a.comparison(b) {
            Changed::Changed(changes) => format!("{changes:?}"),
            Changed::Unchanged => String::new(),
        };
        transcript_inner_diff(&diff)
    }

    fn diff_body(d: &TraceDifference) -> &str {
        match d {
            TraceDifference::Knowledges(KnowledgeDiff::InnerDifference { diff, .. }) => diff,
            _ => panic!("expected a knowledge InnerDifference"),
        }
    }

    fn uaf(partial_success: bool) -> SshMessage {
        SshMessage::UserAuthFailure(UserAuthFailureMessage {
            authentications_that_can_continue: NameList::from_strs(&["password", "publickey"]),
            partial_success,
        })
    }

    fn svc() -> SshMessage {
        SshMessage::ServiceAccept(ServiceAcceptMessage {
            service_name: SshBytes(b"ssh-userauth".to_vec()),
        })
    }

    fn coc() -> SshMessage {
        SshMessage::ChannelOpenConfirmation(ChannelOpenConfirmationMessage {
            recipient_channel: 0,
            sender_channel: 0,
            initial_window_size: 0,
            maximum_packet_size: 0,
            channel_data: vec![],
        })
    }

    /// A benign presence-only USERAUTH_FAILURE asymmetry (PUT 2 emits one extra method-list /
    /// rejection the other does not, APPENDED at the end) is SHADOWED. Built from the REAL
    /// `AlignedTranscript::comparison` output, not a hand-written string.
    #[test]
    fn userauth_failure_presence_only_is_shadowed() {
        let put1 = AlignedTranscript::from_messages(vec![svc()]);
        let put2 = AlignedTranscript::from_messages(vec![svc(), uaf(false)]);
        let d = real_transcript_diff(&put1, &put2);
        assert!(
            !diff_body(&d).contains("Changed("),
            "a pure presence/absence asymmetry must not print a Changed(: {}",
            diff_body(&d)
        );
        assert!(
            !keep(&d),
            "presence-only USERAUTH_FAILURE asymmetry must be shadowed"
        );
    }

    /// SAFETY (F-07): a `partial_success` flip on the SAME USERAUTH_FAILURE key is a CONTENT change
    /// (prints `Changed(`) and MUST survive — the old "every changed key is msg 51" rule dropped
    /// it.
    #[test]
    fn userauth_failure_partial_success_flip_is_kept() {
        let put1 = AlignedTranscript::from_messages(vec![uaf(false)]);
        let put2 = AlignedTranscript::from_messages(vec![uaf(true)]);
        let d = real_transcript_diff(&put1, &put2);
        assert!(
            diff_body(&d).contains("Changed("),
            "a partial_success flip must print a Changed(: {}",
            diff_body(&d)
        );
        assert!(
            keep(&d),
            "a partial_success content divergence must be kept"
        );
    }

    /// SAFETY (F-07): an emission-`Order` transposition co-occurring with a trailing
    /// USERAUTH_FAILURE asymmetry MUST survive — the transposition prints `Changed(` in the
    /// `Order([...])` section.
    #[test]
    fn userauth_failure_with_order_transposition_is_kept() {
        let put1 = AlignedTranscript::from_messages(vec![svc(), coc()]);
        // coc before svc (a transposition) plus a trailing extra failure on PUT 2.
        let put2 = AlignedTranscript::from_messages(vec![coc(), svc(), uaf(false)]);
        let d = real_transcript_diff(&put1, &put2);
        assert!(
            diff_body(&d).contains("Changed("),
            "an order transposition must print a Changed(: {}",
            diff_body(&d)
        );
        assert!(keep(&d), "an order transposition must never be shadowed");
    }

    /// SAFETY (F-07): a USERAUTH_FAILURE present on PUT 2 only that reports `partial_success: true`
    /// (that side ACCEPTED the request and wants another method) is an auth-state divergence. It
    /// prints no `Changed(`, so only the `partial_success: true` guard keeps it.
    #[test]
    fn userauth_failure_one_sided_partial_success_is_kept() {
        let put1 = AlignedTranscript::from_messages(vec![svc()]);
        let put2 = AlignedTranscript::from_messages(vec![svc(), uaf(true)]);
        let d = real_transcript_diff(&put1, &put2);
        let body = diff_body(&d);
        assert!(
            !body.contains("Changed(") && body.contains("partial_success: true"),
            "a one-sided partial-success failure must print as an Added value: {body}"
        );
        assert!(keep(&d), "a one-sided partial-success failure must be kept");
    }

    /// The shadow is one-directional: an extra USERAUTH_FAILURE on PUT 1's side prints as
    /// `Removed(key)`, without the value, so the `UserAuthFailure` condition fails and the delta is
    /// kept (fail-closed).
    #[test]
    fn userauth_failure_extra_on_put1_is_kept() {
        let put1 = AlignedTranscript::from_messages(vec![svc(), uaf(false)]);
        let put2 = AlignedTranscript::from_messages(vec![svc()]);
        let d = real_transcript_diff(&put1, &put2);
        assert!(
            !diff_body(&d).contains("UserAuthFailure"),
            "a key present on PUT 1 only must print without its value: {}",
            diff_body(&d)
        );
        assert!(
            keep(&d),
            "an extra failure on PUT 1's side must be kept (fail-closed)"
        );
    }

    /// SAFETY (F-07): a USERAUTH_FAILURE asymmetry co-occurring with ANOTHER message present on one
    /// side only (here CHANNEL_OPEN_CONFIRMATION, msg 91) MUST survive — a non-51 key keeps it.
    #[test]
    fn userauth_failure_with_co_occurring_message_is_kept() {
        let put1 = AlignedTranscript::from_messages(vec![svc()]);
        let put2 = AlignedTranscript::from_messages(vec![svc(), uaf(false), coc()]);
        assert!(keep(&real_transcript_diff(&put1, &put2)));
    }

    /// SAFETY GUARD (F-07): USERAUTH_SUCCESS anywhere is the accept-vs-reject divergence and is
    /// NEVER shadowed, even when a USERAUTH_FAILURE also appears.
    #[test]
    fn userauth_success_asymmetry_is_always_kept() {
        // SUCCESS present only on PUT 2.
        let put1 = AlignedTranscript::from_messages(vec![svc()]);
        let put2 = AlignedTranscript::from_messages(vec![svc(), SshMessage::UserAuthSuccess]);
        assert!(keep(&real_transcript_diff(&put1, &put2)));
        // SUCCESS and FAILURE both added on PUT 2 — still kept (the success guard fires).
        let put2b =
            AlignedTranscript::from_messages(vec![svc(), uaf(false), SshMessage::UserAuthSuccess]);
        assert!(keep(&real_transcript_diff(&put1, &put2b)));
    }

    /// wolfSSH tcpip-forward REQUEST_SUCCESS port-echo — the EXACT diff produced by
    /// `seed_client_attacker_forwarding` (both accept the forward; wolfSSH appends
    /// the bound port to REQUEST_SUCCESS, libssh sends a bare reply). Filed as
    /// wolfSSL/wolfssh#1246 and SHADOWED.
    #[test]
    fn fwd_reqsuccess_port_echo_is_shadowed() {
        assert!(!keep(&transcript_inner_diff(
            "[ByKey([Changed(AlignmentKey { channel: 0, msg_number: 81, ordinal: 0 }, \
             BothRequestSuccess(RequestSuccessMessageChange { response_data: \
             [Added(0, 0), Added(1, 0), Added(2, 0), Added(3, 22)] }))])]"
        )));
    }

    /// The shadow does not depend on which PUT is first, and only takes an echo on one side:
    /// real comparisons of two REQUEST_SUCCESS messages.
    #[test]
    fn fwd_port_echo_shadow_is_symmetric_and_one_sided() {
        let reply = |response_data: &[u8]| {
            AlignedTranscript::from_messages(vec![SshMessage::RequestSuccess(
                RequestSuccessMessage {
                    response_data: response_data.to_vec(),
                },
            )])
        };
        let shadowed = |a: &[u8], b: &[u8]| {
            is_fwd_reqsuccess_port_echo_diff(&real_transcript_diff(&reply(a), &reply(b)))
        };
        let port = [0, 0, 0, 22];
        assert!(shadowed(&[], &port), "wolfSSH is the second PUT");
        assert!(shadowed(&port, &[]), "wolfSSH is the first PUT");
        assert!(!shadowed(&[1], &[2]), "a byte that differs");
        assert!(
            !shadowed(&[1], &[2, 0]),
            "a byte that differs, and one added"
        );
        assert!(
            !shadowed(&[1, 0], &[2]),
            "a byte that differs, and one removed"
        );
        assert!(!shadowed(&[], &[0; 9]), "longer than a port echo");
        assert!(!shadowed(&[0; 9], &[]), "longer than a port echo");
        assert!(!shadowed(&[], &[0; 5]), "longer than a port echo");
        assert!(!shadowed(&[], &[0; 3]), "shorter than a port echo");
        assert!(
            !shadowed(&[0xaa], &[0xaa, 0, 0, 0, 22]),
            "a port appended to data the other side also sent"
        );
        assert!(
            !shadowed(&[0xaa, 0, 0, 0, 22], &[0xaa]),
            "a port appended to data the other side also sent"
        );
        assert!(!shadowed(&port, &port), "no difference");
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

    /// A KEXINIT whose kex algorithms are curve25519-sha256, ecdh-sha2-nistp256, then `extra`.
    fn kexinit_with(extra: &[&str]) -> SshMessage {
        let mut kex = vec!["curve25519-sha256", "ecdh-sha2-nistp256"];
        kex.extend_from_slice(extra);
        let list = NameList::from_strs;
        SshMessage::KexInit(KexInitMessage {
            cookie: [0; 16],
            kex_algorithms: KexAlgorithms(list(&kex)),
            server_host_key_algorithms: SignatureSchemes(list(&["rsa-sha2-256"])),
            encryption_algorithms_client_to_server: EncryptionAlgorithms(list(&["aes256-gcm"])),
            encryption_algorithms_server_to_client: EncryptionAlgorithms(list(&["aes256-gcm"])),
            mac_algorithms_client_to_server: MacAlgorithms(list(&["hmac-sha2-256"])),
            mac_algorithms_server_to_client: MacAlgorithms(list(&["hmac-sha2-256"])),
            compression_algorithms_client_to_server: CompressionAlgorithms(list(&["none"])),
            compression_algorithms_server_to_client: CompressionAlgorithms(list(&["none"])),
            languages_client_to_server: NameList::empty(),
            languages_server_to_client: NameList::empty(),
            first_kex_packet_follows: false,
        })
    }

    /// A first KEXINIT with libssh's marker, a SERVICE_ACCEPT, then a rekey KEXINIT `rekey`.
    fn with_rekey(rekey: SshMessage) -> AlignedTranscript {
        AlignedTranscript::from_messages(vec![
            kexinit_with(&["kex-strict-s-v00@openssh.com"]),
            svc(),
            rekey,
        ])
    }

    /// wolfSSH 1.6.0 as the second stack appends `ext-info-s` to its rekey KEXINIT, and nothing
    /// else differs: shadowed. Also the delta exactly as `differential-execute libssh0114
    /// wolfssh160` printed it on the `rekey` seed.
    #[test]
    fn rekey_ext_info_s_on_the_second_stack_alone_is_shadowed() {
        let d = real_transcript_diff(
            &with_rekey(kexinit_with(&[])),
            &with_rekey(kexinit_with(&["ext-info-s"])),
        );
        assert!(is_rekey_ext_info_s_diff(&d), "{}", diff_body(&d));
        assert!(!keep(&d));

        assert!(!keep(&transcript_inner_diff(
            "[ByKey([Changed(AlignmentKey { channel: 0, msg_number: 20, ordinal: 1 }, \
             BothKexInit([KexAlgorithms(KexAlgorithmsChange(NameListChange { comparable_names: \
             [Added(8, \"ext-info-s\")] }))]))])]"
        )));
    }

    /// Anything beyond that one appended name keeps the delta.
    #[test]
    fn rekey_ext_info_s_with_anything_else_is_kept() {
        let plain = || with_rekey(kexinit_with(&[]));
        let kept = |a: &AlignedTranscript, b: &AlignedTranscript| {
            let d = real_transcript_diff(a, b);
            assert!(!is_rekey_ext_info_s_diff(&d), "{}", diff_body(&d));
            assert!(keep(&d));
        };
        // the indicator on the first stack's side
        let first_side = real_transcript_diff(&with_rekey(kexinit_with(&["ext-info-s"])), &plain());
        assert!(
            diff_body(&first_side).contains("[Removed(2, \"ext-info-s\")]"),
            "{}",
            diff_body(&first_side)
        );
        kept(&with_rekey(kexinit_with(&["ext-info-s"])), &plain());
        // another indicator or algorithm, or two names
        for extra in [
            &["ext-info-c"][..],
            &["kex-strict-s-v00@openssh.com"],
            &["diffie-hellman-group14-sha256"],
            &["ext-info-s", "kex-strict-s-v00@openssh.com"],
        ] {
            kept(&plain(), &with_rekey(kexinit_with(extra)));
        }
        // another field of the rekey KEXINIT differs too
        let SshMessage::KexInit(mut changed) = kexinit_with(&["ext-info-s"]) else {
            unreachable!()
        };
        changed.first_kex_packet_follows = true;
        kept(&plain(), &with_rekey(SshMessage::KexInit(changed)));
        // another message differs too
        let mut messages = vec![
            kexinit_with(&["kex-strict-s-v00@openssh.com"]),
            svc(),
            kexinit_with(&["ext-info-s"]),
        ];
        messages.push(coc());
        kept(&plain(), &AlignedTranscript::from_messages(messages));
        // the same delta on the first KEXINIT (ordinal 0) is not a rekey
        assert!(keep(&transcript_inner_diff(
            "[ByKey([Changed(AlignmentKey { channel: 0, msg_number: 20, ordinal: 0 }, \
             BothKexInit([KexAlgorithms(KexAlgorithmsChange(NameListChange { comparable_names: \
             [Added(8, \"ext-info-s\")] }))]))])]"
        )));
        // the indicator alone in the list, at index 0
        assert!(keep(&transcript_inner_diff(
            "[ByKey([Changed(AlignmentKey { channel: 0, msg_number: 20, ordinal: 1 }, \
             BothKexInit([KexAlgorithms(KexAlgorithmsChange(NameListChange { comparable_names: \
             [Added(0, \"ext-info-s\")] }))]))])]"
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

    /// Context-aware co-drop: when a banner-strictness status reject is shadowed, the
    /// `AlignedTranscript vs ()` KNOWLEDGE presence diff it induces on the accepting side is the
    /// SAME divergence and is dropped together. Isolated case (synthetic): no claim diff present.
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

    /// REAL-execution case (F-04): the accepting side only has an `AlignedTranscript` because it
    /// emitted a claim, so a CLAIM presence diff co-occurs. That claim diff is kept fail-closed, so
    /// the banner reject is NOT silenced end-to-end — only its redundant knowledge form drops.
    #[test]
    fn banner_reject_against_kex_completing_peer_still_objectives_via_claim() {
        use puffin::differential::ClaimDiff;

        let claim_presence = TraceDifference::Claims(ClaimDiff::DifferentTypes {
            agent: 1,
            index: 0,
            first_type: "alloc::boxed::Box<sshpuffin::claim::SshClaimInner>".into(),
            second_type: "()".into(),
        });
        let set = vec![
            status("Receiving banner: too large banner", "Success"),
            transcript_presence(),
            claim_presence.clone(),
        ];
        let kept = SshProtocolTypes::differential_fuzzing_filter_diffs(set);
        assert_eq!(
            kept,
            vec![claim_presence],
            "the status + knowledge-presence forms drop, but the claim presence diff must SURVIVE \
             (fail-closed), so a banner reject against a KEX-completing peer still objectives"
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

    /// The name `Function::name()` reports for the symbol `sym`.
    fn sym<F>(_sym: F) -> &'static str {
        std::any::type_name::<F>()
    }

    /// Symbol name of a step's outermost aes-gcm counter argument (index 3), or
    /// `None` if the step is not an aes-gcm packet.
    fn counter_name(trace: &Trace<SshProtocolTypes>, step: usize) -> Option<&'static str> {
        let Action::Input(input) = &trace.steps[step].action else {
            return None;
        };
        let DYTerm::Application(f, args) = &input.recipe.term else {
            return None;
        };
        if f.name() != sym(fn_encrypt_packet_aesgcm) {
            return None;
        }
        match &args.get(3)?.term {
            DYTerm::Application(cf, _) => Some(cf.name()),
            DYTerm::Variable(_) => None,
        }
    }

    #[test]
    fn symbols_match_their_signature_entries() {
        // Traces loaded from disk get their functions from the signature, so the
        // symbol name the pass compares against must be the registered one.
        let sig = SshProtocolTypes::signature();
        for name in [
            sym(fn_u32_auto),
            sym(fn_encrypt_packet_aesgcm),
            sym(fn_new_keys),
            sym(fn_packet),
        ] {
            assert!(
                sig.functions_by_name.contains_key(name),
                "{name} not registered"
            );
        }
    }

    #[test]
    fn consecutive_auto_counters_renumber_from_zero() {
        let trace = trace_of(vec![auto_pkt(svc()), auto_pkt(svc()), auto_pkt(svc())]);
        let out = SshProtocolTypes::preprocess_trace(&trace).expect("sentinel present -> Some");
        assert_eq!(counter_name(&out, 0), Some(sym(fn_u32_0)));
        assert_eq!(counter_name(&out, 1), Some(sym(fn_u32_1)));
        assert_eq!(counter_name(&out, 2), Some(sym(fn_u32_2)));
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
        assert_eq!(counter_name(&out, 0), Some(sym(fn_u32_0)));
        assert_eq!(counter_name(&out, 1), Some(sym(fn_u32_1)));
        assert_eq!(counter_name(&out, 2), Some(sym(fn_u32_2)));
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
        assert_eq!(counter_name(&out, 0), Some(sym(fn_u32_0)));
        // step 1 is explicit fn_u32_max -> untouched (its wire slot still consumes
        // a counter, so the next sentinel is 2, not 1).
        assert_eq!(counter_name(&out, 1), Some(sym(fn_u32_max)));
        assert_eq!(counter_name(&out, 2), Some(sym(fn_u32_2)));
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
        assert_eq!(counter_name(&out, 0), Some(sym(fn_u32_0)));
        assert_eq!(counter_name(&out, 1), Some(sym(fn_u32_1)));
        assert_eq!(counter_name(&out, 2), None); // plaintext newkeys, not a gcm pkt
        assert_eq!(counter_name(&out, 3), Some(sym(fn_u32_0)));
        assert_eq!(counter_name(&out, 4), Some(sym(fn_u32_1)));
    }

    #[test]
    fn counter_resets_after_encrypted_newkeys() {
        // An ENCRYPTED NEWKEYS (a rekey completion) carries its own epoch-final
        // counter, then the epoch resets: svc(0), NEWKEYS(1), next-epoch svc(0).
        let enc_newkeys = auto_pkt(term! { fn_new_keys });
        let trace = trace_of(vec![auto_pkt(svc()), enc_newkeys, auto_pkt(svc())]);
        let out = SshProtocolTypes::preprocess_trace(&trace).expect("sentinel present -> Some");
        assert_eq!(counter_name(&out, 0), Some(sym(fn_u32_0)));
        assert_eq!(counter_name(&out, 1), Some(sym(fn_u32_1)));
        assert_eq!(counter_name(&out, 2), Some(sym(fn_u32_0)));
    }

    #[test]
    fn no_sentinel_trace_is_untouched_fast_path() {
        let trace = trace_of(vec![term! { fn_packet((fn_new_keys)) }]);
        assert!(SshProtocolTypes::preprocess_trace(&trace).is_none());
    }
}
