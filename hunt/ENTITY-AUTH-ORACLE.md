# Entity-authentication oracle, approach 1: claim-based invariants

Branch `cves/CVE-2025-14942-entity-auth-ddyf`, on `cves/CVE-2025-11625-ddyf`, on
`origin/pr/ssh/ddyf-artifact` (bb8574845). It is a redesign of the first version,
`cves/CVE-2025-14942-entity-auth` (P1/P2/P3), which stays as it was. Approach 2, from the trace and
the attacker's knowledge, is planned in [`ENTITY-AUTH-TRACE-ORACLE-PLAN.md`](ENTITY-AUTH-TRACE-ORACLE-PLAN.md).
Per-version support is in the support matrix (`docs/docs/references/support-matrix.md`, SSH section).

## Principle

An entity-authentication violation is a PUT reaching an *authenticated* state of its library while
the *check that must precede it* never happened.

- The state is read by an instrument accessor. Pure observation, added to the library at build time.
- The check is recorded where the library performs or delegates it, by the harness, or by the
  instrument when the library offers no callback.
- When the state is reached without the check, the harness raises a one-shot claim flag, which never
  happens on an honest run.
- `SshSecurityViolationPolicy` maps each flag to its violation.
- There are no checks on the content of completion claims, no opt-in gate (flags default to off),
  and no cross-agent comparison.

| id | role | invariant | library state | check record | violation |
|---|---|---|---|---|---|
| C1 | client | keyed ⟹ host key checked | wolfSSH `puffin_wolfssh_client_keyed`; libssh `puffin_ssh_client_keyed` | wolfSSH `host_key_checked` (its `public_key_check_callback`, only called from `DoKexDhReply`); libssh `puffin_ssh_client_hostkey_verified` | Host authentication bypass |
| C2 | client | user-auth accepted ⟹ keyed | wolfSSH `puffin_wolfssh_authed_while_keying`; libssh `puffin_ssh_client_authed_unkeyed` | — (the state itself is contradictory) | Authentication bypass |
| S1 | server | client authenticated ⟹ the harness approved a credential | wolfSSH `clientState >= CLIENT_USERAUTH_DONE`; libssh `flags & SSH_SESSION_FLAG_AUTHENTICATED` | wolfSSH `auth_approved`; libssh `authenticated` | User authentication bypass |

All three invariants are checked on both vendors, except C1 on libssh 0.8.x (see Gaps). C1 and C2
first came from the CVE-2025-11625 and CVE-2025-14942 branches (wolfSSH). The first claim raising a
flag decides; within a claim, C2, then C1, then S1.

## Why each invariant cannot fire honestly

**S1, libssh 0.8.3 to 0.12.2.**
- A server sets `SSH_SESSION_FLAG_AUTHENTICATED` only in `ssh_auth_reply_success`.
- That function is reached only from the callback dispatch of `messages.c`: password, publickey with a
  signature, none, keyboard-interactive. Each path requires the callback to return success.
- The harness registers only the password and publickey callbacks, and sets `authenticated` in them
  before returning success.
- A publickey query only gets PK_OK, and GSSAPI is built off (`-DWITH_GSSAPI=OFF`).

**S1, wolfSSH 1.4.20 to 1.6.0.** `clientState = CLIENT_USERAUTH_DONE` is set at four sites:
- *none* and *keyboard-interactive* need `userAuthCb` to succeed. The harness returns FAILURE for
  both, and keyboard-interactive is not compiled in.
- *password* needs the harness's password branch, which sets `auth_approved`.
- *publickey* needs `userAuthResultCb(SUCCESS)`, which is called after wolfSSH verified the signature:
  exactly where the harness sets `auth_approved`.

The `ClientStates` enum is ordered, so `>=` means "authenticated or beyond".

**C1 and C2, libssh.**
- *Keyed* means `current_crypto` is set. libssh switches it on only once both directions use the new
  keys (`ssh_packet_set_newkeys`, `used == SSH_DIRECTION_BOTH`), and a client switches its incoming
  direction only after the server's host-key signature verified. The outgoing switch, when the client
  sends its NEWKEYS before that verification, is therefore not "keyed".
- *The record*: libssh verifies that signature inside `ssh_packet_newkeys`, with no callback. So
  `instrument_hostkey.cmake` routes that one call of `packet_cb.c` through a wrapper. The wrapper
  returns exactly what `ssh_pki_signature_verify` returns, and records per session that it returned
  `SSH_OK`.
  - It is anchored on the call itself, which `packet_cb.c` has exactly once in libssh 0.9.5, 0.10.4,
    0.11.4 and 0.12.2.
  - Where it has not (0.8.x), nothing is changed and the record is not defined. The harness checks C1
    only when both the state and the record exist, so a build without the record cannot misread
    every keyed client as a bypass.
- *C2*: the client believes the server accepted its user authentication
  (`SSH_SESSION_FLAG_AUTHENTICATED`) without `current_crypto`. A client starts user authentication
  only once keyed, so this cannot happen honestly.

**C1 and C2, wolfSSH**: see the CVE-2025-11625 and CVE-2025-14942 reports.

## What the first version had, and why it is not carried over

1. **P1's checks of the completion claim's content** ("a verified signature and an authorized
   pairing"). On this base both server harnesses emit that claim only after their allow-list
   approved the credential and the library verified it, so the check can never fail. S1 asks the
   question that remains: did the library authenticate without that approval?
2. **wolfSSH `had_signature`.** It was read from `hasSignature` in `auth_callback`, which wolfSSH
   calls *before* verifying the signature, so it meant "carried a signature", not "verified".
3. **libssh P2.** `host_authenticated` was set when `ssh_connect()` returned `SSH_OK`, the same event
   as "keyed", so it was vacuous. C1 on libssh now uses an independent record of the verification
   itself.
4. **P3 and its two-party MITM seed.** The attacker holds the embedded host key, so a MITM running two
   independent key exchanges completes on correct libraries. The first version's own witness fired on
   libssh 0.12.2 and wolfSSH 1.6.0, and it was registered in `with-divergent`, so an unmutated seed
   raised an objective on every instrumented PUT. P3 needs a withheld-key attacker model (approach 2,
   Stage C).
5. **The `role` / `phase` / `entity_auth_checked` fields and gate.** Unneeded: a flag is only ever
   raised by a harness that checks it, and it defaults to off.

## Gaps

- **libssh 0.8.3 does not support the full objective oracle** (marked in the support matrix).
  - C1 is not instrumented: 0.8.x verifies the host key in another key-exchange code.
  - C2 and S1 are instrumented but stay inactive with the standard seed corpora. Those corpora
    negotiate AES-GCM, which 0.8.3 lacks, so the key exchange fails before any authentication.
  - S1 was shown to fire there only with the non-AEAD seed `seed_client_attacker_full_ctr`, which no
    corpus registers.
  - 0.8.3 is not the latest libssh, so this is left as is.
- **S1 has no CVE witness in the catalogue yet.** Its known trigger, a server-side authentication
  bypass, would be a separate catalogue entry.
- **The oracle trusts the library's own verdicts** (a signature it reports as verified, a state it
  reports as reached). A library that verifies wrongly but still calls the callbacks fools it.
  Approach 2 removes that trust.

## Validation (on bb8574845)

- **Unit tests** in `violation.rs`: 3/3. **Catalogue** (wolfSSH, 14 tests, including 1.5.0): green;
  the CVE-2025-14942 and CVE-2025-11625 witnesses raise only their own violation.
- **Accessors compiled in** (`nm`):
  - all wolfSSH accessors in 1.4.20 ×2, 1.4.21 ×2, 1.5.0 and 1.6.0;
  - all four libssh accessors in 0.10.4, 0.11.4 and 0.12.2;
  - 0.8.3 without the host-key record, the instrument reporting "0 host-key verification calls: C1
    is not instrumented".
- **No false fire:** all 20 `with-divergent` seeds on all 10 builds (200 executions) give **0
  violations**, including the logins the servers must reject (`impersonate_a_with_b`,
  `unauthorized_key_c`).
- **The wolfSSH CVE witnesses against libssh clients** (0.10.4, 0.11.4, 0.12.2): libssh's packet
  filter rejects the out-of-order NEWKEYS (type 21, CVE-2025-11625) and USERAUTH_SUCCESS (type 52,
  CVE-2025-14942), with no violation. On 0.8.3 the key exchange fails first.
- **Oracle mutation tests** (scratch builds, never committed). Each disables one record, so its
  invariant must fire wherever the guarded state is honestly reached:
  - S1, approval ignored: it fires on 15–16/20 seeds on every libssh and wolfSSH 1.4.x/1.5.0 build
    and on 13–14/20 on wolfSSH 1.6.0, i.e. every seed where a server logs a client in. It stays
    silent on the rejected logins.
  - C1, record ignored: it fires on the 3 seeds where a client is keyed, on libssh 0.10.4, 0.11.4,
    0.12.2 and wolfSSH 1.4.20 to 1.6.0. It stays silent on libssh 0.8.3, which has no record.
  - C2 on libssh, "keyed" ignored: it fires on the 3 seeds where a libssh client authenticates.
  - On libssh 0.8.3 no seed of the corpora authenticates, and none of these fires.
- **Smoke campaigns** (30 min each, `with-divergent`, single-PUT binaries, every objective replayed):
  - S1 alone: libssh 0.12.2 and wolfSSH 1.6.0, **0 objectives**. The edge maps had 13,501 and 26,097
    edges, at about 1.1k and 0.6k executions per second, reaching 3,213 and 2,241 edges with corpora
    of about 4.9k traces.
  - C1, C2 and S1 together on libssh 0.12.2: **0 objectives**. About 1.75 M executions (~970/s on 6
    cores), a corpus of 5,075 traces, and 3,244 of 13,535 edges.

## Files

- `sshpuffin/include/puffin/ssh.h`: the `user_auth_unapproved` flag.
- `sshpuffin/src/{claim,put,violation}.rs`: the field, the claim filter and decode, the policy.
- `sshpuffin/harness/{wolfssh,libssh}/src/put.c`: the approval records, `check_server_safety` and
  libssh's `check_client_safety`.
- `puffin-build/vendors/{wolfssh,libssh}/instrument_claims.cmake`: the accessors.
- `puffin-build/vendors/libssh/instrument_hostkey.cmake` and `builder.cmake`: C1's host-key record on
  libssh.
