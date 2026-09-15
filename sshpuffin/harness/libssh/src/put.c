/*
 * sshpuffin/harness/libssh/src/put.c
 *
 * LibSSH C harness for sshpuffin.
 *
 * Communication model
 * -------------------
 * We use a Unix socketpair() to give libssh an in-memory full-duplex socket
 * while exposing the opposite end to the puffin fuzzer:
 *
 *   Puffin (Rust)         C Harness (this file)
 *        |                      |
 *        | add_inbound(bytes)   |   fuzz_fd ←──── data written here
 *        |──────────────────────▶   (socketpair end 0)
 *        |                      |       │
 *        |                      |  (kernel socket buffer)
 *        |                      |       │
 *        |                      |   put_fd ────── libssh session
 *        |                      |   (socketpair end 1, set via SSH_OPTIONS_FD)
 *        |                      │
 *        | take_outbound()       |   fuzz_fd ──── read libssh output here
 *        |◀──────────────────────|
 *
 * Both ends are set to O_NONBLOCK so that progress() returns RESULT_IO_WOULD_BLOCK
 * rather than blocking the fuzzer when no data is available.
 */

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#include "bindings.h"
#include "rng.h"
#include <puffin/ssh_authorized_creds.h>

/*
 * Claim instrumentation (HAS_CLAIMS).
 *
 * Everything guarded by HAS_CLAIMS below builds the security-claim used by the
 * claims-based matching-conversation / entity-authentication oracle. It is
 * compiled ONLY when the vendored libssh carries the PUFFIN claim-instrumentation
 * patch (puffin-build/vendors/libssh/instrument_claims.cmake) — the build sets
 * -DHAS_CLAIMS iff the library exposes those hooks (see puffin-build harness
 * wrap()). When it is absent (a plain vendored libssh, or the differential
 * fuzzing setup that does not register a claimer), this code compiles out to
 * no-ops, keeping the harness minimal and symmetric with the wolfSSH harness —
 * i.e. a thin driver that only makes authorization decisions and lets libssh
 * own the protocol. It never affects the protocol path (state transitions live
 * outside these functions), only whether a claim is emitted.
 *
 * The hooks below expose the session id (exchange hash H) and per-direction
 * secure-channel message-type digests; they are not in any public libssh header.
 */
#ifdef HAS_CLAIMS
extern uint64_t puffin_ssh_get_secure_tx_digest(ssh_session session) __attribute__((weak));
extern uint64_t puffin_ssh_get_secure_rx_digest(ssh_session session) __attribute__((weak));
extern int puffin_ssh_get_session_id(ssh_session session, const unsigned char **out, size_t *len)
    __attribute__((weak));
extern uint32_t puffin_ssh_get_rx_count(ssh_session session) __attribute__((weak));
extern uint32_t puffin_ssh_get_tx_count(ssh_session session) __attribute__((weak));
#endif /* HAS_CLAIMS */

/* ── Embedded RSA host key (server only) ─────────────────────────────────── */

static const char *SERVER_HOST_KEY =
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "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\n"
    "-----END OPENSSH PRIVATE KEY-----\n";

/* ── Internal state ──────────────────────────────────────────────────────── */

typedef enum
{
    PUT_STATE_KEX,   /* key-exchange (or TCP connect) in progress */
    PUT_STATE_AUTH,  /* authentication in progress */
    PUT_STATE_DONE,  /* fully authenticated */
    PUT_STATE_ERROR, /* unrecoverable error */
} PutState;

struct AGENT_TYPE
{
    uint8_t name;
    SSH_AGENT_DESCRIPTOR descriptor;

    int fuzz_fd; /* puffin reads/writes here (socketpair end 0) */
    int put_fd;  /* libssh's end (socketpair end 1); kept so destroy() can
                    close it explicitly if ssh_free() leaves it open */

    ssh_session session;
    ssh_bind bind; /* server only; NULL for client */

    PutState state;
    char state_desc[256]; /* human-readable state for describe_state */

    const CLAIMER_CB *claimer; /* registered claim callback, or NULL */
    bool claim_emitted;        /* guard so the handshake claim fires once */
    int last_emitted_phase;    /* highest intermediate phase claim emitted (-1=none) */

    /* Authentication belief recorded by the server auth handler. */
    char auth_method[SSH_CLAIM_STR_LEN];
    char auth_user[SSH_CLAIM_STR_LEN];
    uint8_t auth_key_fp[32];
    uint8_t auth_key_fp_len;

    /* High-level server-callbacks harness state. libssh keeps pointers to these
       callback structs for the whole session lifetime, so they must live in the
       agent (not on the stack). This lets libssh's own state machine drive auth,
       service and channel handling — including sending CHANNEL_SUCCESS for a
       want_reply exec/shell request — rather than the harness re-implementing it
       via the low-level ssh_message API. */
    struct ssh_server_callbacks_struct server_cb;
    struct ssh_channel_callbacks_struct channel_cb;
    ssh_event event;      /* event loop that dispatches the callbacks */
    ssh_channel channel;  /* session channel the client opened, or NULL */
    bool authenticated;   /* set by the auth callback */
    bool callbacks_ready; /* server callbacks + event registered (post-KEX) */
};

/* ── Forward declarations ────────────────────────────────────────────────── */

static AGENT libssh_create(const SSH_AGENT_DESCRIPTOR *descriptor);
static void libssh_destroy(AGENT agent);
static RESULT libssh_progress(AGENT agent);
static RESULT libssh_reset(AGENT agent, uint8_t new_name, uint8_t use_clear);
static const char *libssh_describe_state(AGENT agent);
static bool libssh_is_successful(AGENT agent);
static void libssh_register_claimer(AGENT agent, const CLAIMER_CB *claimer);
static RESULT libssh_add_inbound(AGENT agent, const uint8_t *bytes, size_t length, size_t *written);
static RESULT
libssh_take_outbound(AGENT agent, uint8_t *bytes, size_t max_length, size_t *readbytes);

/* ── PUT interface table ─────────────────────────────────────────────────── */

static const SSH_PUT_INTERFACE LIBSSH_PUT = {
    .create = libssh_create,
    .rng_reseed = rng_reseed,
    .agent_interface =
        {
            .destroy = libssh_destroy,
            .progress = libssh_progress,
            .reset = libssh_reset,
            .describe_state = libssh_describe_state,
            .is_state_successful = libssh_is_successful,
            .register_claimer = libssh_register_claimer,
            .add_inbound = libssh_add_inbound,
            .take_outbound = libssh_take_outbound,
        },
};

/* ── REGISTER entry point (called by puffin-build bundle machinery) ─────── */

const SSH_PUT_INTERFACE *REGISTER(void)
{
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0)
    {
        rl.rlim_cur = (rl.rlim_max == RLIM_INFINITY) ? 65536 : rl.rlim_max;
        setrlimit(RLIMIT_NOFILE, &rl);
    }
    /* Install the deterministic PRNG so handshakes are reproducible. */
    rng_init();
    return &LIBSSH_PUT;
}

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static RESULT ok_result(void)
{
    return PUFFIN.make_result(RESULT_OK, "ok");
}

static RESULT would_block_result(const char *reason)
{
    return PUFFIN.make_result(RESULT_IO_WOULD_BLOCK, reason);
}

static RESULT error_result(const char *reason)
{
    return PUFFIN.make_result(RESULT_ERROR_OTHER, reason);
}

/* ── create ──────────────────────────────────────────────────────────────── */

static AGENT libssh_create(const SSH_AGENT_DESCRIPTOR *descriptor)
{
    /* Create an in-memory socket pair:
     *   sv[0] = fuzz_fd  (fuzzer reads/writes)
     *   sv[1] = put_fd   (libssh session I/O)
     */
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
    {
        _log(PUFFIN.error, "libssh create: socketpair() failed: %s", strerror(errno));
        return NULL;
    }

    int fuzz_fd = sv[0];
    int put_fd = sv[1];

    if (set_nonblocking(fuzz_fd) < 0 || set_nonblocking(put_fd) < 0)
    {
        _log(PUFFIN.error, "libssh create: set_nonblocking() failed: %s", strerror(errno));
        close(fuzz_fd);
        close(put_fd);
        return NULL;
    }

    ssh_session session = ssh_new();
    if (!session)
    {
        _log(PUFFIN.error, "libssh create: ssh_new() failed");
        close(fuzz_fd);
        close(put_fd);
        return NULL;
    }

    /* Disable config-file loading (the option was added in libssh 0.9; older
       versions like 0.8.x don't load a system config here anyway). */
#if defined(LIBSSH_VERSION_INT) && defined(SSH_VERSION_INT)
#if LIBSSH_VERSION_INT >= SSH_VERSION_INT(0, 9, 0)
    {
        int zero = 0;
        ssh_options_set(session, SSH_OPTIONS_PROCESS_CONFIG, &zero);
    }
#endif
#endif
    /* Non-blocking mode */
    ssh_set_blocking(session, 0);

    ssh_bind bind = NULL;

    if (descriptor->role == SSH_SERVER)
    {
        bind = ssh_bind_new();
        if (!bind)
        {
            _log(PUFFIN.error, "libssh create: ssh_bind_new() failed");
            ssh_free(session);
            close(fuzz_fd);
            close(put_fd);
            return NULL;
        }

        /* Uniformise advertised algorithms (differential fuzzing). NULL = keep
         * libssh defaults. Restricting the server's offered sets makes its
         * KEXINIT match the other PUT's so static capability no longer diffs.
         * The algorithm bind options were introduced in libssh 0.9; older
         * vendored builds (0.8.x) keep their defaults — they are not used in the
         * differential (which runs libssh 0.11.4 vs wolfSSH). */
#if defined(LIBSSH_VERSION_INT) && LIBSSH_VERSION_INT >= SSH_VERSION_INT(0, 9, 0)
        if (descriptor->kex)
            ssh_bind_options_set(bind, SSH_BIND_OPTIONS_KEY_EXCHANGE, descriptor->kex);
        if (descriptor->ciphers)
        {
            ssh_bind_options_set(bind, SSH_BIND_OPTIONS_CIPHERS_C_S, descriptor->ciphers);
            ssh_bind_options_set(bind, SSH_BIND_OPTIONS_CIPHERS_S_C, descriptor->ciphers);
        }
        if (descriptor->macs)
        {
            ssh_bind_options_set(bind, SSH_BIND_OPTIONS_HMAC_C_S, descriptor->macs);
            ssh_bind_options_set(bind, SSH_BIND_OPTIONS_HMAC_S_C, descriptor->macs);
        }
        if (descriptor->hostkey_algos)
            ssh_bind_options_set(bind,
                                 SSH_BIND_OPTIONS_HOSTKEY_ALGORITHMS,
                                 descriptor->hostkey_algos);
        /* server-sig-algs advertised in EXT_INFO (RFC 8308): libssh builds it from
           the accepted publickey types, defaulting to its FULL supported set. Pin
           it so it matches wolfSSH's advertisement (see the descriptor field). */
        if (descriptor->server_sig_algs)
            ssh_bind_options_set(bind,
                                 SSH_BIND_OPTIONS_PUBKEY_ACCEPTED_KEY_TYPES,
                                 descriptor->server_sig_algs);
#endif

        /* Import the embedded RSA host key */
        ssh_key host_key = NULL;
        if (ssh_pki_import_privkey_base64(SERVER_HOST_KEY, NULL, NULL, NULL, &host_key) != SSH_OK)
        {
            _log(PUFFIN.error, "libssh create: failed to import host key");
            ssh_bind_free(bind);
            ssh_free(session);
            close(fuzz_fd);
            close(put_fd);
            return NULL;
        }

        ssh_bind_options_set(bind, SSH_BIND_OPTIONS_IMPORT_KEY, host_key);
        /* Do not free host_key here: libssh's bind import-key path keeps ownership/reference. */
        ssh_bind_set_blocking(bind, 0);

        /* Associate the session with put_fd (server side) */
        if (ssh_bind_accept_fd(bind, session, put_fd) != SSH_OK)
        {
            _log(PUFFIN.error,
                 "libssh create: ssh_bind_accept_fd() failed (session=%s bind=%s)",
                 ssh_get_error(session),
                 ssh_get_error(bind));
            ssh_bind_free(bind);
            ssh_free(session);
            close(fuzz_fd);
            close(put_fd);
            return NULL;
        }
        /* put_fd is now owned by the session */
    }
    else /* SSH_CLIENT */
    {
        /* A dummy hostname is required; the actual connection uses put_fd */
        ssh_options_set(session, SSH_OPTIONS_HOST, "puffin-dummy");
        ssh_options_set(session, SSH_OPTIONS_FD, &put_fd);
        /* Pre-set user and ssh_dir to avoid ssh_options_apply failures in
         * restricted environments. */
        const char *user = getenv("USER");
        if (user == NULL)
            user = "puffin";
        ssh_options_set(session, SSH_OPTIONS_USER, user);
        const char *home = getenv("HOME");
        char sshdir[4096];
        if (home != NULL)
        {
            snprintf(sshdir, sizeof(sshdir), "%s/.ssh", home);
        }
        else
        {
            snprintf(sshdir, sizeof(sshdir), "/tmp/.ssh-puffin");
        }
        ssh_options_set(session, SSH_OPTIONS_SSH_DIR, sshdir);
        /* put_fd is now owned by the session */
    }

    AGENT agent = calloc(1, sizeof(struct AGENT_TYPE));
    if (!agent)
    {
        _log(PUFFIN.error, "libssh create: malloc failed");
        ssh_bind_free(bind);
        ssh_free(session);
        close(fuzz_fd);
        return NULL;
    }

    agent->name = descriptor->name;
    agent->descriptor = *descriptor;
    agent->fuzz_fd = fuzz_fd;
    agent->put_fd = put_fd;
    agent->session = session;
    agent->bind = bind;
    agent->state = PUT_STATE_KEX;
    agent->last_emitted_phase = -1;
    snprintf(agent->state_desc, sizeof(agent->state_desc), "KEX");

    return agent;
}

/* ── destroy ─────────────────────────────────────────────────────────────── */

static void libssh_destroy(AGENT agent)
{
    if (!agent)
        return;

    close(agent->fuzz_fd);

    /* Remove the session from the event before freeing either. The channel is
     * owned by the session and freed by ssh_free below. */
    if (agent->event)
    {
        ssh_event_remove_session(agent->event, agent->session);
        ssh_event_free(agent->event);
    }

    if (agent->bind)
        ssh_bind_free(agent->bind);

    ssh_disconnect(agent->session);
    ssh_free(agent->session);

    /* ssh_free() closes put_fd in most cases, but not when the session
       errored before its socket layer was fully initialised (e.g. early
       failure in attacker seeds).  We check with fcntl whether the fd is
       still open before closing to avoid a double-close race. */
    if (fcntl(agent->put_fd, F_GETFD) != -1)
        close(agent->put_fd);

    free(agent);
}

/* ── progress ────────────────────────────────────────────────────────────── */

/* ── claim emission ──────────────────────────────────────────────────────── */

#ifdef HAS_CLAIMS
/* Copy a libssh getter string (may be NULL) into a fixed-size claim buffer. */
static void claim_set(char *dst, const char *src)
{
    if (src == NULL)
        src = "";
    snprintf(dst, SSH_CLAIM_STR_LEN, "%s", src);
}
#endif /* HAS_CLAIMS */

/* ── High-level server callbacks ─────────────────────────────────────────────
 *
 * These let libssh's own state machine own auth / service / channel handling.
 * userdata is the AGENT. libssh verifies publickey signatures and enforces
 * message ordering itself before invoking these, so the harness only makes the
 * authorization decision and records the belief for the claim.
 */

static int cb_auth_pubkey(ssh_session session,
                          const char *user,
                          struct ssh_key_struct *pubkey,
                          char sig_state,
                          void *userdata)
{
    (void)session;
    AGENT agent = (AGENT)userdata;

    /* Probe (no signature yet): tell libssh the key is acceptable so it replies
     * SSH_MSG_USERAUTH_PK_OK and the client sends the signed request. */
    if (sig_state == SSH_PUBLICKEY_STATE_NONE)
        return SSH_AUTH_SUCCESS;
    if (sig_state != SSH_PUBLICKEY_STATE_VALID)
        return SSH_AUTH_DENIED;

    /* libssh cryptographically verified the signature. Compute the key
     * fingerprint and enforce the shared (user, key) allow-list: a valid
     * signature is necessary but not sufficient — the key must be authorized
     * FOR THIS USER. This rejects unauthorized key C and any cross-identity
     * pairing (e.g. user "user" presenting key B), which is the credential-
     * confusion boundary a differential run can compare against wolfSSH. */
    unsigned char *hash = NULL;
    size_t hlen = 0;
    uint8_t fp[32];
    size_t fp_len = 0;
    if (pubkey != NULL &&
        ssh_get_publickey_hash(pubkey, SSH_PUBLICKEY_HASH_SHA256, &hash, &hlen) == 0)
    {
        fp_len = hlen > sizeof(fp) ? sizeof(fp) : hlen;
        memcpy(fp, hash, fp_len);
        ssh_clean_pubkey_hash(&hash);
    }

    if (!ssh_creds_key_authorized(user, fp, fp_len))
        return SSH_AUTH_DENIED;

    /* Authorized: record the belief (kept for the claim path). */
    memcpy(agent->auth_key_fp, fp, fp_len);
    agent->auth_key_fp_len = (uint8_t)fp_len;
    snprintf(agent->auth_method, sizeof(agent->auth_method), "publickey");
    snprintf(agent->auth_user, sizeof(agent->auth_user), "%s", user ? user : "");
    agent->authenticated = true;
    return SSH_AUTH_SUCCESS;
}

static int
cb_auth_password(ssh_session session, const char *user, const char *password, void *userdata)
{
    (void)session;
    AGENT agent = (AGENT)userdata;
    /* Enforce the shared (user, password) allow-list, mirroring wolfSSH. */
    size_t pw_len = password ? strlen(password) : 0;
    if (!ssh_creds_password_authorized(user, (const uint8_t *)password, pw_len))
        return SSH_AUTH_DENIED;

    snprintf(agent->auth_method, sizeof(agent->auth_method), "password");
    snprintf(agent->auth_user, sizeof(agent->auth_user), "%s", user ? user : "");
    agent->auth_key_fp_len = 0;
    agent->authenticated = true;
    return SSH_AUTH_SUCCESS;
}

static int cb_service_request(ssh_session session, const char *service, void *userdata)
{
    (void)session;
    (void)service;
    (void)userdata;
    return 0; /* accept the service request */
}

static int
cb_channel_exec(ssh_session session, ssh_channel channel, const char *command, void *userdata)
{
    (void)session;
    (void)channel;
    (void)command;
    (void)userdata;
    return SSH_OK; /* accept → libssh sends CHANNEL_SUCCESS if want_reply */
}

static int cb_channel_shell(ssh_session session, ssh_channel channel, void *userdata)
{
    (void)session;
    (void)channel;
    (void)userdata;
    return SSH_OK;
}

/* Channel connection-protocol callbacks — make libssh drive channel data / eof /
 * close symmetrically with wolfSSH's worker, so the differential can compare the
 * whole channel flow (not just setup). Without these the harness never consumed
 * channel data (libssh's window never shrank -> no WINDOW_ADJUST), never sent
 * EOF, and never answered the peer's CLOSE — a harness asymmetry (concern 9). */
static int cb_channel_data(ssh_session session,
                           ssh_channel channel,
                           void *data,
                           uint32_t len,
                           int is_stderr,
                           void *userdata)
{
    (void)session;
    (void)channel;
    (void)data;
    (void)is_stderr;
    (void)userdata;
    /* Consume all received data: returning the full length tells libssh the
     * payload was read, so it reopens the local window and emits
     * SSH_MSG_CHANNEL_WINDOW_ADJUST (as wolfSSH does). */
    return (int)len;
}

static void cb_channel_eof(ssh_session session, ssh_channel channel, void *userdata)
{
    (void)session;
    (void)userdata;
    ssh_channel_send_eof(channel); /* answer the peer's EOF with our own */
}

static void cb_channel_close(ssh_session session, ssh_channel channel, void *userdata)
{
    (void)session;
    (void)userdata;
    ssh_channel_close(channel); /* answer the peer's CLOSE (bidirectional close) */
}

static ssh_channel cb_channel_open(ssh_session session, void *userdata)
{
    AGENT agent = (AGENT)userdata;
    if (agent->channel != NULL)
        return NULL; /* one session channel is enough */
    agent->channel = ssh_channel_new(session);
    if (agent->channel == NULL)
        return NULL;
    ssh_callbacks_init(&agent->channel_cb);
    agent->channel_cb.userdata = agent;
    agent->channel_cb.channel_exec_request_function = cb_channel_exec;
    agent->channel_cb.channel_shell_request_function = cb_channel_shell;
    agent->channel_cb.channel_data_function = cb_channel_data;
    agent->channel_cb.channel_eof_function = cb_channel_eof;
    agent->channel_cb.channel_close_function = cb_channel_close;
    ssh_set_channel_callbacks(agent->channel, &agent->channel_cb);
    return agent->channel;
}

#ifdef HAS_CLAIMS
/*
 * Build a HandshakeComplete claim from the session's negotiated parameters and
 * hand it to the registered callback. Fires at most once per agent (guarded by
 * <claim_emitted>); a no-op when no claimer is registered.
 */
static void emit_handshake_claim(AGENT agent)
{
    if (agent->claimer == NULL || agent->claim_emitted)
        return;

    Claim claim;
    memset(&claim, 0, sizeof(claim));
    claim_set(claim.kex, ssh_get_kex_algo(agent->session));
    claim_set(claim.cipher_in, ssh_get_cipher_in(agent->session));
    claim_set(claim.cipher_out, ssh_get_cipher_out(agent->session));
    claim_set(claim.hmac_in, ssh_get_hmac_in(agent->session));
    claim_set(claim.hmac_out, ssh_get_hmac_out(agent->session));
    claim_set(claim.auth_method, agent->auth_method);
    claim_set(claim.auth_user, agent->auth_user);
    if (agent->auth_key_fp_len > 0)
    {
        memcpy(claim.auth_key_fp, agent->auth_key_fp, agent->auth_key_fp_len);
        claim.auth_key_fp_len = agent->auth_key_fp_len;
    }

    /* KEX-transcript binding: the SSH session id (exchange hash H). */
    const unsigned char *sid = NULL;
    size_t sid_len = 0;
    if (puffin_ssh_get_session_id != NULL &&
        puffin_ssh_get_session_id(agent->session, &sid, &sid_len) == 0 && sid != NULL)
    {
        if (sid_len > sizeof(claim.session_id))
            sid_len = sizeof(claim.session_id);
        memcpy(claim.session_id, sid, sid_len);
        claim.session_id_len = (uint8_t)sid_len;
    }
    /* Channel-data integrity: per-direction secure-channel message-type digest. */
    if (puffin_ssh_get_secure_tx_digest != NULL)
        claim.secure_tx_digest = puffin_ssh_get_secure_tx_digest(agent->session);
    if (puffin_ssh_get_secure_rx_digest != NULL)
        claim.secure_rx_digest = puffin_ssh_get_secure_rx_digest(agent->session);
    if (puffin_ssh_get_rx_count != NULL)
        claim.rx_count = puffin_ssh_get_rx_count(agent->session);
    if (puffin_ssh_get_tx_count != NULL)
        claim.tx_count = puffin_ssh_get_tx_count(agent->session);
    claim.phase = 3; /* PHASE_DONE: completed handshake (the security oracle only reads these) */

    agent->claimer->notify(agent->claimer->context, &claim);
    agent->claim_emitted = true;
}

/*
 * Emit a lightweight *intermediate* phase claim (phase 1=KEX, 2=AUTH) for the
 * claim-coverage liveness-depth signal — including from runs that abort before
 * completing. Deduplicated per agent (only on phase advance), and never emits
 * the completion phase (3), which is owned by emit_handshake_claim. Carries the
 * coverage-relevant state known so far (negotiated algorithms once available,
 * the secure-channel digests); the security oracle ignores phase<3 claims.
 */
static void emit_phase_claim(AGENT agent)
{
    if (agent->claimer == NULL)
        return;

    /* Read the session id (exchange hash H) up front: its availability — NOT the
       harness `state` variable — is what determines whether we can emit the
       H-bearing (phase-2) claim. libssh computes current_crypto->session_id when
       KEX finalises (at NEWKEYS), which can be one or more progress ticks BEFORE
       the harness flips state to AUTH (that only happens once the first
       post-NEWKEYS packet is read). A trace that aborts in that window (e.g. a
       malformed first encrypted packet) would otherwise leave libssh with NO
       H-claim while wolfSSH — which emits as soon as ssh->sessionId is set — has
       one, manufacturing a spurious "one PUT has a transcript, the other ()"
       differential. Gating phase on session-id availability makes the two
       harnesses emit the H-claim at the SAME protocol point (post-NEWKEYS). */
    const unsigned char *sid = NULL;
    size_t sid_len = 0;
    bool have_sid = (puffin_ssh_get_session_id != NULL &&
                     puffin_ssh_get_session_id(agent->session, &sid, &sid_len) == 0 &&
                     sid != NULL);

    int phase;
    switch (agent->state)
    {
    case PUT_STATE_KEX:
        /* Once H exists, this is really the post-KEX (phase-2) point even though
           the harness state has not advanced to AUTH yet. */
        phase = have_sid ? 2 : 1;
        break;
    case PUT_STATE_AUTH:
        phase = 2;
        break;
    default:
        return; /* DONE/ERROR: depth already captured by KEX/AUTH claims or completion */
    }
    if (phase <= agent->last_emitted_phase)
        return;

    Claim claim;
    memset(&claim, 0, sizeof(claim));
    claim_set(claim.kex, ssh_get_kex_algo(agent->session));
    claim_set(claim.cipher_in, ssh_get_cipher_in(agent->session));
    claim_set(claim.cipher_out, ssh_get_cipher_out(agent->session));
    claim_set(claim.hmac_in, ssh_get_hmac_in(agent->session));
    claim_set(claim.hmac_out, ssh_get_hmac_out(agent->session));
    if (puffin_ssh_get_secure_tx_digest != NULL)
        claim.secure_tx_digest = puffin_ssh_get_secure_tx_digest(agent->session);
    if (puffin_ssh_get_secure_rx_digest != NULL)
        claim.secure_rx_digest = puffin_ssh_get_secure_rx_digest(agent->session);
    if (puffin_ssh_get_rx_count != NULL)
        claim.rx_count = puffin_ssh_get_rx_count(agent->session);
    if (puffin_ssh_get_tx_count != NULL)
        claim.tx_count = puffin_ssh_get_tx_count(agent->session);
    /* KEX-transcript binding: carry H whenever it is available (see above). The
       Rust side keeps only claims carrying a session id, so a phase-1/no-sid
       claim is harmless (dropped). */
    if (have_sid)
    {
        if (sid_len > sizeof(claim.session_id))
            sid_len = sizeof(claim.session_id);
        memcpy(claim.session_id, sid, sid_len);
        claim.session_id_len = (uint8_t)sid_len;
    }
    claim.phase = (uint8_t)phase;

    agent->claimer->notify(agent->claimer->context, &claim);
    agent->last_emitted_phase = phase;
}
#else  /* !HAS_CLAIMS */
/* No claim instrumentation in this libssh build: claim emission compiles out to
 * no-ops so call sites need no guarding and the differential harness stays
 * minimal. Protocol behaviour is unaffected — state transitions live in the
 * caller, not here. */
static void emit_handshake_claim(AGENT agent)
{
    (void)agent;
}
static void emit_phase_claim(AGENT agent)
{
    (void)agent;
}
#endif /* HAS_CLAIMS */

static RESULT libssh_progress(AGENT agent)
{
    /* Record liveness depth for claim-coverage (incl. runs that later abort). */
    emit_phase_claim(agent);

    if (agent->state == PUT_STATE_ERROR)
        return error_result("agent is in error state");

    if (agent->state == PUT_STATE_DONE)
    {
        /* Post-auth: keep dispatching the event loop so libssh handles any
         * further channel traffic (open, exec/shell requests, data) itself. */
        if (agent->descriptor.role == SSH_SERVER && agent->event != NULL)
        {
            for (int i = 0; i < 16; ++i)
            {
                int rc = ssh_event_dopoll(agent->event, 0);
                if (rc == SSH_ERROR || rc == SSH_AGAIN)
                    break;
            }
        }
        return ok_result();
    }

    if (agent->descriptor.role == SSH_SERVER)
    {
        if (agent->state == PUT_STATE_KEX)
        {
            for (int i = 0; i < 8; ++i)
            {
                int rc = ssh_handle_key_exchange(agent->session);
                if (rc == SSH_AGAIN)
                {
                    snprintf(agent->state_desc, sizeof(agent->state_desc), "KEX/SSH_AGAIN");
                    continue;
                }
                if (rc != SSH_OK)
                {
                    snprintf(agent->state_desc, sizeof(agent->state_desc), "KEX/ERROR");
                    agent->state = PUT_STATE_ERROR;
                    return error_result(ssh_get_error(agent->session));
                }
                agent->state = PUT_STATE_AUTH;
                snprintf(agent->state_desc, sizeof(agent->state_desc), "AUTH");
                break;
            }
            if (agent->state == PUT_STATE_KEX)
                return ok_result();
        }

        /* Register the high-level server callbacks once, right after KEX. From
         * here libssh's own state machine drives auth (publickey/password),
         * service requests, channel open, and channel requests — including
         * sending USERAUTH_PK_OK/FAILURE/SUCCESS and CHANNEL_SUCCESS/FAILURE per
         * RFC 4252/4254 — instead of the harness re-implementing it. This keeps
         * the harness thin and its behaviour close to a real libssh server (and
         * symmetric with the wolfSSH harness, which delegates to wolfSSH_accept). */
        if (!agent->callbacks_ready)
        {
            ssh_callbacks_init(&agent->server_cb);
            agent->server_cb.userdata = agent;
            agent->server_cb.auth_pubkey_function = cb_auth_pubkey;
            agent->server_cb.auth_password_function = cb_auth_password;
            agent->server_cb.service_request_function = cb_service_request;
            agent->server_cb.channel_open_request_session_function = cb_channel_open;
            ssh_set_server_callbacks(agent->session, &agent->server_cb);
            ssh_set_auth_methods(agent->session,
                                 SSH_AUTH_METHOD_PUBLICKEY | SSH_AUTH_METHOD_PASSWORD);
            agent->event = ssh_event_new();
            if (agent->event == NULL)
            {
                agent->state = PUT_STATE_ERROR;
                return error_result("ssh_event_new failed");
            }
            ssh_event_add_session(agent->event, agent->session);
            agent->callbacks_ready = true;
        }

        /* Dispatch pending callbacks non-blocking (timeout 0). Each dopoll
         * processes whatever input the fuzzer already delivered and lets libssh
         * emit its replies; SSH_AGAIN means no more data is ready right now. */
        for (int i = 0; i < 16; ++i)
        {
            int rc = ssh_event_dopoll(agent->event, 0);
            if (rc == SSH_ERROR)
            {
                if (ssh_get_status(agent->session) & (SSH_CLOSED | SSH_CLOSED_ERROR))
                {
                    agent->state = PUT_STATE_ERROR;
                    snprintf(agent->state_desc,
                             sizeof(agent->state_desc),
                             "SESSION_ERROR: %s",
                             ssh_get_error(agent->session));
                    return error_result(agent->state_desc);
                }
                break;
            }
            if (rc == SSH_AGAIN)
                break;
        }

        if (agent->authenticated && !agent->claim_emitted)
        {
            agent->state = PUT_STATE_DONE;
            snprintf(agent->state_desc, sizeof(agent->state_desc), "DONE");
            emit_handshake_claim(agent);
        }
    }
    else /* SSH_CLIENT */
    {
        if (agent->state == PUT_STATE_KEX)
        {
            for (int i = 0; i < 8; ++i)
            {
                int rc = ssh_connect(agent->session);
                if (rc == SSH_AGAIN)
                {
                    snprintf(agent->state_desc, sizeof(agent->state_desc), "KEX/SSH_AGAIN");
                    continue;
                }
                if (rc != SSH_OK)
                {
                    snprintf(agent->state_desc, sizeof(agent->state_desc), "KEX/ERROR");
                    agent->state = PUT_STATE_ERROR;
                    return error_result(ssh_get_error(agent->session));
                }
                agent->state = PUT_STATE_AUTH;
                snprintf(agent->state_desc, sizeof(agent->state_desc), "AUTH");
                break;
            }
            if (agent->state == PUT_STATE_KEX)
                return ok_result();
        }

        if (agent->state == PUT_STATE_AUTH)
        {
            for (int i = 0; i < 4; ++i)
            {
                int rc = ssh_userauth_password(agent->session, NULL, "test");
                if (rc == SSH_AUTH_AGAIN)
                {
                    continue;
                }
                if (rc == SSH_AUTH_SUCCESS)
                {
                    agent->state = PUT_STATE_DONE;
                    snprintf(agent->state_desc, sizeof(agent->state_desc), "DONE");
                    emit_handshake_claim(agent);
                    return ok_result();
                }
                if (rc == SSH_AUTH_DENIED || rc == SSH_AUTH_PARTIAL)
                {
                    snprintf(agent->state_desc, sizeof(agent->state_desc), "AUTH_DENIED");
                    return ok_result();
                }
                agent->state = PUT_STATE_ERROR;
                snprintf(agent->state_desc, sizeof(agent->state_desc), "AUTH_ERROR");
                return error_result(ssh_get_error(agent->session));
            }
        }
    }

    return ok_result();
}

/* ── reset ───────────────────────────────────────────────────────────────── */

static RESULT libssh_reset(AGENT agent, uint8_t new_name, uint8_t use_clear)
{
    (void)use_clear;
    /* Full session reset is not supported for SSH; puffin should recreate the agent. */
    agent->name = new_name;
    return error_result("reset not supported for libssh harness");
}

/* ── describe_state ──────────────────────────────────────────────────────── */

static const char *libssh_describe_state(AGENT agent)
{
    return agent->state_desc;
}

/* ── is_state_successful ─────────────────────────────────────────────────── */

static bool libssh_is_successful(AGENT agent)
{
    return agent->state == PUT_STATE_DONE;
}

/* ── register_claimer ────────────────────────────────────────────────────── */

static void libssh_register_claimer(AGENT agent, const CLAIMER_CB *claimer)
{
    /* Store the callback; ownership of the CB (and its context) stays with the
     * caller, which must keep it alive for the agent's lifetime and free it
     * via the CB's own destroy hook. */
    agent->claimer = claimer;
}

/* ── add_inbound ─────────────────────────────────────────────────────────── */

static RESULT libssh_add_inbound(AGENT agent, const uint8_t *bytes, size_t length, size_t *written)
{
    if (length == 0)
    {
        *written = 0;
        return ok_result();
    }

    ssize_t n = send(agent->fuzz_fd, bytes, length, MSG_DONTWAIT);
    if (n < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            *written = 0;
            return would_block_result("send: EAGAIN");
        }
        *written = 0;
        return error_result(strerror(errno));
    }

    *written = (size_t)n;
    return ok_result();
}

/* ── take_outbound ───────────────────────────────────────────────────────── */

static RESULT
libssh_take_outbound(AGENT agent, uint8_t *bytes, size_t max_length, size_t *readbytes)
{
    if (max_length == 0)
    {
        *readbytes = 0;
        return ok_result();
    }

    ssize_t n = recv(agent->fuzz_fd, bytes, max_length, MSG_DONTWAIT);
    if (n < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            *readbytes = 0;
            return would_block_result("recv: EAGAIN");
        }
        *readbytes = 0;
        return error_result(strerror(errno));
    }

    *readbytes = (size_t)n;
    return ok_result();
}
