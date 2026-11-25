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
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "bindings.h"
#include "rng.h"
#include <puffin/ssh_authorized_creds.h>

/*
 * Claim instrumentation (HAS_CLAIMS).
 *
 * Everything guarded by HAS_CLAIMS below builds the claim that a differential
 * compares between PUTs and reads the session id from. It is compiled ONLY when the vendored libssh
 * carries the PUFFIN claim-instrumentation patch
 * (puffin-build/vendors/libssh/instrument_claims.cmake) — the build sets -DHAS_CLAIMS iff the
 * library exposes those hooks (see puffin-build harness wrap()). When it is absent (a plain
 * vendored libssh, or the differential fuzzing setup that does not register a claimer), this code
 * compiles out to no-ops, keeping the harness minimal and symmetric with the wolfSSH harness — i.e.
 * a thin driver that only makes authorization decisions and lets libssh own the protocol. It never
 * affects the protocol path (state transitions live outside these functions), only whether a claim
 * is emitted.
 *
 * The hooks below expose the session id (exchange hash H) and the secrets of the key exchange
 * behind the outbound keys; they are not in any public libssh header. Both are weak: a vendor
 * patched by an older instrumentation has the first only, and the claims then carry no
 * key-exchange secrets (the differential decrypts the first epoch only).
 */
#ifdef HAS_CLAIMS
extern int puffin_ssh_get_session_id(ssh_session session, const unsigned char **out, size_t *len)
    __attribute__((weak));
extern int puffin_ssh_get_kex_secret(ssh_session session,
                                     const unsigned char **h,
                                     size_t *h_len,
                                     unsigned char *k,
                                     size_t k_cap,
                                     size_t *k_len) __attribute__((weak));
#endif /* HAS_CLAIMS */

/* ── Embedded RSA host key (server only) ─────────────────────────────────── */

static const char *SERVER_HOST_KEY =
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "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\n"
    "-----END OPENSSH PRIVATE KEY-----\n";

/* ── Internal state ──────────────────────────────────────────────────────── */

typedef enum
{
    PUT_STATE_KEX,     /* key-exchange (or TCP connect) in progress */
    PUT_STATE_AUTH,    /* authentication in progress */
    PUT_STATE_CHANNEL, /* client only: authenticated, opening the session
                          channel + shell request (mirrors wolfSSH_connect) */
    PUT_STATE_DONE,    /* fully authenticated (client: channel set up too) */
    PUT_STATE_ERROR,   /* unrecoverable error */
} PutState;

/* Session-channel slots of the SERVER role (see cb_channel_open). */
#define LIBSSH_MAX_SERVER_CHANNELS 8

struct AGENT_TYPE
{
    uint8_t name;
    SSH_AGENT_DESCRIPTOR descriptor;

    int fuzz_fd;          /* puffin reads/writes here (socketpair end 0) */
    int put_fd;           /* libssh's end (socketpair end 1); kept so destroy() can
                             close it explicitly if ssh_free() leaves it open */
    struct stat put_stat; /* identifies that socket, see close_if_same_file() */

    ssh_session session;
    ssh_bind bind; /* server only; NULL for client */

    PutState state;
    char state_desc[256]; /* human-readable state for describe_state */

    /* Client-role progress flags (see the SSH_CLIENT branch of libssh_progress). */
    bool auth_none_done;     /* the "none" probe was refused; now use password */
    bool client_chan_opened; /* CHANNEL_OPEN confirmed; now send the shell request */

    const CLAIMER_CB *claimer; /* registered claim callback, or NULL */
    bool claim_emitted;        /* guard so the handshake claim fires once */
    int last_emitted_phase;    /* highest intermediate phase claim emitted (-1=none) */
    /* The secrets of each key exchange so far, recorded once the outbound keys switched to it
       (track_kex_secrets); every claim carries them. */
    SSH_KEX_SECRET kex_secrets[SSH_CLAIM_MAX_KEX];
    uint8_t kex_count;

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
    /* Session-level callbacks. `global_request_function` (tcpip-forward handling)
     * lives HERE in ssh_callbacks_struct, not in the server callbacks, in both
     * libssh 0.10.4 and 0.11.4 — so it is set via ssh_set_callbacks(). */
    struct ssh_callbacks_struct session_cb;
    struct ssh_channel_callbacks_struct channel_cb;
    ssh_event event;     /* event loop that dispatches the callbacks */
    ssh_channel channel; /* CLIENT role: the session channel it opened, or NULL */
    /* SERVER role: every session channel the peer opened, in slot order (NULL =
     * free slot). Owned by the session; freed in libssh_destroy. */
    ssh_channel server_channels[LIBSSH_MAX_SERVER_CHANNELS];
    bool authenticated;     /* set by the auth callback */
    bool session_requested; /* SERVER role: a shell/exec/subsystem request or channel data
                               arrived, when wolfSSH_accept() completes */
    bool service_refused;   /* a SERVICE_REQUEST other than ssh-userauth arrived */
    bool callbacks_ready;   /* server callbacks registered (before KEX) */
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
static void set_channel_callbacks(AGENT agent, ssh_channel channel);

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

/* Close <fd> if it still refers to the file <identity>. libssh closes the socket it was given,
 * except when the session failed before its socket layer was set up, so whether put_fd is still
 * open after ssh_free() is not known. Its number may by then belong to another file, opened by
 * another thread: only the device and inode tell them apart. */
static void close_if_same_file(int fd, const struct stat *identity)
{
    struct stat current;
    if (fstat(fd, &current) == 0 && current.st_dev == identity->st_dev &&
        current.st_ino == identity->st_ino)
        close(fd);
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

    struct stat put_stat;
    if (set_nonblocking(fuzz_fd) < 0 || set_nonblocking(put_fd) < 0 || fstat(put_fd, &put_stat) < 0)
    {
        _log(PUFFIN.error, "libssh create: socket setup failed: %s", strerror(errno));
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
            close_if_same_file(put_fd, &put_stat);
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
         * restricted environments. The user is a FIXED "user" — identity A of the
         * shared allow-list, the seeds' fn_username, and exactly what the wolfSSH
         * client harness sends (wolfSSH_SetUsername(ssh, "user")). It used to be
         * getenv("USER"), which made the client's USERAUTH_REQUEST depend on who
         * ran the fuzzer (non-reproducible traces) and showed up as a spurious
         * user-name diff against wolfSSH once the c2s transcript was compared. */
        ssh_options_set(session, SSH_OPTIONS_USER, "user");
        /* A directory that does not exist: the user's own ~/.ssh (keys, known_hosts) must not
         * influence a trace. */
        ssh_options_set(session, SSH_OPTIONS_SSH_DIR, "/nonexistent");
        /* Apply the SAME negotiable-algorithm pins the SSH_SERVER branch applies
         * via ssh_bind_options_set, so a CLIENT PUT honours
         * differential_fuzzing_uniformise_put_config too. The wolfSSH harness sets
         * them on the shared CTX for both roles; without this the libssh client
         * offered its full defaults (e.g. diffie-hellman-group18-sha512) and every
         * client-role differential showed a spurious KEXINIT capability diff —
         * surfaced once the c2s decryption recipe made the client stream
         * comparable. Same libssh >= 0.9 guard as the server branch. */
#if defined(LIBSSH_VERSION_INT) && LIBSSH_VERSION_INT >= SSH_VERSION_INT(0, 9, 0)
        if (descriptor->kex)
            ssh_options_set(session, SSH_OPTIONS_KEY_EXCHANGE, descriptor->kex);
        if (descriptor->ciphers)
        {
            ssh_options_set(session, SSH_OPTIONS_CIPHERS_C_S, descriptor->ciphers);
            ssh_options_set(session, SSH_OPTIONS_CIPHERS_S_C, descriptor->ciphers);
        }
        if (descriptor->macs)
        {
            ssh_options_set(session, SSH_OPTIONS_HMAC_C_S, descriptor->macs);
            ssh_options_set(session, SSH_OPTIONS_HMAC_S_C, descriptor->macs);
        }
        if (descriptor->hostkey_algos)
            ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, descriptor->hostkey_algos);
#endif
        /* put_fd is now owned by the session */
    }

    AGENT agent = calloc(1, sizeof(struct AGENT_TYPE));
    if (!agent)
    {
        _log(PUFFIN.error, "libssh create: malloc failed");
        ssh_bind_free(bind);
        ssh_free(session);
        close_if_same_file(put_fd, &put_stat);
        close(fuzz_fd);
        return NULL;
    }

    agent->name = descriptor->name;
    agent->descriptor = *descriptor;
    agent->fuzz_fd = fuzz_fd;
    agent->put_fd = put_fd;
    agent->put_stat = put_stat;
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

    /* Remove the session from the event before freeing either. Channels are
     * owned by the session; free the server's explicitly (ssh_channel_free
     * unlinks each from the session), the client's goes with ssh_free below.
     * Only while the session is connected: ssh_disconnect frees every channel of
     * the session, and libssh up to 0.10 calls it on its own when cb_service_request
     * refuses a service (any but ssh-userauth, also once a channel is open), so after
     * such a disconnect our pointers dangle and freeing them is a use-after-free.
     * ssh_free releases whatever is still listed. */
    bool connected = agent->session != NULL && ssh_is_connected(agent->session);
    for (int i = 0; i < LIBSSH_MAX_SERVER_CHANNELS; ++i)
    {
        if (agent->server_channels[i] != NULL)
        {
            if (connected)
                ssh_channel_free(agent->server_channels[i]);
            agent->server_channels[i] = NULL;
        }
    }
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
       failure in attacker seeds). */
    close_if_same_file(agent->put_fd, &agent->put_stat);

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

/* Record the secrets of the key exchange behind the outbound keys if they are new: the first key
 * exchange's, or a rekey's once this agent has sent its NEWKEYS. True when it recorded one. */
static bool record_kex_secret(AGENT agent)
{
    if (puffin_ssh_get_kex_secret == NULL || agent->kex_count >= SSH_CLAIM_MAX_KEX)
        return false;
    const unsigned char *h = NULL;
    size_t h_len = 0;
    size_t k_len = 0;
    unsigned char k[SSH_KEX_SECRET_MAX_K];
    if (puffin_ssh_get_kex_secret(agent->session, &h, &h_len, k, sizeof(k), &k_len) != 0 ||
        h == NULL || h_len == 0 || h_len > sizeof(agent->kex_secrets[0].h) || k_len == 0)
        return false;
    if (agent->kex_count > 0)
    {
        const SSH_KEX_SECRET *last = &agent->kex_secrets[agent->kex_count - 1];
        if (last->h_len == h_len && memcmp(last->h, h, h_len) == 0)
            return false; /* the key exchange already recorded */
    }
    SSH_KEX_SECRET *secret = &agent->kex_secrets[agent->kex_count++];
    memcpy(secret->h, h, h_len);
    secret->h_len = (uint8_t)h_len;
    memcpy(secret->k, k, k_len);
    secret->k_len = (uint16_t)k_len;
    return true;
}

/* Every claim carries the secrets of the key exchanges recorded so far. */
static void claim_set_kex_secrets(AGENT agent, Claim *claim)
{
    memcpy(claim->kex_secrets, agent->kex_secrets, sizeof(SSH_KEX_SECRET) * agent->kex_count);
    claim->kex_count = agent->kex_count;
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

    if (sig_state != SSH_PUBLICKEY_STATE_NONE && sig_state != SSH_PUBLICKEY_STATE_VALID)
        return SSH_AUTH_DENIED;

    /* Compute the key fingerprint and enforce the shared (user, key) allow-list:
     * a valid signature is necessary but not sufficient — the key must be
     * authorized FOR THIS USER. This rejects unauthorized key C and any cross-
     * identity pairing (e.g. user "user" presenting key B), which is the credential-
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

    /* A query about an authorized key: libssh replies SSH_MSG_USERAUTH_PK_OK and
     * the client sends the signed request. */
    if (sig_state == SSH_PUBLICKEY_STATE_NONE)
        return SSH_AUTH_SUCCESS;

    /* libssh verified the signature. Authorized: record the belief (kept for the
     * claim path). */
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
    AGENT agent = (AGENT)userdata;
    /* Only the authentication service, as wolfSSH. Otherwise libssh sends DISCONNECT and closes
     * the socket, without an error status: dispatch_server_events() ends the session. */
    if (service != NULL && strcmp(service, "ssh-userauth") == 0)
        return 0;
    agent->service_refused = true;
    return -1;
}

/* Global-request handler. Registering it makes libssh hand EVERY recognised global
 * request (tcpip-forward, cancel-tcpip-forward, keepalive@openssh.com,
 * no-more-sessions@openssh.com) to us and send NOTHING itself, so every path must
 * reply exactly as libssh does WITHOUT a callback — otherwise an unanswered
 * want_reply request is a harness-made divergence (wolfSSH does reply):
 *   - tcpip-forward: ACCEPT iff the (host,port) is on the shared forwarding
 *     allow-list (ssh_creds_forward_authorized) — the SAME boundary the wolfSSH
 *     FwdCb enforces — making a forward accept/reject asymmetry a real
 *     cross-vendor differential; else refuse (REQUEST_FAILURE if want_reply), as
 *     libssh's queued-message default does;
 *   - cancel-tcpip-forward: ACCEPT iff the (host,port) is on the same allow-list,
 *     the policy of the wolfSSH harness;
 *   - keepalive / no-more-sessions: REQUEST_SUCCESS if want_reply (libssh's inline
 *     default; no-more-sessions has no enum constant in 0.10.x, hence `default`).
 * Unknown request names never reach this callback (libssh refuses them itself).
 * (direct-tcpip is a CHANNEL open, handled via the message API, not here.) */
static void cb_global_request(ssh_session session, ssh_message message, void *userdata)
{
    (void)session;
    (void)userdata;
    if (ssh_message_type(message) != SSH_REQUEST_GLOBAL)
        return;
    switch (ssh_message_subtype(message))
    {
    case SSH_GLOBAL_REQUEST_TCPIP_FORWARD:
    {
        const char *addr = ssh_message_global_request_address(message);
        int port = ssh_message_global_request_port(message);
        /* libssh hands the wire's uint32 over as an int: only a real TCP port can be bound. */
        if (port >= 0 && port <= 65535 && ssh_creds_forward_authorized(addr, (uint32_t)port))
            ssh_message_global_request_reply_success(message, (uint16_t)port);
        else /* REQUEST_FAILURE iff want_reply */
            ssh_message_reply_default(message);
        break;
    }
    case SSH_GLOBAL_REQUEST_CANCEL_TCPIP_FORWARD:
    {
        const char *addr = ssh_message_global_request_address(message);
        int port = ssh_message_global_request_port(message);
        if (port >= 0 && port <= 65535 && ssh_creds_forward_authorized(addr, (uint32_t)port))
            ssh_message_global_request_reply_success(message, 0);
        else /* REQUEST_FAILURE iff want_reply */
            ssh_message_reply_default(message);
        break;
    }
    default:
        /* keepalive, no-more-sessions: success; a no-op unless want_reply. */
        ssh_message_global_request_reply_success(message, 0);
        break;
    }
}

/* Message callback — catches messages the server callbacks do NOT handle. libssh
 * dispatches server callbacks FIRST (ssh_message_queue): session channel-open,
 * auth, service etc. are handled there and never reach here, so this does not
 * disturb the existing (event-loop) seeds. It exists to accept an inbound
 * `direct-tcpip` channel open (which has no dedicated server-callback hook in the
 * 0.10.4/0.11.4 model), gated on the SAME forwarding allow-list as the wolfSSH
 * FwdCb so a direct-tcpip accept/reject is a real cross-vendor differential.
 * Return 0 = handled (we replied); 1 = not handled => libssh sends the default
 * failure. Accepted channels are owned by the session and freed by ssh_free(). */
static int cb_message(ssh_session session, ssh_message message, void *userdata)
{
    (void)session;
    AGENT agent = (AGENT)userdata;
    if (ssh_message_type(message) == SSH_REQUEST_CHANNEL_OPEN &&
        ssh_message_subtype(message) == SSH_CHANNEL_DIRECT_TCPIP)
    {
        const char *host = ssh_message_channel_request_open_destination(message);
        int port = ssh_message_channel_request_open_destination_port(message);
        if (port >= 0 && port <= 65535 && ssh_creds_forward_authorized(host, (uint32_t)port))
        {
            ssh_channel channel = ssh_message_channel_request_open_reply_accept(message);
            if (channel != NULL)
            {
                /* Accepted (CHANNEL_OPEN_CONFIRMATION sent): its data, EOF and close are
                 * answered like a session channel's. */
                set_channel_callbacks(agent, channel);
                return 0;
            }
        }
    }
    return 1; /* not handled => default failure (ADMINISTRATIVELY_PROHIBITED) */
}

static int
cb_channel_exec(ssh_session session, ssh_channel channel, const char *command, void *userdata)
{
    (void)session;
    (void)channel;
    (void)command;
    ((AGENT)userdata)->session_requested = true;
    return SSH_OK; /* accept → libssh sends CHANNEL_SUCCESS if want_reply */
}

static int cb_channel_shell(ssh_session session, ssh_channel channel, void *userdata)
{
    (void)session;
    (void)channel;
    ((AGENT)userdata)->session_requested = true;
    return SSH_OK;
}

/* A subsystem starts a session like shell and exec do; pty-req and env are granted without one.
 * Without these callbacks libssh refuses the three requests, which wolfSSH grants. */
static int cb_channel_subsystem(ssh_session session,
                                ssh_channel channel,
                                const char *subsystem,
                                void *userdata)
{
    (void)session;
    (void)channel;
    (void)subsystem;
    ((AGENT)userdata)->session_requested = true;
    return SSH_OK;
}

static int cb_channel_pty(ssh_session session,
                          ssh_channel channel,
                          const char *term,
                          int width,
                          int height,
                          int pxwidth,
                          int pxheight,
                          void *userdata)
{
    (void)session;
    (void)channel;
    (void)term;
    (void)width;
    (void)height;
    (void)pxwidth;
    (void)pxheight;
    (void)userdata;
    return SSH_OK;
}

static int cb_channel_env(ssh_session session,
                          ssh_channel channel,
                          const char *env_name,
                          const char *env_value,
                          void *userdata)
{
    (void)session;
    (void)channel;
    (void)env_name;
    (void)env_value;
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
    ((AGENT)userdata)->session_requested = true;
    /* Consume all received data: returning the full length tells libssh the
     * payload was read, so it reopens the local window and emits
     * SSH_MSG_CHANNEL_WINDOW_ADJUST (as wolfSSH does). */
    return len > INT_MAX ? INT_MAX : (int)len;
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

/* One callback table serves every channel: the callbacks receive the channel they fire for. */
static void set_channel_callbacks(AGENT agent, ssh_channel channel)
{
    ssh_callbacks_init(&agent->channel_cb);
    agent->channel_cb.userdata = agent;
    agent->channel_cb.channel_exec_request_function = cb_channel_exec;
    agent->channel_cb.channel_shell_request_function = cb_channel_shell;
    agent->channel_cb.channel_subsystem_request_function = cb_channel_subsystem;
    agent->channel_cb.channel_pty_request_function = cb_channel_pty;
    agent->channel_cb.channel_env_request_function = cb_channel_env;
    agent->channel_cb.channel_data_function = cb_channel_data;
    agent->channel_cb.channel_eof_function = cb_channel_eof;
    agent->channel_cb.channel_close_function = cb_channel_close;
    ssh_set_channel_callbacks(channel, &agent->channel_cb);
}

static ssh_channel cb_channel_open(ssh_session session, void *userdata)
{
    AGENT agent = (AGENT)userdata;
    /* Mirror wolfSSH's session-channel policy exactly (internal.c DoChannelOpen:
     * a session open is refused, ADMINISTRATIVELY_PROHIBITED, while one is already
     * in its channel list, and accepted again once that one is closed). libssh
     * itself has no such limit — it is the application's choice — so the harness
     * makes the SAME choice: one OPEN session channel at a time, any number over
     * the session's life. Refusing every later open (as this harness used to)
     * made "open, close, open again" diverge on a harness choice; accepting
     * concurrent opens would diverge the other way. */
    int free_slot = -1;
    for (int i = 0; i < LIBSSH_MAX_SERVER_CHANNELS; ++i)
    {
        ssh_channel c = agent->server_channels[i];
        if (c != NULL && !ssh_channel_is_closed(c))
            return NULL; /* a session channel is still open: refuse */
        if (free_slot < 0 && (c == NULL || ssh_channel_is_closed(c)))
            free_slot = i;
    }
    if (free_slot < 0)
        return NULL;
    if (agent->server_channels[free_slot] != NULL) /* recycle a closed channel */
        ssh_channel_free(agent->server_channels[free_slot]);

    ssh_channel channel = ssh_channel_new(session);
    agent->server_channels[free_slot] = channel;
    if (channel == NULL)
        return NULL;
    set_channel_callbacks(agent, channel);
    return channel;
}

#ifdef HAS_CLAIMS
static void emit_phase_claim(AGENT agent);

/*
 * Build a HandshakeComplete claim from the session's negotiated parameters and
 * hand it to the registered callback. Fires at most once per agent (guarded by
 * <claim_emitted>); a no-op when no claimer is registered.
 */
static void emit_handshake_claim(AGENT agent)
{
    if (agent->claimer == NULL || agent->claim_emitted)
        return;
    emit_phase_claim(agent); /* the post-KEX claim always comes first */

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
    /* This claim may come inside the step that switched the outbound keys (a client that sends
       the end of its key exchange and its authentication in one write): record their secrets
       first, track_kex_secrets has not run yet. */
    record_kex_secret(agent);
    claim_set_kex_secrets(agent, &claim);
    claim.phase = 3; /* PHASE_DONE: completed handshake */

    agent->claimer->notify(agent->claimer->context, &claim);
    agent->claim_emitted = true;
}

/*
 * The claim announcing a rekey, once this agent's outbound keys switched to it (its NEWKEYS sent):
 * the state of the last claim (the auth belief once authenticated) and the secrets of every key
 * exchange so far, so that the differential decrypts the agent's output after the rekey too.
 */
static void emit_rekey_claim(AGENT agent)
{
    Claim claim;
    memset(&claim, 0, sizeof(claim));
    claim_set(claim.kex, ssh_get_kex_algo(agent->session));
    claim_set(claim.cipher_in, ssh_get_cipher_in(agent->session));
    claim_set(claim.cipher_out, ssh_get_cipher_out(agent->session));
    claim_set(claim.hmac_in, ssh_get_hmac_in(agent->session));
    claim_set(claim.hmac_out, ssh_get_hmac_out(agent->session));
    if (agent->claim_emitted)
    {
        claim_set(claim.auth_method, agent->auth_method);
        claim_set(claim.auth_user, agent->auth_user);
        if (agent->auth_key_fp_len > 0)
        {
            memcpy(claim.auth_key_fp, agent->auth_key_fp, agent->auth_key_fp_len);
            claim.auth_key_fp_len = agent->auth_key_fp_len;
        }
    }
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
    claim_set_kex_secrets(agent, &claim);
    claim.phase = agent->claim_emitted ? 3 : 2;

    agent->claimer->notify(agent->claimer->context, &claim);
}

/*
 * Around each step, before its phase claims, and after each poll of the event loop: record the
 * secrets of the key exchange behind the outbound keys when they are new, so that every claim
 * carries those recorded so far (the claims also record them themselves). After each poll, so
 * that a step whose two rekeys come in different polls keeps the secrets of both. A poll handles
 * every complete packet of one read (up to 4 KiB): of two rekeys in one read, only the second's
 * are recorded. The first key exchange's travel in the post-KEX claim; a rekey's are announced by
 * a claim of their own, once the post-KEX claim exists, so that the decryption recipe, which reads
 * the agent's last claim, has them as soon as the outbound keys switch, also in a rekey that never
 * completes. That claim repeats the auth belief of the last one: the claim comparison, which
 * merges adjacent equal claims, does not see it.
 */
static void track_kex_secrets(AGENT agent)
{
    if (agent->claimer == NULL || !record_kex_secret(agent))
        return;
    if (agent->kex_count > 1 && agent->last_emitted_phase >= 2)
        emit_rekey_claim(agent);
}

/*
 * Emit a lightweight *intermediate* phase claim (phase 1=KEX, 2=AUTH) for the
 * claim-coverage liveness-depth signal — including from runs that abort before
 * completing. Deduplicated per agent (only on phase advance), and never emits
 * the completion phase (3), which is owned by emit_handshake_claim. Carries the
 * state known so far (negotiated algorithms once available, the session id).
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
                     puffin_ssh_get_session_id(agent->session, &sid, &sid_len) == 0 && sid != NULL);

    int phase;
    switch (agent->state)
    {
    case PUT_STATE_KEX:
    case PUT_STATE_ERROR: /* the step that completed KEX may also have failed */
        /* Once H exists, this is really the post-KEX (phase-2) point even though
           the harness state has not advanced to AUTH yet. */
        phase = have_sid ? 2 : 1;
        break;
    case PUT_STATE_AUTH:
        phase = 2;
        break;
    default:
        return; /* DONE: depth already captured by KEX/AUTH claims or completion */
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
    /* Inside a step too (from emit_handshake_claim): record the secrets first. */
    record_kex_secret(agent);
    claim_set_kex_secrets(agent, &claim);
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
static void track_kex_secrets(AGENT agent)
{
    (void)agent;
}
#endif /* HAS_CLAIMS */

/* Dispatch what the fuzzer delivered, non-blocking (timeout 0): each dopoll processes the
 * pending input and lets libssh emit its replies; SSH_AGAIN means nothing more is ready. Returns
 * false when the session ended in an error, recorded in the agent's state. */
static bool dispatch_server_events(AGENT agent)
{
    for (int i = 0; i < 16 && !agent->service_refused; ++i)
    {
        int rc = ssh_event_dopoll(agent->event, 0);
        track_kex_secrets(agent);
        /* Checked whatever dopoll returned: it reports success for a poll whose packet put the
         * session in its error state (e.g. a packet length over the limit). */
        if (ssh_get_status(agent->session) & (SSH_CLOSED | SSH_CLOSED_ERROR))
        {
            agent->state = PUT_STATE_ERROR;
            snprintf(agent->state_desc,
                     sizeof(agent->state_desc),
                     "SESSION_ERROR: %s",
                     ssh_get_error(agent->session));
            return false;
        }
        if (rc == SSH_ERROR || rc == SSH_AGAIN)
            break;
    }
    if (agent->service_refused)
    {
        agent->state = PUT_STATE_ERROR;
        snprintf(agent->state_desc, sizeof(agent->state_desc), "SESSION_ERROR: service refused");
        return false;
    }
    return true;
}

/* The client's counterpart, once its shell runs: handle what the server sends (channel data,
 * EOF, close, a rekey, a DISCONNECT), as the wolfSSH client does in wolfSSH_worker(), and read
 * the channel as an application does, which lets libssh re-open the window for what was read.
 * Returns false when the session ended in an error, recorded in the agent's state. */
static bool dispatch_client_events(AGENT agent)
{
    if (agent->event == NULL)
    {
        agent->event = ssh_event_new();
        if (agent->event == NULL)
        {
            agent->state = PUT_STATE_ERROR;
            snprintf(agent->state_desc, sizeof(agent->state_desc), "ssh_event_new failed");
            return false;
        }
        ssh_event_add_session(agent->event, agent->session);
    }
    char buf[4096];
    for (int i = 0; i < 16; ++i)
    {
        int rc = ssh_event_dopoll(agent->event, 0);
        track_kex_secrets(agent);
        for (int is_stderr = 0; is_stderr < 2; ++is_stderr)
        {
            while (agent->channel != NULL && ssh_channel_is_open(agent->channel) &&
                   ssh_channel_read_nonblocking(agent->channel, buf, sizeof(buf), is_stderr) > 0)
            {
            }
        }
        if (ssh_get_status(agent->session) & (SSH_CLOSED | SSH_CLOSED_ERROR))
        {
            agent->state = PUT_STATE_ERROR;
            snprintf(agent->state_desc,
                     sizeof(agent->state_desc),
                     "SESSION_ERROR: %s",
                     ssh_get_error(agent->session));
            return false;
        }
        if (rc == SSH_ERROR || rc == SSH_AGAIN)
            break;
    }
    return true;
}

static RESULT libssh_step(AGENT agent);

static RESULT libssh_progress(AGENT agent)
{
    /* Record liveness depth for claim-coverage (incl. runs that later abort), after the step
     * too: KEX may complete on the last progress of a trace. The key-exchange secrets first, so
     * that the phase claims carry them. */
    track_kex_secrets(agent);
    emit_phase_claim(agent);
    RESULT result = libssh_step(agent);
    track_kex_secrets(agent);
    emit_phase_claim(agent);
    return result;
}

static RESULT libssh_step(AGENT agent)
{
    if (agent->state == PUT_STATE_ERROR)
        return error_result("agent is in error state");

    if (agent->state == PUT_STATE_DONE)
    {
        /* Past the handshake: keep handling the peer's traffic, as libssh's event loop does
         * for an application (the server: channel opens, requests, data; the client: what its
         * channel receives, a rekey, a DISCONNECT). */
        bool alive = agent->descriptor.role == SSH_SERVER
                         ? (agent->event == NULL || dispatch_server_events(agent))
                         : dispatch_client_events(agent);
        return alive ? ok_result() : error_result(agent->state_desc);
    }

    if (agent->descriptor.role == SSH_SERVER)
    {
        /* Register the high-level server callbacks once, BEFORE the key
         * exchange (as libssh's samplesshd-cb does). From here libssh's own state
         * machine drives auth (publickey/password), service requests, channel
         * open, and channel requests — including sending USERAUTH_PK_OK/FAILURE/
         * SUCCESS and CHANNEL_SUCCESS/FAILURE per RFC 4252/4254 — instead of the
         * harness re-implementing it. This keeps the harness thin and its
         * behaviour close to a real libssh server (and symmetric with the wolfSSH
         * harness, which delegates to wolfSSH_accept).
         * They must exist before ssh_handle_key_exchange: a peer may send its
         * SERVICE_REQUEST in the same write as its NEWKEYS (wolfSSH and libssh
         * clients both do), and libssh then dispatches it from inside the key
         * exchange. Registered only afterwards (as this harness used to), that
         * request was parked with no callback and never answered — the session
         * stalled on libssh while wolfSSH replied: a harness-made divergence. */
        if (!agent->callbacks_ready)
        {
            ssh_callbacks_init(&agent->server_cb);
            agent->server_cb.userdata = agent;
            agent->server_cb.auth_pubkey_function = cb_auth_pubkey;
            agent->server_cb.auth_password_function = cb_auth_password;
            agent->server_cb.service_request_function = cb_service_request;
            agent->server_cb.channel_open_request_session_function = cb_channel_open;
            ssh_set_server_callbacks(agent->session, &agent->server_cb);
            /* global_request_function (tcpip-forward) is a SESSION callback. */
            ssh_callbacks_init(&agent->session_cb);
            agent->session_cb.userdata = agent;
            agent->session_cb.global_request_function = cb_global_request;
            ssh_set_callbacks(agent->session, &agent->session_cb);
            /* Fallback for messages the server callbacks don't handle (direct-tcpip
             * channel open). Server callbacks run first, so existing seeds are
             * unaffected; this only catches the fall-through. */
            ssh_set_message_callback(agent->session, cb_message, agent);
            ssh_set_auth_methods(agent->session,
                                 SSH_AUTH_METHOD_PUBLICKEY | SSH_AUTH_METHOD_PASSWORD);
            agent->callbacks_ready = true;
        }

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

        /* The event loop that dispatches post-KEX traffic is created once KEX
         * is done (as in libssh's samplesshd-cb); the callbacks it dispatches
         * to were registered before KEX (see above). */
        if (agent->event == NULL)
        {
            agent->event = ssh_event_new();
            if (agent->event == NULL)
            {
                agent->state = PUT_STATE_ERROR;
                return error_result("ssh_event_new failed");
            }
            ssh_event_add_session(agent->event, agent->session);
        }

        bool alive = dispatch_server_events(agent);
        /* The claim comes with the authentication, as the wolfSSH harness emits it from its
         * auth callbacks: also when a later packet of the same step ended the session. */
        if (agent->authenticated)
            emit_handshake_claim(agent);
        if (!alive)
            return error_result(agent->state_desc);

        if (agent->authenticated)
        {
            /* DONE at the same point as the wolfSSH server, whose accept() completes on the
             * first session request (or channel data), not at USERAUTH_SUCCESS. */
            if (agent->session_requested)
            {
                agent->state = PUT_STATE_DONE;
                snprintf(agent->state_desc, sizeof(agent->state_desc), "DONE");
            }
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

        /* The client flow mirrors wolfSSH_connect() step for step, so a libssh
         * client and a wolfSSH client emit the same c2s message sequence and the
         * c2s-decrypted transcripts compare 1:1:
         *   USERAUTH_REQUEST "none" (the RFC 4252 §5.2 probe) -> "password" only if
         *   the server refuses it -> CHANNEL_OPEN "session" -> CHANNEL_REQUEST
         *   "shell" (want_reply) -> DONE.
         * (wolfSSH's connect() sends exactly these; its agent / pty requests are
         * compiled out of our build.) The handshake claim is still emitted at
         * auth success, as before. */
        if (agent->state == PUT_STATE_AUTH)
        {
            for (int i = 0; i < 4; ++i)
            {
                int rc = agent->auth_none_done ? ssh_userauth_password(agent->session, NULL, "test")
                                               : ssh_userauth_none(agent->session, NULL);
                if (rc == SSH_AUTH_AGAIN)
                {
                    continue;
                }
                if (rc == SSH_AUTH_SUCCESS)
                {
                    emit_handshake_claim(agent); /* in the AUTH state, for its post-KEX claim */
                    agent->state = PUT_STATE_CHANNEL;
                    snprintf(agent->state_desc, sizeof(agent->state_desc), "CHANNEL_OPEN");
                    break;
                }
                if ((rc == SSH_AUTH_DENIED || rc == SSH_AUTH_PARTIAL) && !agent->auth_none_done)
                {
                    agent->auth_none_done = true; /* "none" refused: fall back */
                    continue;
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
            if (agent->state == PUT_STATE_AUTH)
                return ok_result();
        }

        if (agent->state == PUT_STATE_CHANNEL)
        {
            if (agent->channel == NULL)
            {
                agent->channel = ssh_channel_new(agent->session);
                if (agent->channel == NULL)
                {
                    agent->state = PUT_STATE_ERROR;
                    snprintf(agent->state_desc, sizeof(agent->state_desc), "CHANNEL_ERROR");
                    return error_result(ssh_get_error(agent->session));
                }
            }
            for (int i = 0; i < 4; ++i)
            {
                int rc = agent->client_chan_opened ? ssh_channel_request_shell(agent->channel)
                                                   : ssh_channel_open_session(agent->channel);
                if (rc == SSH_AGAIN)
                    return ok_result(); /* waiting for the server's reply */
                if (rc != SSH_OK)
                {
                    agent->state = PUT_STATE_ERROR;
                    snprintf(agent->state_desc, sizeof(agent->state_desc), "CHANNEL_ERROR");
                    return error_result(ssh_get_error(agent->session));
                }
                if (!agent->client_chan_opened)
                {
                    agent->client_chan_opened = true; /* confirmed: send the shell request */
                    snprintf(agent->state_desc, sizeof(agent->state_desc), "CHANNEL_REQUEST");
                    continue;
                }
                agent->state = PUT_STATE_DONE;
                snprintf(agent->state_desc, sizeof(agent->state_desc), "DONE");
                /* What the server sent behind its reply is handled in this same step, as
                 * the wolfSSH harness goes on into wolfSSH_worker() once connect() is done. */
                return dispatch_client_events(agent) ? ok_result()
                                                     : error_result(agent->state_desc);
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

    /* MSG_NOSIGNAL: a peer that closed its end is an error here, not a SIGPIPE. */
    ssize_t n = send(agent->fuzz_fd, bytes, length, MSG_DONTWAIT | MSG_NOSIGNAL);
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
