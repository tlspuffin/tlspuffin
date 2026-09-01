/*
 * sshpuffin/harness/wolfssh/src/put.c
 *
 * wolfSSH C harness for sshpuffin.
 *
 * Same in-memory model as the libssh harness: a socketpair() gives wolfSSH a
 * full-duplex socket while the opposite end is exposed to the puffin fuzzer.
 * wolfSSH is a library with embedder-supplied auth callbacks (no privsep / PAM /
 * fork), so a full handshake — including userauth and channels — runs in-process.
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

#include <wolfssh/error.h>
#include <wolfssh/ssh.h>
#include <wolfssl/wolfcrypt/sha256.h>

#include "bindings.h"
#include "server_key.h"
#include <puffin/ssh_authorized_creds.h>

/*
 * Claim instrumentation (HAS_CLAIMS). Set iff the vendored wolfSSH carries the
 * PUFFIN session-id patch (puffin-build/vendors/wolfssh/instrument_claims.cmake).
 * The accessor exposes the SSH session id (exchange hash H) from the internal
 * WOLFSSH struct — not in any public wolfSSH header — so the decryption recipe
 * can derive the server-to-client keys. Declared weak so a plain (non-patched)
 * wolfSSH still links; then the call resolves to NULL and session_id stays
 * empty. Pure observation; never affects the protocol path.
 */
#ifdef HAS_CLAIMS
extern int puffin_wolfssh_get_session_id(WOLFSSH *ssh, const unsigned char **out,
                                         unsigned int *len) __attribute__((weak));
#endif /* HAS_CLAIMS */

/* ── Internal state ──────────────────────────────────────────────────────── */

typedef enum
{
    PUT_STATE_HANDSHAKE, /* KEX + userauth in progress */
    PUT_STATE_DONE,      /* accept()/connect() completed */
    PUT_STATE_ERROR,     /* unrecoverable error */
} PutState;

struct AGENT_TYPE
{
    uint8_t name;
    SSH_AGENT_DESCRIPTOR descriptor;

    int fuzz_fd; /* puffin reads/writes here (socketpair end 0) */
    int put_fd;  /* wolfSSH session I/O (socketpair end 1) */

    WOLFSSH_CTX *ctx;
    WOLFSSH *ssh;

    PutState state;
    char state_desc[256];

    const CLAIMER_CB *claimer; /* registered claim callback, or NULL */
    bool claim_emitted;        /* guard so the handshake claim fires once */

    /* Authentication belief recorded by the userauth callback (server side). */
    char auth_method[SSH_CLAIM_STR_LEN];
    char auth_user[SSH_CLAIM_STR_LEN];
    uint8_t auth_key_fp[32];
    uint8_t auth_key_fp_len;
};

/* ── Forward declarations ────────────────────────────────────────────────── */

static AGENT wolfssh_create(const SSH_AGENT_DESCRIPTOR *descriptor);
static void wolfssh_destroy(AGENT agent);
static RESULT wolfssh_progress(AGENT agent);
static RESULT wolfssh_reset(AGENT agent, uint8_t new_name, uint8_t use_clear);
static const char *wolfssh_describe_state(AGENT agent);
static bool wolfssh_is_successful(AGENT agent);
static void wolfssh_register_claimer(AGENT agent, const CLAIMER_CB *claimer);
static RESULT
wolfssh_add_inbound(AGENT agent, const uint8_t *bytes, size_t length, size_t *written);
static RESULT
wolfssh_take_outbound(AGENT agent, uint8_t *bytes, size_t max_length, size_t *readbytes);
static void wolfssh_rng_reseed(const uint8_t *buffer, size_t length);
static void wolfssh_seed_rewind(void);
static void emit_handshake_claim(AGENT agent);

/* ── auth callback: enforce the shared authorization boundary ─────────────── */

static const char WOLFSSH_AUTH_PASSWORD[] = "password";

static int auth_callback(uint8_t authType, WS_UserAuthData *authData, void *ctx)
{
    AGENT agent = (AGENT)ctx;
    bool is_server = (agent != NULL && agent->descriptor.role == SSH_SERVER);

    /* CLIENT role: *provide* a password so SendUserAuthRequest has something to
       send (wolfSSH calls the same callback to obtain client credentials). Only
       do this off the server path — on the server, sf.password holds the
       RECEIVED password and must not be overwritten. */
    if (!is_server)
    {
        if (authType == WOLFSSH_USERAUTH_PASSWORD && authData != NULL)
        {
            authData->sf.password.password = (const uint8_t *)WOLFSSH_AUTH_PASSWORD;
            authData->sf.password.passwordSz =
                (uint32_t)(sizeof(WOLFSSH_AUTH_PASSWORD) - 1);
        }
        return WOLFSSH_USERAUTH_SUCCESS;
    }

    /* SERVER role: enforce the shared (user, key) / (user, password) allow-list
       so the boundary is identical to the libssh harness. wolfSSH has
       cryptographically verified the publickey signature by the time it calls us
       with hasSignature set; a valid signature is necessary but not sufficient —
       the key must be authorized FOR THIS USER. */
    if (authData == NULL)
        return WOLFSSH_USERAUTH_FAILURE;

    char user[SSH_CLAIM_STR_LEN];
    snprintf(user, sizeof(user), "%.*s", (int)authData->usernameSz,
             authData->username ? (const char *)authData->username : "");
    snprintf(agent->auth_user, sizeof(agent->auth_user), "%s", user);

    if (authType == WOLFSSH_USERAUTH_PUBLICKEY)
    {
        if (!authData->sf.publicKey.hasSignature)
            return WOLFSSH_USERAUTH_SUCCESS; /* probe: let the client send the sig */

        uint8_t fp[32];
        wc_Sha256Hash(authData->sf.publicKey.publicKey,
                      authData->sf.publicKey.publicKeySz, fp);
        if (!ssh_creds_key_authorized(user, fp, sizeof(fp)))
            return WOLFSSH_USERAUTH_INVALID_PUBLICKEY;

        snprintf(agent->auth_method, sizeof(agent->auth_method), "publickey");
        memcpy(agent->auth_key_fp, fp, sizeof(fp));
        agent->auth_key_fp_len = 32;
        /* Emit the completion claim HERE, at auth success — not at
           wolfSSH_accept()==WS_SUCCESS, which for a server only fires after a
           channel is opened. The differential corpus is auth-complete (no channel
           step), so accept() never returns WS_SUCCESS on it and the claim would
           never fire; libssh's harness emits at auth completion, so this keeps the
           two symmetric. The session id (H) is set at KEX (before auth), so it is
           already available for the decryption recipe. Idempotent (claim_emitted). */
        emit_handshake_claim(agent);
        return WOLFSSH_USERAUTH_SUCCESS;
    }
    else if (authType == WOLFSSH_USERAUTH_PASSWORD)
    {
        if (!ssh_creds_password_authorized(user, authData->sf.password.password,
                                           authData->sf.password.passwordSz))
            return WOLFSSH_USERAUTH_INVALID_PASSWORD;

        snprintf(agent->auth_method, sizeof(agent->auth_method), "password");
        agent->auth_key_fp_len = 0;
        emit_handshake_claim(agent); /* see publickey branch: emit at auth success */
        return WOLFSSH_USERAUTH_SUCCESS;
    }

    return WOLFSSH_USERAUTH_FAILURE;
}

/* Client-side host-key check: accept any server key. Without this, wolfSSH's
   client rejects the (fuzzer-supplied) host key and aborts the handshake. */
static int public_key_check_callback(const uint8_t *publicKey, uint32_t publicKeySz, void *ctx)
{
    (void)publicKey;
    (void)publicKeySz;
    (void)ctx;
    return 0; /* 0 = accept */
}

/* ── PUT interface table ─────────────────────────────────────────────────── */

static const SSH_PUT_INTERFACE WOLFSSH_PUT = {
    .create = wolfssh_create,
    .rng_reseed = wolfssh_rng_reseed,
    .agent_interface =
        {
            .destroy = wolfssh_destroy,
            .progress = wolfssh_progress,
            .reset = wolfssh_reset,
            .describe_state = wolfssh_describe_state,
            .is_state_successful = wolfssh_is_successful,
            .register_claimer = wolfssh_register_claimer,
            .add_inbound = wolfssh_add_inbound,
            .take_outbound = wolfssh_take_outbound,
        },
};

/* ── REGISTER entry point ────────────────────────────────────────────────── */

const SSH_PUT_INTERFACE *REGISTER(void)
{
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0)
    {
        rl.rlim_cur = (rl.rlim_max == RLIM_INFINITY) ? 65536 : rl.rlim_max;
        setrlimit(RLIMIT_NOFILE, &rl);
    }
    wolfSSH_Init();
#ifdef PUFFIN_WOLFSSH_DEBUG
    wolfSSH_Debugging_ON();
#endif
    return &WOLFSSH_PUT;
}

/* ── helpers ─────────────────────────────────────────────────────────────── */

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
static RESULT would_block_result(const char *r)
{
    return PUFFIN.make_result(RESULT_IO_WOULD_BLOCK, r);
}
static RESULT error_result(const char *r)
{
    return PUFFIN.make_result(RESULT_ERROR_OTHER, r);
}

/* ── create ──────────────────────────────────────────────────────────────── */

static AGENT wolfssh_create(const SSH_AGENT_DESCRIPTOR *descriptor)
{
    // Start this agent's deterministic RNG stream from position 0 (see
    // wolfssh_seed_rewind): makes both PUTs in a differential run identical.
    wolfssh_seed_rewind();

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
    {
        _log(PUFFIN.error, "wolfssh create: socketpair() failed: %s", strerror(errno));
        return NULL;
    }
    int fuzz_fd = sv[0];
    int put_fd = sv[1];

    if (set_nonblocking(fuzz_fd) < 0 || set_nonblocking(put_fd) < 0)
    {
        _log(PUFFIN.error, "wolfssh create: set_nonblocking() failed: %s", strerror(errno));
        close(fuzz_fd);
        close(put_fd);
        return NULL;
    }

    uint8_t is_server = (descriptor->role == SSH_SERVER);
    WOLFSSH_CTX *ctx =
        wolfSSH_CTX_new(is_server ? WOLFSSH_ENDPOINT_SERVER : WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (!ctx)
    {
        _log(PUFFIN.error, "wolfssh create: wolfSSH_CTX_new() failed");
        close(fuzz_fd);
        close(put_fd);
        return NULL;
    }

    /* Uniformise advertised algorithms (differential fuzzing). NULL = keep
     * wolfSSH defaults. Restricting the offered sets makes this PUT's KEXINIT
     * match the other PUT's so static capability no longer diffs. */
    if (descriptor->kex)
        wolfSSH_CTX_SetAlgoListKex(ctx, descriptor->kex);
    if (descriptor->ciphers)
        wolfSSH_CTX_SetAlgoListCipher(ctx, descriptor->ciphers);
    if (descriptor->macs)
        wolfSSH_CTX_SetAlgoListMac(ctx, descriptor->macs);
    if (descriptor->hostkey_algos)
        wolfSSH_CTX_SetAlgoListKey(ctx, descriptor->hostkey_algos);
    /* server-sig-algs advertised in EXT_INFO (RFC 8308). wolfSSH stores the
       pointer without copying, so the string must outlive the ctx — the Rust
       side keeps it alive for the agent lifetime (see CAgent `_algos`). */
    if (descriptor->server_sig_algs)
        wolfSSH_CTX_SetAlgoListKeyAccepted(ctx, descriptor->server_sig_algs);

    if (is_server)
    {
        wolfSSH_SetUserAuth(ctx, auth_callback);
        if (wolfSSH_CTX_UsePrivateKey_buffer(ctx,
                                             SERVER_KEY_DER,
                                             (uint32_t)SERVER_KEY_DER_LEN,
                                             WOLFSSH_FORMAT_ASN1) < 0)
        {
            _log(PUFFIN.error, "wolfssh create: failed to load host key");
            wolfSSH_CTX_free(ctx);
            close(fuzz_fd);
            close(put_fd);
            return NULL;
        }
    }

    WOLFSSH *ssh = wolfSSH_new(ctx);
    if (!ssh)
    {
        _log(PUFFIN.error, "wolfssh create: wolfSSH_new() failed");
        wolfSSH_CTX_free(ctx);
        close(fuzz_fd);
        close(put_fd);
        return NULL;
    }

    if (!is_server)
    {
        /* Client also uses the userauth callback — here to PROVIDE a password. */
        wolfSSH_SetUserAuth(ctx, auth_callback);
        /* A username is required before connect. */
        wolfSSH_SetUsername(ssh, "user");
        /* Accept the server's host key (fuzzer-supplied) rather than rejecting. */
        wolfSSH_CTX_SetPublicKeyCheck(ctx, public_key_check_callback);
    }

    wolfSSH_set_fd(ssh, put_fd);

    AGENT agent = calloc(1, sizeof(struct AGENT_TYPE));
    if (!agent)
    {
        wolfSSH_free(ssh);
        wolfSSH_CTX_free(ctx);
        close(fuzz_fd);
        close(put_fd);
        return NULL;
    }
    agent->name = descriptor->name;
    agent->descriptor = *descriptor;
    agent->fuzz_fd = fuzz_fd;
    agent->put_fd = put_fd;
    agent->ctx = ctx;
    agent->ssh = ssh;
    agent->state = PUT_STATE_HANDSHAKE;
    snprintf(agent->state_desc, sizeof(agent->state_desc), "HANDSHAKE");
    /* Hand the agent to the userauth callback so it can record the server's
     * authentication belief (method / user / verified-key fingerprint). */
    wolfSSH_SetUserAuthCtx(ssh, agent);
    return agent;
}

/* ── destroy ─────────────────────────────────────────────────────────────── */

static void wolfssh_destroy(AGENT agent)
{
    if (!agent)
        return;
    if (agent->ssh)
        wolfSSH_free(agent->ssh);
    if (agent->ctx)
        wolfSSH_CTX_free(agent->ctx);
    close(agent->fuzz_fd);
    /* wolfSSH_free closes put_fd via the session; close defensively if still open. */
    if (fcntl(agent->put_fd, F_GETFD) != -1)
        close(agent->put_fd);
    free(agent);
}

/* ── progress ────────────────────────────────────────────────────────────── */

static int is_would_block(int rc)
{
    return rc == WS_WANT_READ || rc == WS_WANT_WRITE;
}

/* ── claim emission ──────────────────────────────────────────────────────── */

/* Write the negotiated text value identified by <id> into a fixed claim buffer. */
static void claim_get_text(AGENT agent, WS_Text id, char *dst)
{
    dst[0] = '\0';
    /* wolfSSH_GetText returns the number of chars that would be written; it may
       exceed the buffer (truncation) but never overruns it. */
    (void)wolfSSH_GetText(agent->ssh, id, dst, SSH_CLAIM_STR_LEN);
}

/*
 * Build a HandshakeComplete claim from the session's negotiated parameters and
 * hand it to the registered callback. Fires at most once per agent.
 */
static void emit_handshake_claim(AGENT agent)
{
    if (agent->claimer == NULL || agent->claim_emitted)
        return;

    Claim claim;
    memset(&claim, 0, sizeof(claim));
    claim_get_text(agent, WOLFSSH_TEXT_KEX_ALGO, claim.kex);
    claim_get_text(agent, WOLFSSH_TEXT_CRYPTO_IN_CIPHER, claim.cipher_in);
    claim_get_text(agent, WOLFSSH_TEXT_CRYPTO_OUT_CIPHER, claim.cipher_out);
    claim_get_text(agent, WOLFSSH_TEXT_CRYPTO_IN_MAC, claim.hmac_in);
    claim_get_text(agent, WOLFSSH_TEXT_CRYPTO_OUT_MAC, claim.hmac_out);
    snprintf(claim.auth_method, SSH_CLAIM_STR_LEN, "%s", agent->auth_method);
    snprintf(claim.auth_user, SSH_CLAIM_STR_LEN, "%s", agent->auth_user);
    if (agent->auth_key_fp_len > 0)
    {
        memcpy(claim.auth_key_fp, agent->auth_key_fp, agent->auth_key_fp_len);
        claim.auth_key_fp_len = agent->auth_key_fp_len;
    }
#ifdef HAS_CLAIMS
    /* KEX-transcript binding: the SSH session id (exchange hash H). */
    if (puffin_wolfssh_get_session_id != NULL)
    {
        const unsigned char *sid = NULL;
        unsigned int sid_len = 0;
        if (puffin_wolfssh_get_session_id(agent->ssh, &sid, &sid_len) == 0 && sid != NULL)
        {
            if (sid_len > sizeof(claim.session_id))
                sid_len = sizeof(claim.session_id);
            memcpy(claim.session_id, sid, sid_len);
            claim.session_id_len = (uint8_t)sid_len;
        }
    }
#endif /* HAS_CLAIMS */
    claim.phase = 3; /* PHASE_DONE: this is the completed-handshake claim */

    agent->claimer->notify(agent->claimer->context, &claim);
    agent->claim_emitted = true;
}

static RESULT wolfssh_progress(AGENT agent)
{
    if (agent->state == PUT_STATE_ERROR)
        return error_result("agent in error state");

    if (agent->state == PUT_STATE_HANDSHAKE)
    {
        int rc = (agent->descriptor.role == SSH_SERVER) ? wolfSSH_accept(agent->ssh)
                                                        : wolfSSH_connect(agent->ssh);
        if (rc == WS_SUCCESS)
        {
            agent->state = PUT_STATE_DONE;
            snprintf(agent->state_desc, sizeof(agent->state_desc), "DONE");
            emit_handshake_claim(agent);
        }
        else if (is_would_block(rc))
        {
            snprintf(agent->state_desc, sizeof(agent->state_desc), "HANDSHAKE/WOULD_BLOCK");
            return ok_result();
        }
        else
        {
            /* wolfSSH signals non-blocking wait via get_error (WS_WANT_READ/
               WRITE) while the function return is the generic WS_ERROR. */
            int gerr = wolfSSH_get_error(agent->ssh);
            if (is_would_block(gerr))
            {
                snprintf(agent->state_desc, sizeof(agent->state_desc), "HANDSHAKE/WOULD_BLOCK");
                return ok_result();
            }
            /* wolfSSH_accept returns non-error STATUS codes (not failures) when
               channel activity happens while it is still driving the accept
               loop: channel data / extended data became available, or a rekey
               is in flight. libssh's harness consumes these via its channel
               callbacks and keeps going; treating them as a failed handshake
               here (as any non-would-block code otherwise is) is a harness
               asymmetry that made post-auth channel-data seeds diverge. Mirror
               libssh: a channel-data status means KEX+auth+channel-open already
               completed, so move to DONE (the DONE path's wolfSSH_worker drains
               the channel); a rekey status just means keep progressing. */
            if (rc == WS_CHAN_RXD || gerr == WS_CHAN_RXD || rc == WS_EXTDATA ||
                gerr == WS_EXTDATA)
            {
                agent->state = PUT_STATE_DONE;
                snprintf(agent->state_desc, sizeof(agent->state_desc),
                         "DONE (channel data during accept)");
                return ok_result();
            }
            if (rc == WS_REKEYING || gerr == WS_REKEYING)
            {
                snprintf(agent->state_desc, sizeof(agent->state_desc), "HANDSHAKE/REKEYING");
                return ok_result();
            }
            /* A failed handshake is the common, expected outcome when the
               fuzzer feeds mutated input — the PUT is correctly rejecting it.
               Report it through error_result (the channel the fuzzer handles)
               and keep it at trace level, like the libssh harness, instead of
               flooding error.log. */
            _log(PUFFIN.trace,
                 "wolfssh %s failed: rc=%d gerr=%d (%s)",
                 agent->descriptor.role == SSH_SERVER ? "accept" : "connect",
                 rc,
                 gerr,
                 wolfSSH_ErrorToName(gerr));
            agent->state = PUT_STATE_ERROR;
            snprintf(agent->state_desc,
                     sizeof(agent->state_desc),
                     "HANDSHAKE/ERROR rc=%d gerr=%d",
                     rc,
                     gerr);
            return error_result(wolfSSH_ErrorToName(gerr));
        }
    }

    if (agent->state == PUT_STATE_DONE)
    {
        /* Drive the post-handshake state machine to quiescence, exactly like a
         * real server's event loop (and mirroring the libssh harness's
         * ssh_event_dopoll loop above). A SINGLE wolfSSH_worker call is NOT a
         * faithful I/O stub: some operations need several worker calls to fully
         * process input and FLUSH all output (e.g. reading a peer KEXINIT and
         * then sending the rekey KEXINIT response). Calling worker once dropped
         * that second-step output, making the harness's wolfSSH behave
         * differently from a real TCP server. Loop until it would-block (nothing
         * left to do) or hits a fatal error; a bounded cap prevents a spin. */
        for (int i = 0; i < 32; ++i)
        {
            word32 channelId = 0;
            int rc = wolfSSH_worker(agent->ssh, &channelId);
            int err = wolfSSH_get_error(agent->ssh);
            /* Mirror the wolfSSH echoserver's post-handshake loop exactly (see
             * examples/echoserver.c): during a rekey, KEEP TURNING THE CRANK —
             * wolfSSH_worker returns WS_REKEYING while it drives the re-exchange
             * across several calls (reading the peer KEXINIT, sending its own
             * KEXINIT and KEXDH_REPLY, NEWKEYS). Breaking on WS_REKEYING (as a
             * single call does) leaves the rekey half-driven and drops the
             * server's rekey output, making the harness diverge from a real
             * server. */
            if (rc == WS_REKEYING)
                continue;
            if (is_would_block(err))
                break; /* WANT_READ/WANT_WRITE: no more to do this round */
            if (rc == WS_SUCCESS || rc == WS_CHAN_RXD)
                continue; /* made progress; more may be pending */
            /* Real error / EOF: record and stop (next input feeds on next step). */
            snprintf(agent->state_desc, sizeof(agent->state_desc), "DONE/worker rc=%d", rc);
            break;
        }
        return ok_result();
    }

    return ok_result();
}

/* ── reset ───────────────────────────────────────────────────────────────── */

static RESULT wolfssh_reset(AGENT agent, uint8_t new_name, uint8_t use_clear)
{
    (void)use_clear;
    agent->name = new_name;
    return error_result("reset not supported for wolfssh harness");
}

static const char *wolfssh_describe_state(AGENT agent)
{
    return agent->state_desc;
}
static bool wolfssh_is_successful(AGENT agent)
{
    return agent->state == PUT_STATE_DONE;
}

static void wolfssh_register_claimer(AGENT agent, const CLAIMER_CB *claimer)
{
    /* Ownership of the CB (and its context) stays with the caller. */
    agent->claimer = claimer;
}

/* ── add_inbound / take_outbound (puffin <-> fuzz_fd) ─────────────────────── */

static RESULT wolfssh_add_inbound(AGENT agent, const uint8_t *bytes, size_t length, size_t *written)
{
    if (length == 0)
    {
        *written = 0;
        return ok_result();
    }
    ssize_t n = send(agent->fuzz_fd, bytes, length, MSG_DONTWAIT);
    if (n < 0)
    {
        *written = 0;
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return would_block_result("send: EAGAIN");
        return error_result(strerror(errno));
    }
    *written = (size_t)n;
    return ok_result();
}

static RESULT
wolfssh_take_outbound(AGENT agent, uint8_t *bytes, size_t max_length, size_t *readbytes)
{
    if (max_length == 0)
    {
        *readbytes = 0;
        return ok_result();
    }
    ssize_t n = recv(agent->fuzz_fd, bytes, max_length, MSG_DONTWAIT);
    if (n < 0)
    {
        *readbytes = 0;
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return would_block_result("recv: EAGAIN");
        return error_result(strerror(errno));
    }
    *readbytes = (size_t)n;
    return ok_result();
}

/* ── rng_reseed ──────────────────────────────────────────────────────────── */

/* Deterministic entropy source for wolfCrypt.
 *
 * wolfSSL is built with -DCUSTOM_RAND_GENERATE_SEED=puffin_wolfssl_seed (see
 * puffin-build/vendors/wolfssh/build_wolfssl_dep.sh), so every wc_GenerateSeed()
 * — which seeds wolfCrypt's Hash_DRBG, and therefore all of wolfSSH's KEX
 * randomness — routes here. We emit a reproducible byte stream whose read
 * position is reset by wolfssh_rng_reseed(). Because the differential reseeds
 * both PUTs from the same buffer before each run, the two PUTs draw identical
 * entropy and produce identical ephemerals, removing encrypted-layer false
 * positives; campaigns also become deterministic. */
static uint8_t g_seed_base[64];
static size_t g_seed_len = 0;
static uint32_t g_seed_pos = 0;

int puffin_wolfssl_seed(unsigned char *output, unsigned int sz)
{
    for (unsigned int i = 0; i < sz; i++)
    {
        uint8_t b = (g_seed_len > 0) ? g_seed_base[g_seed_pos % g_seed_len] : (uint8_t)0xA5;
        /* Mix in the position so a single short seed buffer still yields a
           full-entropy-looking (but deterministic) stream for the DRBG. */
        output[i] = (uint8_t)(b + (uint8_t)(g_seed_pos * 0x9Du));
        g_seed_pos++;
    }
    return 0;
}

static void wolfssh_rng_reseed(const uint8_t *buffer, size_t length)
{
    g_seed_len = (length < sizeof(g_seed_base)) ? length : sizeof(g_seed_base);
    if (g_seed_len > 0)
        memcpy(g_seed_base, buffer, g_seed_len);
    g_seed_pos = 0;
}

/* Rewind the deterministic seed stream to position 0 WITHOUT changing the seed
 * base. Called at the start of every agent create so that each PUT execution
 * begins from the same RNG position. This matters for the DIFFERENTIAL: puffin
 * reseeds all factories ONCE before running both PUTs (execution.rs), so without
 * this rewind the first PUT advances g_seed_pos and the SECOND PUT starts from a
 * different position — giving the two wolfSSH runs different ephemeral randomness,
 * different packet padding, and hence order-dependent output (e.g. whether a
 * CHANNEL_OPEN_CONFIRMATION lands in a given drain). Rewinding makes wolfSSH-vs-
 * wolfSSH deterministic, a precondition for comparing wolfSSH against libssh. */
static void wolfssh_seed_rewind(void)
{
    g_seed_pos = 0;
}
