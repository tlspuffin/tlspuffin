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

#include <wolfssh/ssh.h>
#include <wolfssh/error.h>

#include "bindings.h"
#include "server_key.h"

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
};

/* ── Forward declarations ────────────────────────────────────────────────── */

static AGENT       wolfssh_create(const SSH_AGENT_DESCRIPTOR *descriptor);
static void        wolfssh_destroy(AGENT agent);
static RESULT      wolfssh_progress(AGENT agent);
static RESULT      wolfssh_reset(AGENT agent, uint8_t new_name, uint8_t use_clear);
static const char *wolfssh_describe_state(AGENT agent);
static bool        wolfssh_is_successful(AGENT agent);
static void        wolfssh_register_claimer(AGENT agent, const CLAIMER_CB *claimer);
static RESULT      wolfssh_add_inbound(AGENT agent, const uint8_t *bytes, size_t length, size_t *written);
static RESULT      wolfssh_take_outbound(AGENT agent, uint8_t *bytes, size_t max_length, size_t *readbytes);
static void        wolfssh_rng_reseed(const uint8_t *buffer, size_t length);

/* ── auth callback: accept everything ────────────────────────────────────── */

static const char WOLFSSH_AUTH_PASSWORD[] = "password";

static int auth_callback(uint8_t authType, WS_UserAuthData *authData, void *ctx)
{
    (void)ctx;
    /* Dual purpose: as a SERVER, accept any credential (return SUCCESS); as a
       CLIENT, *provide* a password so SendUserAuthRequest has something to send
       (wolfSSH calls the same callback to obtain client credentials). */
    if (authType == WOLFSSH_USERAUTH_PASSWORD && authData != NULL) {
        authData->sf.password.password = (const uint8_t *)WOLFSSH_AUTH_PASSWORD;
        authData->sf.password.passwordSz = (uint32_t)(sizeof(WOLFSSH_AUTH_PASSWORD) - 1);
    }
    return WOLFSSH_USERAUTH_SUCCESS;
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
    .agent_interface = {
        .destroy             = wolfssh_destroy,
        .progress            = wolfssh_progress,
        .reset               = wolfssh_reset,
        .describe_state      = wolfssh_describe_state,
        .is_state_successful = wolfssh_is_successful,
        .register_claimer    = wolfssh_register_claimer,
        .add_inbound         = wolfssh_add_inbound,
        .take_outbound       = wolfssh_take_outbound,
    },
};

/* ── REGISTER entry point ────────────────────────────────────────────────── */

const SSH_PUT_INTERFACE *REGISTER(void)
{
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
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

static RESULT ok_result(void)             { return PUFFIN.make_result(RESULT_OK, "ok"); }
static RESULT would_block_result(const char *r) { return PUFFIN.make_result(RESULT_IO_WOULD_BLOCK, r); }
static RESULT error_result(const char *r) { return PUFFIN.make_result(RESULT_ERROR_OTHER, r); }

/* ── create ──────────────────────────────────────────────────────────────── */

static AGENT wolfssh_create(const SSH_AGENT_DESCRIPTOR *descriptor)
{
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        _log(PUFFIN.error, "wolfssh create: socketpair() failed: %s", strerror(errno));
        return NULL;
    }
    int fuzz_fd = sv[0];
    int put_fd  = sv[1];

    if (set_nonblocking(fuzz_fd) < 0 || set_nonblocking(put_fd) < 0) {
        _log(PUFFIN.error, "wolfssh create: set_nonblocking() failed: %s", strerror(errno));
        close(fuzz_fd); close(put_fd);
        return NULL;
    }

    uint8_t is_server = (descriptor->role == SSH_SERVER);
    WOLFSSH_CTX *ctx = wolfSSH_CTX_new(
        is_server ? WOLFSSH_ENDPOINT_SERVER : WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (!ctx) {
        _log(PUFFIN.error, "wolfssh create: wolfSSH_CTX_new() failed");
        close(fuzz_fd); close(put_fd);
        return NULL;
    }

    if (is_server) {
        wolfSSH_SetUserAuth(ctx, auth_callback);
        if (wolfSSH_CTX_UsePrivateKey_buffer(ctx, SERVER_KEY_DER,
                                             (uint32_t)SERVER_KEY_DER_LEN,
                                             WOLFSSH_FORMAT_ASN1) < 0) {
            _log(PUFFIN.error, "wolfssh create: failed to load host key");
            wolfSSH_CTX_free(ctx);
            close(fuzz_fd); close(put_fd);
            return NULL;
        }
    }

    WOLFSSH *ssh = wolfSSH_new(ctx);
    if (!ssh) {
        _log(PUFFIN.error, "wolfssh create: wolfSSH_new() failed");
        wolfSSH_CTX_free(ctx);
        close(fuzz_fd); close(put_fd);
        return NULL;
    }

    if (!is_server) {
        /* Client also uses the userauth callback — here to PROVIDE a password. */
        wolfSSH_SetUserAuth(ctx, auth_callback);
        /* A username is required before connect. */
        wolfSSH_SetUsername(ssh, "user");
        /* Accept the server's host key (fuzzer-supplied) rather than rejecting. */
        wolfSSH_CTX_SetPublicKeyCheck(ctx, public_key_check_callback);
    }

    wolfSSH_set_fd(ssh, put_fd);

    AGENT agent = calloc(1, sizeof(struct AGENT_TYPE));
    if (!agent) {
        wolfSSH_free(ssh); wolfSSH_CTX_free(ctx);
        close(fuzz_fd); close(put_fd);
        return NULL;
    }
    agent->name       = descriptor->name;
    agent->descriptor = *descriptor;
    agent->fuzz_fd    = fuzz_fd;
    agent->put_fd     = put_fd;
    agent->ctx        = ctx;
    agent->ssh        = ssh;
    agent->state      = PUT_STATE_HANDSHAKE;
    snprintf(agent->state_desc, sizeof(agent->state_desc), "HANDSHAKE");
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

static RESULT wolfssh_progress(AGENT agent)
{
    if (agent->state == PUT_STATE_ERROR)
        return error_result("agent in error state");

    if (agent->state == PUT_STATE_HANDSHAKE) {
        int rc = (agent->descriptor.role == SSH_SERVER)
                     ? wolfSSH_accept(agent->ssh)
                     : wolfSSH_connect(agent->ssh);
        if (rc == WS_SUCCESS) {
            agent->state = PUT_STATE_DONE;
            snprintf(agent->state_desc, sizeof(agent->state_desc), "DONE");
        } else if (is_would_block(rc)) {
            snprintf(agent->state_desc, sizeof(agent->state_desc), "HANDSHAKE/WOULD_BLOCK");
            return ok_result();
        } else {
            /* wolfSSH signals non-blocking wait via get_error (WS_WANT_READ/
               WRITE) while the function return is the generic WS_ERROR. */
            int gerr = wolfSSH_get_error(agent->ssh);
            if (is_would_block(gerr)) {
                snprintf(agent->state_desc, sizeof(agent->state_desc),
                         "HANDSHAKE/WOULD_BLOCK");
                return ok_result();
            }
            _log(PUFFIN.error, "wolfssh %s failed: rc=%d gerr=%d (%s)",
                 agent->descriptor.role == SSH_SERVER ? "accept" : "connect",
                 rc, gerr, wolfSSH_ErrorToName(gerr));
            agent->state = PUT_STATE_ERROR;
            snprintf(agent->state_desc, sizeof(agent->state_desc),
                     "HANDSHAKE/ERROR rc=%d gerr=%d", rc, gerr);
            return error_result(wolfSSH_ErrorToName(gerr));
        }
    }

    if (agent->state == PUT_STATE_DONE) {
        /* Drive the channel layer so post-auth traffic is processed. */
        word32 channelId = 0;
        int rc = wolfSSH_worker(agent->ssh, &channelId);
        if (rc != WS_SUCCESS && !is_would_block(rc)) {
            /* Channel-layer errors are not fatal for the harness. */
            snprintf(agent->state_desc, sizeof(agent->state_desc), "DONE/worker rc=%d", rc);
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

static const char *wolfssh_describe_state(AGENT agent) { return agent->state_desc; }
static bool wolfssh_is_successful(AGENT agent) { return agent->state == PUT_STATE_DONE; }

static void wolfssh_register_claimer(AGENT agent, const CLAIMER_CB *claimer)
{
    (void)agent;
    (void)claimer;
}

/* ── add_inbound / take_outbound (puffin <-> fuzz_fd) ─────────────────────── */

static RESULT wolfssh_add_inbound(AGENT agent, const uint8_t *bytes, size_t length, size_t *written)
{
    if (length == 0) { *written = 0; return ok_result(); }
    ssize_t n = send(agent->fuzz_fd, bytes, length, MSG_DONTWAIT);
    if (n < 0) {
        *written = 0;
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return would_block_result("send: EAGAIN");
        return error_result(strerror(errno));
    }
    *written = (size_t)n;
    return ok_result();
}

static RESULT wolfssh_take_outbound(AGENT agent, uint8_t *bytes, size_t max_length, size_t *readbytes)
{
    if (max_length == 0) { *readbytes = 0; return ok_result(); }
    ssize_t n = recv(agent->fuzz_fd, bytes, max_length, MSG_DONTWAIT);
    if (n < 0) {
        *readbytes = 0;
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return would_block_result("recv: EAGAIN");
        return error_result(strerror(errno));
    }
    *readbytes = (size_t)n;
    return ok_result();
}

/* ── rng_reseed ──────────────────────────────────────────────────────────── */

static void wolfssh_rng_reseed(const uint8_t *buffer, size_t length)
{
    /* wolfCrypt's RNG is not reset through a simple hook here; differential
       determinism is handled by the DDYF field annotations instead. No-op. */
    (void)buffer;
    (void)length;
}
