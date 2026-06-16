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
};

/* ── Forward declarations ────────────────────────────────────────────────── */

static AGENT    libssh_create(const SSH_AGENT_DESCRIPTOR *descriptor);
static void     libssh_destroy(AGENT agent);
static RESULT   libssh_progress(AGENT agent);
static RESULT   libssh_reset(AGENT agent, uint8_t new_name, uint8_t use_clear);
static const char *libssh_describe_state(AGENT agent);
static bool     libssh_is_successful(AGENT agent);
static void     libssh_register_claimer(AGENT agent, const CLAIMER_CB *claimer);
static RESULT   libssh_add_inbound(AGENT agent, const uint8_t *bytes, size_t length, size_t *written);
static RESULT   libssh_take_outbound(AGENT agent, uint8_t *bytes, size_t max_length, size_t *readbytes);

/* ── PUT interface table ─────────────────────────────────────────────────── */

static const SSH_PUT_INTERFACE LIBSSH_PUT = {
    .create = libssh_create,
    .agent_interface = {
        .destroy            = libssh_destroy,
        .progress           = libssh_progress,
        .reset              = libssh_reset,
        .describe_state     = libssh_describe_state,
        .is_state_successful = libssh_is_successful,
        .register_claimer   = libssh_register_claimer,
        .add_inbound        = libssh_add_inbound,
        .take_outbound      = libssh_take_outbound,
    },
};

/* ── REGISTER entry point (called by puffin-build bundle machinery) ─────── */

const SSH_PUT_INTERFACE *REGISTER(void)
{
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        rl.rlim_cur = (rl.rlim_max == RLIM_INFINITY) ? 65536 : rl.rlim_max;
        setrlimit(RLIMIT_NOFILE, &rl);
    }
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
    int put_fd  = sv[1];

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

    /* Disable config-file loading */
    int zero = 0;
    ssh_options_set(session, SSH_OPTIONS_PROCESS_CONFIG, &zero);
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

    agent->name        = descriptor->name;
    agent->descriptor  = *descriptor;
    agent->fuzz_fd     = fuzz_fd;
    agent->put_fd      = put_fd;
    agent->session     = session;
    agent->bind        = bind;
    agent->state       = PUT_STATE_KEX;
    snprintf(agent->state_desc, sizeof(agent->state_desc), "KEX");

    return agent;
}

/* ── destroy ─────────────────────────────────────────────────────────────── */

static void libssh_destroy(AGENT agent)
{
    if (!agent)
        return;

    close(agent->fuzz_fd);

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

static RESULT libssh_progress(AGENT agent)
{
    if (agent->state == PUT_STATE_ERROR)
        return error_result("agent is in error state");

    if (agent->state == PUT_STATE_DONE)
        return ok_result();

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

        if (agent->state == PUT_STATE_AUTH)
        {
            for (int i = 0; i < 4; ++i)
            {
                ssh_message msg = ssh_message_get(agent->session);
                if (!msg)
                    break;

                int msg_type = ssh_message_type(msg);
                if (msg_type == SSH_REQUEST_AUTH)
                {
                    ssh_message_auth_reply_success(msg, 0);
                    agent->state = PUT_STATE_DONE;
                    snprintf(agent->state_desc, sizeof(agent->state_desc), "DONE");
                    ssh_message_free(msg);
                    break;
                }
                else
                {
                    ssh_message_reply_default(msg);
                }
                ssh_message_free(msg);
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

/* ── register_claimer (no-op for now) ────────────────────────────────────── */

static void libssh_register_claimer(AGENT agent, const CLAIMER_CB *claimer)
{
    /* Claims extraction is not yet implemented for SSH. */
    (void)agent;
    (void)claimer;
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

static RESULT libssh_take_outbound(AGENT agent, uint8_t *bytes, size_t max_length, size_t *readbytes)
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

