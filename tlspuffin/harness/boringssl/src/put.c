#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <claim-interface.h>
#include <puffin/tls.h>

#include "bindings.h"
#include "claims.h"
#include "rng.h"

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

extern const TLS_PUT_INTERFACE *REGISTER();

// ---------------------------------------------------------------------------
// Agent state.
//
// The deferred claim queue (claimQueue) follows the LibreSSL harness pattern:
//   - msg_callback fires inside SSL_do_handshake() when SSL state is mid-transition.
//   - We only snapshot the transcript hash + claim type into the queue.
//   - In progress(), after SSL_do_handshake() returns, we flush the queue and
//     emit full claims (fill_claim) when SSL state is stable.
// ---------------------------------------------------------------------------

#define CLAIM_QUEUE_SIZE 8

struct AGENT_TYPE
{
    uint8_t name;
    TLS_AGENT_DESCRIPTOR descriptor;

    SSL_CTX *ctx;
    SSL *ssl;
    BIO *in;
    BIO *out;

    const CLAIMER_CB *claimer;

    // Deferred claim queue (filled in msg_callback, flushed in progress).
    // Secrets are captured here because BoringSSL frees hs when the handshake
    // completes, making secrets inaccessible at progress() flush time.
    struct
    {
        enum ClaimType type;
        uint8_t transcript[EVP_MAX_MD_SIZE];
        int transcript_len;
        // Snapshot of secrets at msg_callback time (hs still alive)
        bool has_secrets;
    } claimQueue[CLAIM_QUEUE_SIZE];
    int claimQueueLen;

    // Snapshot of TLS 1.3 secrets, captured from hs during msg_callback
    // before BoringSSL frees hs at handshake completion.
    SnappedTLS13Secrets snapped_secrets;
    bool secrets_snapped;

    // Cached randoms from handshake messages (msg_callback).
    // Needed because BoringSSL may not expose them via SSL_get_*_random
    // at the time fill_claim runs (especially TLS 1.3 client-side).
    unsigned char cached_server_random[SSL3_RANDOM_SIZE];
    unsigned char cached_client_random[SSL3_RANDOM_SIZE];
    bool has_cached_server_random;
    bool has_cached_client_random;

    // CH+SH transcript hash and handshake secret, captured by the
    // PUFFIN_store_ch_sh_transcript patch at the exact right moment
    // in tls13_derive_handshake_secrets.  Stored here (not in a global
    // C++ map) to avoid lifetime/threading issues.
    uint8_t stored_ch_sh_transcript[EVP_MAX_MD_SIZE];
    size_t stored_ch_sh_transcript_len;
    uint8_t stored_handshake_secret[EVP_MAX_MD_SIZE];
    size_t stored_handshake_secret_len;
};

// ---------------------------------------------------------------------------
// Forward declarations
// ---------------------------------------------------------------------------

AGENT boringssl_create(const TLS_AGENT_DESCRIPTOR *descriptor);
static AGENT boringssl_create_client(const TLS_AGENT_DESCRIPTOR *descriptor);
static AGENT boringssl_create_server(const TLS_AGENT_DESCRIPTOR *descriptor);
void boringssl_destroy(AGENT agent);
RESULT boringssl_progress(AGENT agent);
RESULT boringssl_reset(AGENT agent, uint8_t new_name, uint8_t use_clear);
bool boringssl_is_successful(AGENT agent);
const char *boringssl_describe_state(AGENT agent);
RESULT boringssl_add_inbound(AGENT agent, const uint8_t *bytes, size_t length, size_t *written);
RESULT boringssl_take_outbound(AGENT agent, uint8_t *bytes, size_t max_length, size_t *readbytes);
void boringssl_register_claimer(AGENT agent, const CLAIMER_CB *claimer);

static RESULT get_result(AGENT agent, int retcode, bool allow_would_block);
static AGENT make_agent(SSL_CTX *ssl_ctx, const TLS_AGENT_DESCRIPTOR *descriptor);
static bool recreate_ssl_from_agent_ctx(AGENT agent);
static void setup_msg_callback(AGENT agent);
static void boringssl_set_protocol_version(SSL_CTX *ssl_ctx, TLS_VERSION version);

// ---------------------------------------------------------------------------
// Default claimer (no-op)
// ---------------------------------------------------------------------------

static void default_claimer_notify(void *context, Claim *claim)
{
}
static void default_claimer_destroy(void *context)
{
}

static const CLAIMER_CB DEFAULT_CLAIMER_CB = {
    .context = NULL,
    .notify = default_claimer_notify,
    .destroy = default_claimer_destroy,
};

// ---------------------------------------------------------------------------
// PUT interface registration
// ---------------------------------------------------------------------------

static const TLS_PUT_INTERFACE BORINGSSL_PUT = {
    .create = boringssl_create,
    .rng_reseed = rng_reseed,
    .supports = NULL,
    .agent_interface =
        {
            .destroy = boringssl_destroy,
            .progress = boringssl_progress,
            .reset = boringssl_reset,
            .describe_state = boringssl_describe_state,
            .is_state_successful = boringssl_is_successful,
            .register_claimer = boringssl_register_claimer,
            .add_inbound = boringssl_add_inbound,
            .take_outbound = boringssl_take_outbound,
        },
};

const TLS_PUT_INTERFACE *REGISTER()
{
    boringssl_init();
    return &BORINGSSL_PUT;
}

// ---------------------------------------------------------------------------
// Message callback — captures transcript hashes and caches randoms.
//
// This callback fires during SSL_do_handshake().  We must NOT call
// boringssl_fill_claim here because the SSL state is mid-transition.
// Instead we snapshot transcript hashes into the deferred queue and
// cache random values for later use.
// ---------------------------------------------------------------------------

static void boringssl_msg_callback(int write_p,
                                   int version,
                                   int content_type,
                                   const void *buf,
                                   size_t len,
                                   SSL *ssl,
                                   void *arg)
{
    AGENT agent = (AGENT)arg;
    if (agent == NULL)
    {
        return;
    }

    // Only interested in handshake messages (content_type 22)
    if (content_type != SSL3_RT_HANDSHAKE || len < 1)
    {
        return;
    }

    uint8_t msg_type = ((const uint8_t *)buf)[0];

    // Cache randoms from ClientHello / ServerHello messages.
    // Format: type(1) + length(3) + version(2) + random(32) -> random at offset 6.
    if (msg_type == SSL3_MT_CLIENT_HELLO && len >= 38)
    {
        memcpy(agent->cached_client_random, (const uint8_t *)buf + 6, SSL3_RANDOM_SIZE);
        agent->has_cached_client_random = true;
    }
    if (msg_type == SSL3_MT_SERVER_HELLO && len >= 38)
    {
        memcpy(agent->cached_server_random, (const uint8_t *)buf + 6, SSL3_RANDOM_SIZE);
        agent->has_cached_server_random = true;
    }

    // Enqueue transcript claims for specific handshake messages.
    // The transcript hash is snapshotted NOW because it advances as the
    // handshake continues within the same SSL_do_handshake() call.
    //
    // For CH+SH: the stored hash from PUFFIN_store_ch_sh_transcript is used
    // (captured at the exact right point by the BoringSSL patch).
    // For other messages: extract the current transcript hash.

    // BoringSSL fires msg_callback BEFORE updating hs->transcript (see
    // s3_both.cc: ssl_do_msg_callback is called before transcript.Update).
    // So we must include the current message in the hash ourselves.

#define ENQUEUE_CLAIM(agent, ctype)                                                                \
    do                                                                                             \
    {                                                                                              \
        if ((agent)->claimQueueLen < CLAIM_QUEUE_SIZE)                                             \
        {                                                                                          \
            int _idx = (agent)->claimQueueLen++;                                                   \
            (agent)->claimQueue[_idx].type = (ctype);                                              \
            (agent)->claimQueue[_idx].transcript_len = boringssl_extract_transcript_with_msg(      \
                (agent)->ssl,                                                                      \
                (const uint8_t *)buf,                                                              \
                len,                                                                               \
                (agent)->claimQueue[_idx].transcript,                                              \
                sizeof((agent)->claimQueue[_idx].transcript));                                     \
        }                                                                                          \
    } while (0)

#define ENQUEUE_CLAIM_WITH_STORED_TRANSCRIPT(agent, ctype)                                         \
    do                                                                                             \
    {                                                                                              \
        if ((agent)->claimQueueLen < CLAIM_QUEUE_SIZE)                                             \
        {                                                                                          \
            int _idx = (agent)->claimQueueLen++;                                                   \
            (agent)->claimQueue[_idx].type = (ctype);                                              \
            if ((agent)->stored_ch_sh_transcript_len > 0)                                          \
            {                                                                                      \
                (agent)->claimQueue[_idx].transcript_len =                                         \
                    (int)(agent)->stored_ch_sh_transcript_len;                                     \
                memcpy((agent)->claimQueue[_idx].transcript,                                       \
                       (agent)->stored_ch_sh_transcript,                                           \
                       (agent)->stored_ch_sh_transcript_len);                                      \
            }                                                                                      \
            else                                                                                   \
            {                                                                                      \
                (agent)->claimQueue[_idx].transcript_len = boringssl_extract_transcript_with_msg(  \
                    (agent)->ssl,                                                                  \
                    (const uint8_t *)buf,                                                          \
                    len,                                                                           \
                    (agent)->claimQueue[_idx].transcript,                                          \
                    sizeof((agent)->claimQueue[_idx].transcript));                                 \
            }                                                                                      \
        }                                                                                          \
    } while (0)

    if (write_p == 0) // message being read (received from peer)
    {
        switch (msg_type)
        {
        case SSL3_MT_SERVER_HELLO:
            // CH+SH transcript — use stored value from PUFFIN patch if available
            ENQUEUE_CLAIM_WITH_STORED_TRANSCRIPT(agent, CLAIM_TRANSCRIPT_CH_SH);
            break;
        case SSL3_MT_CERTIFICATE:
            // Only track server Certificate (when we're the client reading it)
            if (agent->descriptor.role == CLIENT)
            {
                ENQUEUE_CLAIM(agent, CLAIM_TRANSCRIPT_CH_CERT);
            }
            break;
        case SSL3_MT_FINISHED: // Finished from peer
            // Extract CH+SH transcript and handshake secret from BoringSSL patch.
            if (agent->stored_ch_sh_transcript_len == 0)
            {
                boringssl_extract_ch_sh_and_secrets(agent);
            }
            if (agent->descriptor.role == CLIENT)
            {
                ENQUEUE_CLAIM(agent, CLAIM_TRANSCRIPT_CH_SERVER_FIN);
            }
            else
            {
                ENQUEUE_CLAIM(agent, CLAIM_TRANSCRIPT_CH_CLIENT_FIN);
            }
            break;
        default:
            break;
        }
    }
    else // write_p == 1, message being sent
    {
        switch (msg_type)
        {
        case SSL3_MT_SERVER_HELLO:
            // Server sending ServerHello — use stored transcript
            ENQUEUE_CLAIM_WITH_STORED_TRANSCRIPT(agent, CLAIM_TRANSCRIPT_CH_SH);
            break;
        case SSL3_MT_FINISHED: // Finished outbound
            // Extract CH+SH transcript and handshake secret if not done yet.
            if (agent->stored_ch_sh_transcript_len == 0)
            {
                boringssl_extract_ch_sh_and_secrets(agent);
            }
            if (agent->descriptor.role == SERVER)
            {
                ENQUEUE_CLAIM(agent, CLAIM_TRANSCRIPT_CH_SERVER_FIN);
            }
            else
            {
                ENQUEUE_CLAIM(agent, CLAIM_TRANSCRIPT_CH_CLIENT_FIN);
            }
            // Snapshot TLS 1.3 secrets while hs is still alive
            if (!agent->secrets_snapped)
            {
                boringssl_snapshot_secrets(agent);
            }
            break;
        default:
            break;
        }
    }

#undef ENQUEUE_CLAIM
#undef ENQUEUE_CLAIM_WITH_STORED_TRANSCRIPT
}

// ---------------------------------------------------------------------------
// Agent creation
// ---------------------------------------------------------------------------

static SSL_CTX *configure_common(const TLS_AGENT_DESCRIPTOR *descriptor)
{
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_method());
    if (!ssl_ctx)
    {
        return NULL;
    }

    boringssl_set_protocol_version(ssl_ctx, descriptor->tls_version);

    // Cipher configuration.
    // BoringSSL's SSL_CTX_set_cipher_list tolerates unknown names (silently
    // ignores them).  TLS 1.3 ciphers in BoringSSL are always enabled and
    // cannot be individually disabled, so we only configure TLS 1.2 ciphers
    // here.  Both cipher_string_tls12 and cipher_string_tls13 may contain
    // IANA names which BoringSSL recognises.
    if (descriptor->cipher_string_tls12 != NULL)
    {
        SSL_CTX_set_cipher_list(ssl_ctx, descriptor->cipher_string_tls12);
    }

    // Groups / curves
    if (descriptor->group_list != NULL)
    {
        SSL_CTX_set1_groups_list(ssl_ctx, descriptor->group_list);
    }
    else
    {
        SSL_CTX_set1_groups_list(ssl_ctx, "X25519:P-256:P-384");
    }

    // Signature algorithms
    if (descriptor->sigalgs_list != NULL)
    {
        SSL_CTX_set1_sigalgs_list(ssl_ctx, descriptor->sigalgs_list);
    }

    return ssl_ctx;
}

AGENT boringssl_create(const TLS_AGENT_DESCRIPTOR *descriptor)
{
    if (descriptor->role == CLIENT)
    {
        return boringssl_create_client(descriptor);
    }
    if (descriptor->role == SERVER)
    {
        return boringssl_create_server(descriptor);
    }
    return NULL;
}

static AGENT boringssl_create_client(const TLS_AGENT_DESCRIPTOR *descriptor)
{
    SSL_CTX *ssl_ctx = configure_common(descriptor);
    if (!ssl_ctx)
    {
        return NULL;
    }

    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);

    if (descriptor->client_authentication)
    {
        ssl_ctx = set_cert(ssl_ctx, descriptor->cert);
        ssl_ctx = set_pkey(ssl_ctx, descriptor->pkey);
        if (ssl_ctx == NULL)
        {
            return NULL;
        }
    }

    if (descriptor->server_authentication)
    {
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        ssl_ctx = set_store(ssl_ctx, descriptor->store, descriptor->store_length);
        if (ssl_ctx == NULL)
        {
            return NULL;
        }
    }

    AGENT agent = make_agent(ssl_ctx, descriptor);
    if (agent == NULL)
    {
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    SSL_set_connect_state(agent->ssl);
    return agent;
}

static AGENT boringssl_create_server(const TLS_AGENT_DESCRIPTOR *descriptor)
{
    SSL_CTX *ssl_ctx = configure_common(descriptor);
    if (!ssl_ctx)
    {
        return NULL;
    }

    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);

    ssl_ctx = set_cert(ssl_ctx, descriptor->cert);
    ssl_ctx = set_pkey(ssl_ctx, descriptor->pkey);
    if (ssl_ctx == NULL)
    {
        return NULL;
    }

    if (descriptor->client_authentication)
    {
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        ssl_ctx = set_store(ssl_ctx, descriptor->store, descriptor->store_length);
        if (ssl_ctx == NULL)
        {
            return NULL;
        }
    }

    AGENT agent = make_agent(ssl_ctx, descriptor);
    if (agent == NULL)
    {
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    SSL_set_accept_state(agent->ssl);
    return agent;
}

// ---------------------------------------------------------------------------
// Agent lifecycle helpers
// ---------------------------------------------------------------------------

static AGENT make_agent(SSL_CTX *ssl_ctx, const TLS_AGENT_DESCRIPTOR *descriptor)
{
    AGENT agent = calloc(1, sizeof(struct AGENT_TYPE));
    if (!agent)
    {
        return NULL;
    }

    agent->name = descriptor->name;
    memcpy(&agent->descriptor, descriptor, sizeof(TLS_AGENT_DESCRIPTOR));
    agent->claimer = &DEFAULT_CLAIMER_CB;
    agent->claimQueueLen = 0;
    agent->has_cached_server_random = false;
    agent->has_cached_client_random = false;
    agent->stored_ch_sh_transcript_len = 0;
    agent->stored_handshake_secret_len = 0;
    agent->secrets_snapped = false;

    agent->ctx = ssl_ctx;
    agent->ssl = SSL_new(agent->ctx);
    if (!agent->ssl)
    {
        free(agent);
        return NULL;
    }

    agent->in = BIO_new(BIO_s_mem());
    agent->out = BIO_new(BIO_s_mem());
    SSL_set_bio(agent->ssl, agent->in, agent->out);
    setup_msg_callback(agent);

    // Store the agent pointer in SSL ex_data so PUFFIN_store_ch_sh_transcript
    // can reach it from within BoringSSL internals.
    boringssl_set_agent_for_ssl(agent->ssl, agent);

    return agent;
}

static void setup_msg_callback(AGENT agent)
{
    SSL_set_msg_callback(agent->ssl, boringssl_msg_callback);
    SSL_set_msg_callback_arg(agent->ssl, agent);
}

void boringssl_destroy(AGENT agent)
{
    if (!agent)
    {
        return;
    }
    if (agent->claimer != NULL && agent->claimer != &DEFAULT_CLAIMER_CB)
    {
        agent->claimer->destroy(agent->claimer->context);
        free((void *)agent->claimer);
    }
    if (agent->ssl)
    {
        SSL_free(agent->ssl);
    }
    if (agent->ctx)
    {
        SSL_CTX_free(agent->ctx);
    }
    free(agent);
}

// ---------------------------------------------------------------------------
// Progress — drives handshake and flushes deferred claims
// ---------------------------------------------------------------------------

RESULT boringssl_progress(AGENT agent)
{
    RESULT result;

    if (!boringssl_is_successful(agent))
    {
        int ret = SSL_do_handshake(agent->ssl);
        result = get_result(agent, ret, true);
    }
    else
    {
        uint8_t buf[128];
        int ret = SSL_read(agent->ssl, &buf, sizeof(buf));
        if (ret > 0)
        {
            result = get_result(agent, SSL_ERROR_NONE, false);
        }
        else
        {
            result = get_result(agent, ret, true);
        }
    }

    // Flush deferred claim queue.
    // Claims are emitted here (after SSL_do_handshake returns) when the
    // SSL state is stable enough for fill_claim to read.
    if (agent->claimer != NULL && agent->claimer->notify != NULL && agent->claimQueueLen > 0)
    {
        for (int i = 0; i < agent->claimQueueLen; i++)
        {
            enum ClaimType ct = agent->claimQueue[i].type;
            int tlen = agent->claimQueue[i].transcript_len;

            // For Finished-related transcripts, emit a standalone CLAIM_FINISHED first.
            // This is critical: decryption recipes look for CLAIM_FINISHED to extract
            // secrets (handshake_secret, master_secret, randoms, cipher).
            if (ct == CLAIM_TRANSCRIPT_CH_CLIENT_FIN || ct == CLAIM_TRANSCRIPT_CH_SERVER_FIN)
            {
                struct Claim claim = {};
                claim.typ = CLAIM_FINISHED;
                boringssl_fill_claim(agent, &claim);
                if (tlen > 0)
                {
                    memcpy(claim.transcript.data, agent->claimQueue[i].transcript, tlen);
                    claim.transcript.length = tlen;
                }
                agent->claimer->notify(agent->claimer->context, &claim);
            }

            // Emit the transcript claim itself.
            struct Claim claim = {};
            claim.typ = ct;
            boringssl_fill_claim(agent, &claim);
            if (tlen > 0)
            {
                memcpy(claim.transcript.data, agent->claimQueue[i].transcript, tlen);
                claim.transcript.length = tlen;
            }
            agent->claimer->notify(agent->claimer->context, &claim);
        }
        agent->claimQueueLen = 0;
    }

    return result;
}

// ---------------------------------------------------------------------------
// Reset
// ---------------------------------------------------------------------------

RESULT boringssl_reset(AGENT agent, uint8_t new_name, uint8_t use_clear)
{
    agent->name = new_name;
    agent->descriptor.name = new_name;
    agent->claimQueueLen = 0;
    agent->has_cached_server_random = false;
    agent->has_cached_client_random = false;
    agent->stored_ch_sh_transcript_len = 0;
    agent->stored_handshake_secret_len = 0;
    agent->secrets_snapped = false;

    if (use_clear)
    {
        int ret = SSL_clear(agent->ssl);
        if (ret == 0)
        {
            return get_result(agent, SSL_ERROR_SSL, false);
        }
    }
    else
    {
        if (!recreate_ssl_from_agent_ctx(agent))
        {
            return PUFFIN.make_result(RESULT_ERROR_OTHER, "failed to recreate SSL state");
        }
    }

    return PUFFIN.make_result(RESULT_OK, NULL);
}

static bool recreate_ssl_from_agent_ctx(AGENT agent)
{
    SSL_free(agent->ssl);
    agent->ssl = NULL;
    agent->in = NULL;
    agent->out = NULL;

    agent->ssl = SSL_new(agent->ctx);
    if (!agent->ssl)
    {
        return false;
    }
    agent->in = BIO_new(BIO_s_mem());
    agent->out = BIO_new(BIO_s_mem());
    SSL_set_bio(agent->ssl, agent->in, agent->out);
    setup_msg_callback(agent);

    agent->claimQueueLen = 0;
    agent->has_cached_server_random = false;
    agent->has_cached_client_random = false;
    agent->stored_ch_sh_transcript_len = 0;
    agent->stored_handshake_secret_len = 0;
    agent->secrets_snapped = false;

    boringssl_set_agent_for_ssl(agent->ssl, agent);

    if (agent->descriptor.role == SERVER)
    {
        SSL_set_accept_state(agent->ssl);
    }
    else
    {
        SSL_set_connect_state(agent->ssl);
    }

    return true;
}

// ---------------------------------------------------------------------------
// State queries
// ---------------------------------------------------------------------------

bool boringssl_is_successful(AGENT agent)
{
    return !SSL_in_init(agent->ssl);
}

const char *boringssl_describe_state(AGENT agent)
{
    return SSL_state_string_long(agent->ssl);
}

// ---------------------------------------------------------------------------
// I/O
// ---------------------------------------------------------------------------

RESULT boringssl_add_inbound(AGENT agent, const uint8_t *bytes, size_t length, size_t *written)
{
    int ret = BIO_write(agent->in, bytes, length);
    if (ret <= 0)
    {
        *written = 0;
        return PUFFIN.make_result(RESULT_OK, NULL);
    }
    *written = ret;
    return PUFFIN.make_result(RESULT_OK, NULL);
}

RESULT boringssl_take_outbound(AGENT agent, uint8_t *bytes, size_t max_length, size_t *readbytes)
{
    int ret = BIO_read(agent->out, bytes, max_length);
    if (ret <= 0)
    {
        *readbytes = 0;
        return PUFFIN.make_result(RESULT_OK, NULL);
    }
    *readbytes = ret;
    return PUFFIN.make_result(RESULT_OK, NULL);
}

// ---------------------------------------------------------------------------
// Claimer registration
// ---------------------------------------------------------------------------

void boringssl_register_claimer(AGENT agent, const CLAIMER_CB *claimer)
{
    if (agent->claimer != NULL && agent->claimer != &DEFAULT_CLAIMER_CB)
    {
        agent->claimer->destroy(agent->claimer->context);
        free((void *)agent->claimer);
    }

    if (claimer != NULL)
    {
        // Copy the CLAIMER_CB — the caller's struct may be stack-allocated.
        CLAIMER_CB *new_claimer = malloc(sizeof(CLAIMER_CB));
        memcpy(new_claimer, claimer, sizeof(CLAIMER_CB));
        agent->claimer = new_claimer;
    }
    else
    {
        agent->claimer = &DEFAULT_CLAIMER_CB;
    }
}

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

static RESULT get_result(AGENT agent, int retcode, bool allow_would_block)
{
    int err = SSL_get_error(agent->ssl, retcode);
    if (retcode > 0 || err == SSL_ERROR_NONE)
    {
        return PUFFIN.make_result(RESULT_OK, NULL);
    }

    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE ||
        err == SSL_ERROR_WANT_CONNECT || err == SSL_ERROR_WANT_ACCEPT ||
        err == SSL_ERROR_WANT_X509_LOOKUP)
    {
        if (allow_would_block)
        {
            return PUFFIN.make_result(RESULT_OK, NULL);
        }
        return PUFFIN.make_result(RESULT_IO_WOULD_BLOCK, NULL);
    }

    char *reason = get_error_reason();
    RESULT result = PUFFIN.make_result(RESULT_ERROR_OTHER, reason);
    free(reason);
    return result;
}

// ---------------------------------------------------------------------------
// Protocol version configuration
// ---------------------------------------------------------------------------

static void boringssl_set_protocol_version(SSL_CTX *ssl_ctx, TLS_VERSION version)
{
    switch (version)
    {
    case V1_3:
        SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
        SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);
        break;
    case V1_2:
        SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_2_VERSION);
        break;
    case Both:
        SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);
        break;
    }
}

// ---------------------------------------------------------------------------
// Accessor functions for claims.cc (C++ cannot see struct AGENT_TYPE)
// ---------------------------------------------------------------------------

SSL *boringssl_agent_get_ssl(void *agent_opaque)
{
    AGENT agent = (AGENT)agent_opaque;
    return agent ? agent->ssl : NULL;
}

void boringssl_agent_set_ch_sh_transcript(void *agent_opaque, const uint8_t *hash, size_t hash_len)
{
    AGENT agent = (AGENT)agent_opaque;
    if (agent == NULL)
    {
        return;
    }
    agent->stored_ch_sh_transcript_len = MIN(hash_len, sizeof(agent->stored_ch_sh_transcript));
    memcpy(agent->stored_ch_sh_transcript, hash, agent->stored_ch_sh_transcript_len);
}

void boringssl_agent_set_handshake_secret(void *agent_opaque, const uint8_t *data, size_t len)
{
    AGENT agent = (AGENT)agent_opaque;
    if (agent == NULL)
    {
        return;
    }
    agent->stored_handshake_secret_len = MIN(len, sizeof(agent->stored_handshake_secret));
    memcpy(agent->stored_handshake_secret, data, agent->stored_handshake_secret_len);
}

void boringssl_agent_get_stored_handshake_secret(void *agent_opaque,
                                                 const uint8_t **out,
                                                 size_t *out_len)
{
    AGENT agent = (AGENT)agent_opaque;
    if (agent == NULL || agent->stored_handshake_secret_len == 0)
    {
        *out = NULL;
        *out_len = 0;
        return;
    }
    *out = agent->stored_handshake_secret;
    *out_len = agent->stored_handshake_secret_len;
}

void boringssl_agent_get_cached_client_random(void *agent_opaque,
                                              const uint8_t **out,
                                              size_t *out_len)
{
    AGENT agent = (AGENT)agent_opaque;
    if (agent == NULL || !agent->has_cached_client_random)
    {
        *out = NULL;
        *out_len = 0;
        return;
    }
    *out = agent->cached_client_random;
    *out_len = SSL3_RANDOM_SIZE;
}

void boringssl_agent_get_cached_server_random(void *agent_opaque,
                                              const uint8_t **out,
                                              size_t *out_len)
{
    AGENT agent = (AGENT)agent_opaque;
    if (agent == NULL || !agent->has_cached_server_random)
    {
        *out = NULL;
        *out_len = 0;
        return;
    }
    *out = agent->cached_server_random;
    *out_len = SSL3_RANDOM_SIZE;
}

void boringssl_agent_fixup_ch_sh_transcript(void *agent_opaque,
                                            const uint8_t *hash,
                                            size_t hash_len)
{
    AGENT agent = (AGENT)agent_opaque;
    if (agent == NULL)
    {
        return;
    }
    for (int i = 0; i < agent->claimQueueLen; i++)
    {
        if (agent->claimQueue[i].type == CLAIM_TRANSCRIPT_CH_SH)
        {
            size_t copy_len = MIN(hash_len, sizeof(agent->claimQueue[i].transcript));
            memcpy(agent->claimQueue[i].transcript, hash, copy_len);
            agent->claimQueue[i].transcript_len = (int)copy_len;
        }
    }
}

void boringssl_agent_store_snapped_secrets(void *agent_opaque, const SnappedTLS13Secrets *secrets)
{
    AGENT agent = (AGENT)agent_opaque;
    if (agent == NULL || secrets == NULL)
    {
        return;
    }
    memcpy(&agent->snapped_secrets, secrets, sizeof(SnappedTLS13Secrets));
    agent->secrets_snapped = true;
}

bool boringssl_agent_get_snapped_secrets(void *agent_opaque, SnappedTLS13Secrets *out)
{
    AGENT agent = (AGENT)agent_opaque;
    if (agent == NULL || !agent->secrets_snapped || out == NULL)
    {
        return false;
    }
    memcpy(out, &agent->snapped_secrets, sizeof(SnappedTLS13Secrets));
    return true;
}
