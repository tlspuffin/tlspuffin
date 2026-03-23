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
#include <claim-interface.h>
#include <puffin/tls.h>
#include "bindings.h"
#include "rng.h"
#include "claims.h"

extern const TLS_PUT_INTERFACE *REGISTER();

struct AGENT_TYPE
{
    uint8_t name;
    TLS_AGENT_DESCRIPTOR descriptor;
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *in;
    BIO *out;
    CLAIMER_CB claimer;
};

AGENT boringssl_create(const TLS_AGENT_DESCRIPTOR *descriptor);
AGENT boringssl_create_client(const TLS_AGENT_DESCRIPTOR *descriptor);
AGENT boringssl_create_server(const TLS_AGENT_DESCRIPTOR *descriptor);
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
static void boringssl_set_protocol_version(SSL_CTX *ssl_ctx, TLS_VERSION version);
static bool boringssl_set_cipher_preferences(SSL_CTX *ssl_ctx, const TLS_AGENT_DESCRIPTOR *descriptor);

static void default_claimer_notify(void *context, Claim *claim) {}
static void default_claimer_destroy(void *context) {}

static const CLAIMER_CB DEFAULT_CLAIMER_CB = {
    .context = NULL,
    .notify = default_claimer_notify,
    .destroy = default_claimer_destroy
};

static const TLS_PUT_INTERFACE BORINGSSL_PUT = {
    .create = boringssl_create,
    .rng_reseed = rng_reseed,
    .supports = NULL,
    .agent_interface = {
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

static ClaimType map_handshake_type(uint8_t type) {
    switch (type) {
        case SSL3_MT_CLIENT_HELLO: return CLAIM_CLIENT_HELLO;
        case SSL3_MT_SERVER_HELLO: return CLAIM_SERVER_HELLO;
        case SSL3_MT_CERTIFICATE: return CLAIM_CERTIFICATE;
        case SSL3_MT_SERVER_KEY_EXCHANGE: return CLAIM_KEY_EXCHANGE;
        case SSL3_MT_CERTIFICATE_REQUEST: return CLAIM_CERTIFICATE_REQUEST;
        case SSL3_MT_SERVER_DONE: return CLAIM_SERVER_DONE;
        case SSL3_MT_CERTIFICATE_VERIFY: return CLAIM_CERTIFICATE_VERIFY;
        case SSL3_MT_CLIENT_KEY_EXCHANGE: return CLAIM_KEY_EXCHANGE;
        case SSL3_MT_FINISHED: return CLAIM_FINISHED;
        case SSL3_MT_ENCRYPTED_EXTENSIONS: return CLAIM_ENCRYPTED_EXTENSIONS;
        case SSL3_MT_NEW_SESSION_TICKET: return CLAIM_SESSION_TICKET;
        case SSL3_MT_KEY_UPDATE: return CLAIM_KEY_UPDATE;
        case SSL3_MT_END_OF_EARLY_DATA: return CLAIM_END_OF_EARLY_DATA;
        default: return CLAIM_UNKNOWN;
    }
}

static void boringssl_message_callback(int write_p, int version, int content_type,
                                       const void *buf, size_t len, SSL *ssl,
                                       void *arg)
{
    AGENT agent = (AGENT)arg;
    if (!agent || !agent->claimer.notify) return;

    if (content_type == SSL3_RT_HANDSHAKE && len > 0) {
        uint8_t msg_type = ((const uint8_t*)buf)[0];
        bool sender_is_server = write_p ? SSL_is_server(ssl) : !SSL_is_server(ssl);

        Claim claim;
        boringssl_fill_claim(ssl, &claim);
        claim.write = write_p;
        
        // General handshake message claim
        claim.typ = map_handshake_type(msg_type);
        agent->claimer.notify(agent->claimer.context, &claim);

        // Transcript claims (based on message type)
        Claim transcript_claim = claim;
        int append_msg_to_transcript = write_p ? 0 : 1;
        switch (msg_type) {
            case SSL3_MT_CLIENT_HELLO:
                transcript_claim.typ = CLAIM_TRANSCRIPT_CH;
                break;
            case SSL3_MT_SERVER_HELLO:
                transcript_claim.typ = CLAIM_TRANSCRIPT_CH_SH;
                break;
            case SSL3_MT_CERTIFICATE:
                if (!sender_is_server) {
                    return;
                }
                transcript_claim.typ = CLAIM_TRANSCRIPT_CH_CERT;
                break;
            case SSL3_MT_FINISHED:
                if (sender_is_server) {
                    transcript_claim.typ = CLAIM_TRANSCRIPT_CH_SERVER_FIN;
                } else {
                    transcript_claim.typ = CLAIM_TRANSCRIPT_CH_CLIENT_FIN;
                }
                break;
            default:
                return;
        }
        boringssl_fill_claim_for_message(
            ssl,
            &transcript_claim,
            (const uint8_t *)buf,
            len,
            append_msg_to_transcript);
        agent->claimer.notify(agent->claimer.context, &transcript_claim);
    }
}

AGENT boringssl_create(const TLS_AGENT_DESCRIPTOR *descriptor)
{
    if (descriptor->role == CLIENT) {
        return boringssl_create_client(descriptor);
    }
    if (descriptor->role == SERVER) {
        return boringssl_create_server(descriptor);
    }
    return NULL;
}

AGENT boringssl_create_client(const TLS_AGENT_DESCRIPTOR *descriptor)
{
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_method());
    if (!ssl_ctx) {
        return NULL;
    }

    boringssl_set_protocol_version(ssl_ctx, descriptor->tls_version);

    if (!boringssl_set_cipher_preferences(ssl_ctx, descriptor)) {
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    if (descriptor->group_list != NULL) {
        SSL_CTX_set1_groups_list(ssl_ctx, descriptor->group_list);
    } else {
        SSL_CTX_set1_groups_list(ssl_ctx, "X25519:P-256:P-384");
    }

    if (descriptor->sigalgs_list != NULL) {
        SSL_CTX_set1_sigalgs_list(ssl_ctx, descriptor->sigalgs_list);
    }

    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);

    if (descriptor->client_authentication) {
        ssl_ctx = set_cert(ssl_ctx, descriptor->cert);
        ssl_ctx = set_pkey(ssl_ctx, descriptor->pkey);
        if (ssl_ctx == NULL) {
            return NULL;
        }
    }

    if (descriptor->server_authentication) {
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

        ssl_ctx = set_store(ssl_ctx, descriptor->store, descriptor->store_length);
        if (ssl_ctx == NULL) {
            return NULL;
        }
    }

    AGENT agent = make_agent(ssl_ctx, descriptor);
    if (agent == NULL) {
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    SSL_set_connect_state(agent->ssl);
    return agent;
}

AGENT boringssl_create_server(const TLS_AGENT_DESCRIPTOR *descriptor)
{
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_method());
    if (!ssl_ctx) {
        return NULL;
    }

    boringssl_set_protocol_version(ssl_ctx, descriptor->tls_version);

    if (!boringssl_set_cipher_preferences(ssl_ctx, descriptor)) {
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    if (descriptor->group_list != NULL) {
        SSL_CTX_set1_groups_list(ssl_ctx, descriptor->group_list);
    } else {
        SSL_CTX_set1_groups_list(ssl_ctx, "X25519:P-256:P-384");
    }

    if (descriptor->sigalgs_list != NULL) {
        SSL_CTX_set1_sigalgs_list(ssl_ctx, descriptor->sigalgs_list);
    }

    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);

    ssl_ctx = set_cert(ssl_ctx, descriptor->cert);
    ssl_ctx = set_pkey(ssl_ctx, descriptor->pkey);
    if (ssl_ctx == NULL) {
        return NULL;
    }

    if (descriptor->client_authentication) {
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

        ssl_ctx = set_store(ssl_ctx, descriptor->store, descriptor->store_length);
        if (ssl_ctx == NULL) {
            return NULL;
        }
    }

    AGENT agent = make_agent(ssl_ctx, descriptor);
    if (agent == NULL) {
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    SSL_set_accept_state(agent->ssl);
    return agent;
}

static AGENT make_agent(SSL_CTX *ssl_ctx, const TLS_AGENT_DESCRIPTOR *descriptor)
{
    AGENT agent = calloc(1, sizeof(struct AGENT_TYPE));
    if (!agent) {
        return NULL;
    }

    agent->name = descriptor->name;
    memcpy(&agent->descriptor, descriptor, sizeof(TLS_AGENT_DESCRIPTOR));
    memcpy(&agent->claimer, &DEFAULT_CLAIMER_CB, sizeof(CLAIMER_CB));

    agent->ctx = ssl_ctx;
    agent->ssl = SSL_new(agent->ctx);
    if (!agent->ssl) {
        boringssl_destroy(agent);
        return NULL;
    }

    agent->in = BIO_new(BIO_s_mem());
    agent->out = BIO_new(BIO_s_mem());
    SSL_set_bio(agent->ssl, agent->in, agent->out);
    SSL_set_msg_callback(agent->ssl, boringssl_message_callback);
    SSL_set_msg_callback_arg(agent->ssl, agent);

    return agent;
}

void boringssl_destroy(AGENT agent)
{
    if (!agent) return;
    if (agent->claimer.destroy) agent->claimer.destroy(agent->claimer.context);
    if (agent->ssl) {
        boringssl_clear_ch_sh_transcript(agent->ssl);
        SSL_free(agent->ssl);
    }
    if (agent->ctx) SSL_CTX_free(agent->ctx);
    free(agent);
}

RESULT boringssl_progress(AGENT agent)
{
    if (SSL_in_init(agent->ssl)) {
        int ret = SSL_do_handshake(agent->ssl);
        return get_result(agent, ret, true);
    }

    uint8_t buf[128];
    int ret = SSL_read(agent->ssl, &buf, sizeof(buf));
    if (ret > 0) {
        return get_result(agent, SSL_ERROR_NONE, false);
    }
    return get_result(agent, ret, true);
}

RESULT boringssl_reset(AGENT agent, uint8_t new_name, uint8_t use_clear)
{
    agent->name = new_name;
    agent->descriptor.name = new_name;
    
    if (use_clear) {
        boringssl_clear_ch_sh_transcript(agent->ssl);
        int ret = SSL_clear(agent->ssl);
        if (ret == 0) {
            return get_result(agent, SSL_ERROR_SSL, false);
        }
    } else {
        if (!recreate_ssl_from_agent_ctx(agent)) {
            return PUFFIN.make_result(RESULT_ERROR_OTHER, "failed to recreate SSL state");
        }
    }
    
    return PUFFIN.make_result(RESULT_OK, NULL);
}

bool boringssl_is_successful(AGENT agent)
{
    return !SSL_in_init(agent->ssl);
}

const char *boringssl_describe_state(AGENT agent)
{
    return SSL_state_string_long(agent->ssl);
}

RESULT boringssl_add_inbound(AGENT agent, const uint8_t *bytes, size_t length, size_t *written)
{
    int ret = BIO_write(agent->in, bytes, length);
    if (ret <= 0) {
        *written = 0;
        return PUFFIN.make_result(RESULT_OK, NULL);
    }
    *written = ret;
    return PUFFIN.make_result(RESULT_OK, NULL);
}

RESULT boringssl_take_outbound(AGENT agent, uint8_t *bytes, size_t max_length, size_t *readbytes)
{
    int ret = BIO_read(agent->out, bytes, max_length);
    if (ret <= 0) {
        *readbytes = 0;
        if (BIO_should_retry(agent->out)) {
            return PUFFIN.make_result(RESULT_OK, NULL);
        }
        return PUFFIN.make_result(RESULT_OK, NULL);
    }
    *readbytes = ret;
    return PUFFIN.make_result(RESULT_OK, NULL);
}

void boringssl_register_claimer(AGENT agent, const CLAIMER_CB *claimer)
{
    if (agent->claimer.destroy) agent->claimer.destroy(agent->claimer.context);
    if (claimer) {
        memcpy(&agent->claimer, claimer, sizeof(CLAIMER_CB));
    } else {
        memcpy(&agent->claimer, &DEFAULT_CLAIMER_CB, sizeof(CLAIMER_CB));
    }
}

static RESULT get_result(AGENT agent, int retcode, bool allow_would_block)
{
    int err = SSL_get_error(agent->ssl, retcode);
    if (retcode > 0 || err == SSL_ERROR_NONE) {
        return PUFFIN.make_result(RESULT_OK, NULL);
    }

    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE ||
        err == SSL_ERROR_WANT_CONNECT || err == SSL_ERROR_WANT_ACCEPT ||
        err == SSL_ERROR_WANT_X509_LOOKUP) {
        if (allow_would_block) {
            return PUFFIN.make_result(RESULT_OK, NULL);
        }
        return PUFFIN.make_result(RESULT_IO_WOULD_BLOCK, NULL);
    }

    char *reason = get_error_reason();
    RESULT result = PUFFIN.make_result(RESULT_ERROR_OTHER, reason);
    free(reason);
    return result;
}

static bool recreate_ssl_from_agent_ctx(AGENT agent)
{
    boringssl_clear_ch_sh_transcript(agent->ssl);
    SSL_free(agent->ssl);
    agent->ssl = NULL;
    agent->in = NULL;
    agent->out = NULL;

    agent->ssl = SSL_new(agent->ctx);
    if (!agent->ssl) {
        return false;
    }

    agent->in = BIO_new(BIO_s_mem());
    agent->out = BIO_new(BIO_s_mem());
    SSL_set_bio(agent->ssl, agent->in, agent->out);
    SSL_set_msg_callback(agent->ssl, boringssl_message_callback);
    SSL_set_msg_callback_arg(agent->ssl, agent);

    if (agent->descriptor.role == SERVER) {
        SSL_set_accept_state(agent->ssl);
    } else {
        SSL_set_connect_state(agent->ssl);
    }

    return true;
}

static void boringssl_set_protocol_version(SSL_CTX *ssl_ctx, TLS_VERSION version)
{
    switch (version) {
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

static bool boringssl_set_cipher_preferences(SSL_CTX *ssl_ctx, const TLS_AGENT_DESCRIPTOR *descriptor)
{
    if (ssl_ctx == NULL || descriptor == NULL) {
        return false;
    }

    if (descriptor->tls_version == V1_3) {
        if (SSL_CTX_set_strict_cipher_list(ssl_ctx, descriptor->cipher_string_tls13) == 1) {
            return true;
        }
        return SSL_CTX_set_cipher_list(ssl_ctx, descriptor->cipher_string_tls13) == 1;
    }

    if (descriptor->tls_version == V1_2) {
        if (SSL_CTX_set_strict_cipher_list(ssl_ctx, descriptor->cipher_string_tls12) == 1) {
            return true;
        }
        return SSL_CTX_set_cipher_list(ssl_ctx, descriptor->cipher_string_tls12) == 1;
    }

    if (descriptor->tls_version == Both) {
        const char *tls13 = descriptor->cipher_string_tls13;
        const char *tls12 = descriptor->cipher_string_tls12;
        size_t len13 = strlen(tls13);
        size_t len12 = strlen(tls12);
        size_t total_len = len13 + 1 + len12 + 1;

        char *combined = (char *)malloc(total_len);
        if (combined == NULL) {
            return false;
        }

        snprintf(combined, total_len, "%s:%s", tls13, tls12);
        int ok = SSL_CTX_set_strict_cipher_list(ssl_ctx, combined);
        if (ok != 1) {
            ok = SSL_CTX_set_cipher_list(ssl_ctx, combined);
        }
        free(combined);
        return ok == 1;
    }

    return false;
}

