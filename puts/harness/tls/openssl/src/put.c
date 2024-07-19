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
#include <tlspuffin/put.h>

#include "bindings.h"
#include "rng.h"

typedef struct
{
    uint8_t name;

    SSL *ssl;

    BIO *in;
    BIO *out;

    const CLAIMER_CB *claimer;
} AGENT;

void *openssl_create(const AGENT_DESCRIPTOR *descriptor);
void *openssl_create_client(const AGENT_DESCRIPTOR *descriptor);
void *openssl_create_server(const AGENT_DESCRIPTOR *descriptor);
void openssl_destroy(void *agent);
RESULT openssl_progress(void *agent);
RESULT openssl_reset(void *agent, uint8_t new_name);
bool openssl_is_successful(void *agent);
const char *openssl_describe_state(void *agent);
bool openssl_is_successful(void *agent);
RESULT openssl_add_inbound(void *agent, const uint8_t *bytes, size_t length, size_t *written);
RESULT openssl_take_outbound(void *agent, uint8_t *bytes, size_t max_length, size_t *readbytes);
void openssl_register_claimer(void *agent, const CLAIMER_CB *claimer);

static AGENT *as_agent(void *ptr);
static RESULT_CODE result_code(AGENT *agent, int retcode);

static AGENT *make_agent(SSL_CTX *ssl_ctx, const AGENT_DESCRIPTOR *descriptor);

static void default_claimer_notify(void *context, Claim claim)
{
    _log(TLSPUFFIN.trace, "call to default claimer `notify`");
};

static void default_claimer_destroy(void *context)
{
    _log(TLSPUFFIN.trace, "call to default claimer `destroy`");
};

static const CLAIMER_CB DEFAULT_CLAIMER_CB = {.context = NULL,
                                              .notify = default_claimer_notify,
                                              .destroy = default_claimer_destroy};

static C_PUT_INTERFACE OPENSSL_PUT = {
    .create = openssl_create,
    .destroy = openssl_destroy,

    .rng_reseed = rng_reseed,

    .progress = openssl_progress,
    .reset = openssl_reset,
    .describe_state = openssl_describe_state,
    .is_state_successful = openssl_is_successful,

    .register_claimer = openssl_register_claimer,

    .add_inbound = openssl_add_inbound,
    .take_outbound = openssl_take_outbound,
};

void REGISTER()
{
    const char *capabilities[] = {
        "tls12",
        "tls12_session_resumption",
#ifdef HAS_TLS1_3_VERSION
        "tls13",
        "tls13_session_resumption",
#endif
        "deterministic",
        "transcript_extraction",
        "client_authentication_transcript_extraction",
        "openssl_binding",
#ifdef HAS_CLAIMS
        "claims",
#endif
    };

    openssl_init();

    REGISTER_PUT(&OPENSSL_PUT, &capabilities[0], sizeof(capabilities) / sizeof(capabilities[0]));
}

const int tls_version[] = {TLS1_3_VERSION, TLS1_2_VERSION};
const char *version_str[] = {"V1_3", "V1_2"};
const char *type_str[] = {"client", "server"};

void *openssl_create(const AGENT_DESCRIPTOR *descriptor)
{
    _log(TLSPUFFIN.info,
         "descriptor %u version: %s type: %s",
         descriptor->name,
         version_str[descriptor->tls_version],
         type_str[descriptor->type]);

    if (tls_version[descriptor->tls_version] == TLS_UNSUPPORTED_VERSION)
    {
        _log(TLSPUFFIN.error, "unsupported TLS version: %s", version_str[descriptor->tls_version]);
        return NULL;
    }

    if (descriptor->type == CLIENT)
    {
        return openssl_create_client(descriptor);
    }

    if (descriptor->type == SERVER)
    {
        return openssl_create_server(descriptor);
    }

    _log(TLSPUFFIN.error, "unknown agent type for descriptor %u: %u", descriptor->name, descriptor->type);
    return NULL;
}

void openssl_destroy(void *a)
{
    AGENT *agent = as_agent(a);

    agent->claimer->destroy(agent->claimer->context);

    SSL_free(agent->ssl);
    free(agent);
}

RESULT openssl_progress(void *a)
{
    AGENT *agent = as_agent(a);

    if (!openssl_is_successful(agent))
    {
        // not connected yet -> do handshake
        int ret = SSL_do_handshake(agent->ssl);

        RESULT_CODE ecode = result_code(agent, ret);
        if (ecode == RESULT_IO_WOULD_BLOCK)
        {
            ecode = RESULT_OK;
        }

        char *reason = get_error_reason();
        RESULT result = TLSPUFFIN.make_result(ecode, reason);
        free(reason);

        return result;
    }

    // trigger another read
    uint8_t buf[128];
    int ret = SSL_read(agent->ssl, &buf, 128);
    if (ret > 0)
    {
        return TLSPUFFIN.make_result(RESULT_OK, NULL);
    }

    RESULT_CODE ecode = result_code(agent, ret);
    if (ecode == RESULT_IO_WOULD_BLOCK)
    {
        ecode = RESULT_OK;
    }

    char *reason = get_error_reason();
    RESULT result = TLSPUFFIN.make_result(ecode, reason);
    free(reason);

    return result;
}

RESULT openssl_reset(void *a, uint8_t new_name)
{
    AGENT *agent = as_agent(a);
    agent->name = new_name;

    openssl_register_claimer(agent, &DEFAULT_CLAIMER_CB);

    int ret = SSL_clear(agent->ssl);
    if (ret == 0)
    {
        return TLSPUFFIN.make_result(RESULT_ERROR_OTHER, get_error_reason());
    }

    return TLSPUFFIN.make_result(RESULT_OK, NULL);
}

const char *openssl_describe_state(void *a)
{
    AGENT *agent = as_agent(a);

    // NOTE: Very useful for nonblocking according to docs:
    //     https://www.openssl.org/docs/manmaster/man3/SSL_state_string.html
    //
    //     When using nonblocking sockets, the function call performing the
    //     handshake may return with SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE
    //     condition, so that SSL_state_string[_long]() may be called.
    return SSL_state_string_long(agent->ssl);
}

bool openssl_is_successful(void *a)
{
    AGENT *agent = as_agent(a);

    return (strstr(openssl_describe_state(agent), "SSL negotiation finished successfully") != NULL);
}

#ifdef HAS_CLAIMS
void _inner_claimer(Claim claim, void *ctx)
{
    AGENT *agent = as_agent(ctx);
    agent->claimer->notify(agent->claimer->context, claim);
}
#endif

void openssl_register_claimer(void *a, const CLAIMER_CB *claimer)
{
    AGENT *agent = as_agent(a);

    agent->claimer->destroy(agent->claimer->context);
    CLAIMER_CB *new_claimer = malloc(sizeof(CLAIMER_CB));
    memcpy(new_claimer, claimer, sizeof(CLAIMER_CB));
    agent->claimer = new_claimer;

#ifdef HAS_CLAIMS
    register_claimer(agent->ssl, _inner_claimer, agent);
#endif
}

RESULT openssl_add_inbound(void *a, const uint8_t *bytes, size_t length, size_t *written)
{
    AGENT *agent = as_agent(a);

    int ret = BIO_write_ex(agent->in, bytes, length, written);

    RESULT_CODE ecode = result_code(agent, ret);
    char *reason = get_error_reason();
    RESULT result = TLSPUFFIN.make_result(ecode, reason);
    free(reason);

    return result;
}

RESULT openssl_take_outbound(void *a, uint8_t *bytes, size_t max_length, size_t *readbytes)
{
    AGENT *agent = as_agent(a);

    int ret = BIO_read_ex(agent->out, bytes, max_length, readbytes);

    RESULT_CODE ecode = result_code(agent, ret);
    char *reason = get_error_reason();
    RESULT result = TLSPUFFIN.make_result(ecode, reason);
    free(reason);

    return result;
}

void *openssl_create_client(const AGENT_DESCRIPTOR *descriptor)
{
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_method());

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
    // Not sure whether we want this disabled or enabled: https://github.com/tlspuffin/tlspuffin/issues/67
    // The tests become simpler if disabled to maybe that's what we want. Lets leave it default
    // for now.
    // https://wiki.openssl.org/index.php/TLS1.3#Middlebox_Compatibility_Mode
    SSL_CTX_clear_options(ssl_ctx, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    SSL_CTX_set_max_proto_version(ssl_ctx, tls_version[descriptor->tls_version]);
#endif

    // Disallow EXPORT in client
    SSL_CTX_set_cipher_list(ssl_ctx, "ALL:!EXPORT:!LOW:!aNULL:!eNULL:!SSLv2");
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

    AGENT *agent = make_agent(ssl_ctx, descriptor);
    if (agent == NULL)
    {
        return NULL;
    }

    SSL_set_connect_state(agent->ssl);

    return agent;
}

void *openssl_create_server(const AGENT_DESCRIPTOR *descriptor)
{
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_method());

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
    SSL_CTX_set_options(ssl_ctx, SSL_OP_ALLOW_NO_DHE_KEX);
    SSL_CTX_clear_options(ssl_ctx, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    SSL_CTX_set_max_proto_version(ssl_ctx, tls_version[descriptor->tls_version]);
#endif

#if OPENSSL_VERSION_NUMBER > 0x10002000L
    SSL_CTX_set_ecdh_auto(ssl_ctx, 1);
#else
    EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_secp384r1);
    SSL_CTX_set_tmp_ecdh(ssl_ctx, ecdh);
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    RSA *rsa = RSA_generate_key(512, RSA_F4, NULL, NULL);
    SSL_CTX_set_tmp_rsa(ssl_ctx, rsa);
#endif

    // Allow EXPORT in server
    SSL_CTX_set_cipher_list(ssl_ctx, "ALL:EXPORT:!LOW:!aNULL:!eNULL:!SSLv2");
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

    AGENT *agent = make_agent(ssl_ctx, descriptor);
    if (agent == NULL)
    {
        return NULL;
    }

    SSL_set_accept_state(agent->ssl);

    return agent;
}

static AGENT *make_agent(SSL_CTX *ssl_ctx, const AGENT_DESCRIPTOR *descriptor)
{
    SSL *ssl = SSL_new(ssl_ctx);

    AGENT *agent = malloc(sizeof(AGENT));
    agent->name = descriptor->name;
    agent->ssl = ssl;
    agent->in = BIO_new(BIO_s_mem());
    agent->out = BIO_new(BIO_s_mem());

    agent->claimer = &DEFAULT_CLAIMER_CB;
    openssl_register_claimer(agent, &DEFAULT_CLAIMER_CB);

    SSL_set_bio(agent->ssl, agent->in, agent->out);
    SSL_CTX_free(ssl_ctx);

    return agent;
}

static RESULT_CODE result_code(AGENT *agent, int retcode)
{
    int ssl_ecode = SSL_get_error(agent->ssl, retcode);
    switch (ssl_ecode)
    {
    case SSL_ERROR_NONE:
        return RESULT_OK;

    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
        return RESULT_IO_WOULD_BLOCK;
    default:
        return RESULT_ERROR_OTHER;
    }
}

static AGENT *as_agent(void *ptr)
{
    return (AGENT *)ptr;
}
