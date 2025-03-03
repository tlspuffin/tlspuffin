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

extern const TLS_PUT_INTERFACE *REGISTER();

struct AGENT_TYPE
{
    uint8_t name;

    SSL *ssl;

    BIO *in;
    BIO *out;

    const CLAIMER_CB *claimer;
};

AGENT openssl_create(const TLS_AGENT_DESCRIPTOR *descriptor);
AGENT openssl_create_client(const TLS_AGENT_DESCRIPTOR *descriptor);
AGENT openssl_create_server(const TLS_AGENT_DESCRIPTOR *descriptor);
void openssl_destroy(AGENT agent);
RESULT openssl_progress(AGENT agent);
RESULT openssl_reset(AGENT agent, uint8_t new_name);
bool openssl_is_successful(AGENT agent);
const char *openssl_describe_state(AGENT agent);
bool openssl_is_successful(AGENT agent);
RESULT openssl_add_inbound(AGENT agent, const uint8_t *bytes, size_t length, size_t *written);
RESULT openssl_take_outbound(AGENT agent, uint8_t *bytes, size_t max_length, size_t *readbytes);
void openssl_register_claimer(AGENT agent, const CLAIMER_CB *claimer);

static RESULT get_result(AGENT agent, int retcode, bool allow_would_block);

static AGENT make_agent(SSL_CTX *ssl_ctx, const TLS_AGENT_DESCRIPTOR *descriptor);

static void default_claimer_notify(void *context, Claim *claim)
{
    _log(PUFFIN.trace, "call to default claimer `notify`");
};

static void default_claimer_destroy(void *context)
{
    _log(PUFFIN.trace, "call to default claimer `destroy`");
};

static const CLAIMER_CB DEFAULT_CLAIMER_CB = {.context = NULL,
                                              .notify = default_claimer_notify,
                                              .destroy = default_claimer_destroy};

static const TLS_PUT_INTERFACE OPENSSL_PUT = {
    .create = openssl_create,
    .rng_reseed = NULL,
    .supports = NULL,

    .agent_interface =
        {
            .destroy = openssl_destroy,
            .progress = openssl_progress,
            .reset = openssl_reset,
            .describe_state = openssl_describe_state,
            .is_state_successful = openssl_is_successful,
            .register_claimer = openssl_register_claimer,

            .add_inbound = openssl_add_inbound,
            .take_outbound = openssl_take_outbound,
        },
};

const TLS_PUT_INTERFACE *REGISTER()
{
    openssl_init();

    return &OPENSSL_PUT;
}

const int tls_version[] = {TLS1_3_VERSION, TLS1_2_VERSION};
const char *version_str[] = {"V1_3", "V1_2"};
const char *type_str[] = {"client", "server"};

AGENT openssl_create(const TLS_AGENT_DESCRIPTOR *descriptor)
{
    _log(PUFFIN.info,
         "descriptor %u version: %s type: %s",
         descriptor->name,
         version_str[descriptor->tls_version],
         type_str[descriptor->role]);

    if (tls_version[descriptor->tls_version] == TLS_UNSUPPORTED_VERSION)
    {
        _log(PUFFIN.error, "unsupported TLS version: %s", version_str[descriptor->tls_version]);
        return NULL;
    }

    if (descriptor->role == CLIENT)
    {
        return openssl_create_client(descriptor);
    }

    if (descriptor->role == SERVER)
    {
        return openssl_create_server(descriptor);
    }

    _log(PUFFIN.error,
         "unknown agent type for descriptor %u: %u",
         descriptor->name,
         descriptor->role);
    return NULL;
}

void openssl_destroy(AGENT agent)
{
    if (agent->claimer != NULL)
    {
        agent->claimer->destroy(agent->claimer->context);
    }

    SSL_free(agent->ssl);
    free(agent);
}

RESULT openssl_progress(AGENT agent)
{
    if (!openssl_is_successful(agent))
    {
        // not connected yet -> do handshake
        int ret = SSL_do_handshake(agent->ssl);

        return get_result(agent, ret, true);
    }

    // trigger another read
    uint8_t buf[128];
    int ret = SSL_read(agent->ssl, &buf, 128);
    if (ret > 0)
    {
        return get_result(agent, SSL_ERROR_NONE, false);
    }

    return get_result(agent, ret, true);
}

RESULT openssl_reset(AGENT agent, uint8_t new_name)
{
    agent->name = new_name;

    openssl_register_claimer(agent, &DEFAULT_CLAIMER_CB);

    int ret = SSL_clear(agent->ssl);
    if (ret == 0)
    {
        return get_result(agent, SSL_ERROR_SSL, false);
    }

    return get_result(agent, SSL_ERROR_NONE, false);
}

const char *openssl_describe_state(AGENT agent)
{
    // NOTE: Very useful for nonblocking according to docs:
    //     https://www.openssl.org/docs/manmaster/man3/SSL_state_string.html
    //
    //     When using nonblocking sockets, the function call performing the
    //     handshake may return with SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE
    //     condition, so that SSL_state_string[_long]() may be called.
    return SSL_state_string_long(agent->ssl);
}

bool openssl_is_successful(AGENT agent)
{
    return (strstr(openssl_describe_state(agent), "SSL negotiation finished successfully") != NULL);
}

#ifdef HAS_CLAIMS
void _inner_claimer(Claim claim, void *ctx)
{
    AGENT agent = (AGENT)(ctx);
    agent->claimer->notify(agent->claimer->context, &claim);
}
#endif

void openssl_register_claimer(AGENT agent, const CLAIMER_CB *claimer)
{
    if (agent->claimer != NULL)
    {
        agent->claimer->destroy(agent->claimer->context);
    }

    CLAIMER_CB *new_claimer = malloc(sizeof(CLAIMER_CB));
    memcpy(new_claimer, claimer, sizeof(CLAIMER_CB));
    agent->claimer = new_claimer;

#ifdef HAS_CLAIMS
    register_claimer(agent->ssl, _inner_claimer, agent);
#endif
}

RESULT openssl_add_inbound(AGENT agent, const uint8_t *bytes, size_t length, size_t *written)
{
    int ret = BIO_write_ex(agent->in, bytes, length, written);

    return get_result(agent, ret, false);
}

RESULT openssl_take_outbound(AGENT agent, uint8_t *bytes, size_t max_length, size_t *readbytes)
{
    int ret = BIO_read_ex(agent->out, bytes, max_length, readbytes);

    return get_result(agent, ret, false);
}

AGENT openssl_create_client(const TLS_AGENT_DESCRIPTOR *descriptor)
{
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_method());

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
    // Not sure whether we want this disabled or enabled:
    // https://github.com/tlspuffin/tlspuffin/issues/67 The tests become simpler if disabled to
    // maybe that's what we want. Lets leave it default for now.
    // https://wiki.openssl.org/index.php/TLS1.3#Middlebox_Compatibility_Mode
    SSL_CTX_clear_options(ssl_ctx, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    SSL_CTX_set_max_proto_version(ssl_ctx, tls_version[descriptor->tls_version]);
#endif

    // Disallow EXPORT in client
    SSL_CTX_set_cipher_list(ssl_ctx, descriptor->cipher_string);
    SSL_CTX_set_ciphersuites(ssl_ctx, descriptor->cipher_string);

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
        return NULL;
    }

    SSL_set_connect_state(agent->ssl);

    return agent;
}

AGENT openssl_create_server(const TLS_AGENT_DESCRIPTOR *descriptor)
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
    SSL_CTX_set_cipher_list(ssl_ctx, descriptor->cipher_string);
    SSL_CTX_set_ciphersuites(ssl_ctx, descriptor->cipher_string);

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
        return NULL;
    }

    SSL_set_accept_state(agent->ssl);

    return agent;
}

static AGENT make_agent(SSL_CTX *ssl_ctx, const TLS_AGENT_DESCRIPTOR *descriptor)
{
    SSL *ssl = SSL_new(ssl_ctx);

    AGENT agent = malloc(sizeof(struct AGENT_TYPE));
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

static RESULT get_result(AGENT agent, int retcode, bool allow_would_block)
{
    int ssl_ecode = SSL_get_error(agent->ssl, retcode);

    char *reason = get_error_reason();
    char *error_type;
    RESULT_CODE res = RESULT_OK;

    switch (ssl_ecode)
    {
    case SSL_ERROR_NONE:
        error_type = strdup("no error");
        break;
    case SSL_ERROR_ZERO_RETURN:
        error_type = strdup("SSL_ERROR_ZERO_RETURN");
        break;
    case SSL_ERROR_WANT_CONNECT:
        error_type = strdup("SSL_ERROR_WANT_CONNECT");
        break;
    case SSL_ERROR_WANT_ACCEPT:
        error_type = strdup("SSL_ERROR_WANT_ACCEPT");
        break;
    case SSL_ERROR_WANT_X509_LOOKUP:
        error_type = strdup("SSL_ERROR_WANT_X509_LOOKUP");
        break;
    case SSL_ERROR_WANT_ASYNC:
        error_type = strdup("SSL_ERROR_WANT_ASYNC");
        break;
    case SSL_ERROR_WANT_ASYNC_JOB:
        error_type = strdup("SSL_ERROR_WANT_ASYNC_JOB");
        break;
    case SSL_ERROR_WANT_CLIENT_HELLO_CB:
        error_type = strdup("SSL_ERROR_WANT_CLIENT_HELLO_CB");
        break;
    case SSL_ERROR_SYSCALL:
        error_type = strdup("SSL_ERROR_SYSCALL");
        break;
    case SSL_ERROR_SSL:
        error_type = strdup("SSL_ERROR_SSL");
        res = RESULT_ERROR_OTHER;
        break;
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
        error_type = strdup("IO_WOULD_BLOCK");
        if (!allow_would_block)
        {
            res = RESULT_IO_WOULD_BLOCK;
        }
        break;
    default:
        error_type = malloc(32 * sizeof(char));
        snprintf(error_type, sizeof(error_type), "UNKNOWN SSL ERROR %d", ssl_ecode);
        res = RESULT_ERROR_OTHER;
    }

    char *msg;
    if (strlen(reason) > 0)
    {
        msg = malloc((strlen(error_type) + strlen(reason) + 3) * sizeof(char));
        snprintf(msg, strlen(error_type) + strlen(reason) + 3, "%s: %s", error_type, reason);
    }
    else
    {
        msg = malloc((strlen(error_type) + 13) * sizeof(char));
        snprintf(msg, strlen(error_type) + 13, "%s: no message", error_type);
    }
    RESULT result = PUFFIN.make_result(res, msg);
    free(reason);
    free(msg);
    free(error_type);
    return result;
}
