#include <stdio.h>
#include <stdlib.h>

#include <openssl/decoder.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "put.h"

typedef struct
{
    AGENT_DESCRIPTOR *descriptor;

    SSL *ssl;

    BIO *in;
    BIO *out;
} AGENT;

const char *openssl_version();
void *openssl_create(AGENT_DESCRIPTOR *descriptor);
void *openssl_create_client(AGENT_DESCRIPTOR *descriptor);
void *openssl_create_server(AGENT_DESCRIPTOR *descriptor);
void openssl_destroy(void *agent);
RESULT openssl_progress(void *agent);
RESULT openssl_reset(void *agent);
void openssl_rename(void *agent, uint8_t agent_name);
const char *openssl_describe_state(void *agent);
bool openssl_is_successful(void *agent);
void openssl_set_deterministic(void *agent);
const char *openssl_shutdown(void *agent);
RESULT openssl_add_inbound(void *agent, const uint8_t *bytes, size_t length, size_t *written);
RESULT openssl_take_outbound(void *agent, uint8_t *bytes, size_t max_length, size_t *readbytes);

static AGENT *as_agent(void *ptr);
static RESULT_CODE result_code(AGENT *agent, int retcode);
static char *get_error_reason();

static SSL_CTX *set_cert(SSL_CTX *ssl_ctx, const PEM *pem_cert);
static SSL_CTX *set_pkey(SSL_CTX *ssl_ctx, const PEM *pem_pkey);
static SSL_CTX *set_store(SSL_CTX *ssl_ctx, const PEM *const *pems);

static AGENT *make_agent(SSL_CTX *ssl_ctx, AGENT_DESCRIPTOR *descriptor);
static X509_STORE *make_store(const PEM *const *pems);
static X509 *load_inmem_cert(const PEM *pem);
static EVP_PKEY *load_inmem_pkey(const PEM *pem);

const C_PUT_TYPE CPUT = {
    .create = openssl_create,
    .destroy = openssl_destroy,
    .version = openssl_version,

    .progress = openssl_progress,
    .reset = openssl_reset,
    .rename_agent = openssl_rename,
    .describe_state = openssl_describe_state,
    .is_state_successful = openssl_is_successful,
    .set_deterministic = openssl_set_deterministic,
    .shutdown = openssl_shutdown,

    .add_inbound = openssl_add_inbound,
    .take_outbound = openssl_take_outbound,
};

const int tls_version[] = {TLS1_3_VERSION, TLS1_2_VERSION};
const char *version_str[] = {"V1_3", "V1_2"};
const char *type_str[] = {"client", "server"};

const char *openssl_version()
{
    return OPENSSL_FULL_VERSION_STR;
}

void *openssl_create(AGENT_DESCRIPTOR *descriptor)
{
    _log(TLSPUFFIN.info, "descriptor %u version: %s type: %s", descriptor->name, version_str[descriptor->tls_version], type_str[descriptor->type]);

    SSL_library_init();

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

RESULT openssl_reset(void *a)
{
    AGENT *agent = as_agent(a);

    int ret = SSL_clear(agent->ssl);
    if (ret == 0)
    {
        return TLSPUFFIN.make_result(RESULT_ERROR_OTHER, get_error_reason());
    }

    return TLSPUFFIN.make_result(RESULT_OK, NULL);
}

void openssl_rename(void *a, uint8_t agent_name)
{
    AGENT *agent = as_agent(a);

    agent->descriptor->name = agent_name;
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

void openssl_set_deterministic(void *agent)
{
    return;
}

const char *openssl_shutdown(void *agent)
{
    return "";
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

void *openssl_create_client(AGENT_DESCRIPTOR *descriptor)
{
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_method());

    // Not sure whether we want this disabled or enabled: https://github.com/tlspuffin/tlspuffin/issues/67
    // The tests become simpler if disabled to maybe that's what we want. Lets leave it default
    // for now.
    // https://wiki.openssl.org/index.php/TLS1.3#Middlebox_Compatibility_Mode
    SSL_CTX_clear_options(ssl_ctx, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);

    SSL_CTX_set_max_proto_version(ssl_ctx, tls_version[descriptor->tls_version]);

    // Disallow EXPORT in client
    SSL_CTX_set_cipher_list(ssl_ctx, "ALL:!EXPORT:!LOW:!aNULL:!eNULL:!SSLv2");
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);

    if (descriptor->client_authentication)
    {
        ssl_ctx = set_cert(ssl_ctx, &descriptor->cert);
        ssl_ctx = set_pkey(ssl_ctx, &descriptor->pkey);
        if (ssl_ctx == NULL)
        {
            return NULL;
        }
    }

    if (descriptor->server_authentication)
    {
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

        ssl_ctx = set_store(ssl_ctx, descriptor->store);
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

void *openssl_create_server(AGENT_DESCRIPTOR *descriptor)
{
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_method());

    SSL_CTX_set_options(ssl_ctx, SSL_OP_ALLOW_NO_DHE_KEX);
    SSL_CTX_clear_options(ssl_ctx, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);

    SSL_CTX_set_max_proto_version(ssl_ctx, tls_version[descriptor->tls_version]);

    // Allow EXPORT in server
    SSL_CTX_set_cipher_list(ssl_ctx, "ALL:EXPORT:!LOW:!aNULL:!eNULL:!SSLv2");
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);

    ssl_ctx = set_cert(ssl_ctx, &descriptor->cert);
    ssl_ctx = set_pkey(ssl_ctx, &descriptor->pkey);
    if (ssl_ctx == NULL)
    {
        return NULL;
    }

    if (descriptor->client_authentication)
    {
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

        ssl_ctx = set_store(ssl_ctx, descriptor->store);
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

static X509 *load_inmem_cert(const PEM *pem)
{
    BIO *cert_bio = BIO_new_mem_buf(pem->bytes, pem->length);
    if (cert_bio == NULL)
    {
        return NULL;
    }

    X509 *cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);

    BIO_free(cert_bio);
    return cert;
}

static EVP_PKEY *load_inmem_pkey(const PEM *pem)
{
    EVP_PKEY *pkey = NULL;
    BIO *pkey_bio = BIO_new_mem_buf(pem->bytes, pem->length);
    OSSL_DECODER_CTX *dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "PEM", NULL, NULL, OSSL_KEYMGMT_SELECT_KEYPAIR, NULL, NULL);
    OSSL_DECODER_from_bio(dctx, pkey_bio);

    OSSL_DECODER_CTX_free(dctx);
    BIO_free(pkey_bio);
    return pkey;
}

static X509_STORE *make_store(const PEM *const *pems)
{
    X509_STORE *store = X509_STORE_new();
    if (store == NULL)
    {
        return NULL;
    }

    for (size_t i = 0; pems[i] != NULL; ++i)
    {
        const PEM *const pem = pems[i];

        X509 *cert = load_inmem_cert(pem);
        if (cert == NULL)
        {
            X509_STORE_free(store);
            return NULL;
        }
        X509_STORE_add_cert(store, cert);
        X509_free(cert);
    }

    return store;
}

static SSL_CTX *set_cert(SSL_CTX *ssl_ctx, const PEM *pem_cert)
{
    X509 *cert = load_inmem_cert(pem_cert);
    if (cert == NULL)
    {
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    if (SSL_CTX_use_certificate(ssl_ctx, cert) != 1)
    {
        X509_free(cert);
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    X509_free(cert);
    return ssl_ctx;
}

static SSL_CTX *set_pkey(SSL_CTX *ssl_ctx, const PEM *pem_pkey)
{
    EVP_PKEY *pkey = load_inmem_pkey(pem_pkey);
    if (pkey == NULL)
    {
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    if (SSL_CTX_use_PrivateKey(ssl_ctx, pkey) != 1)
    {
        EVP_PKEY_free(pkey);
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    return ssl_ctx;
}

static SSL_CTX *set_store(SSL_CTX *ssl_ctx, const PEM *const *pems)
{
    X509_STORE *store = make_store(pems);
    if (store == NULL)
    {
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    SSL_CTX_set_cert_store(ssl_ctx, store);

    return ssl_ctx;
}

static AGENT *make_agent(SSL_CTX *ssl_ctx, AGENT_DESCRIPTOR *descriptor)
{
    SSL *ssl = SSL_new(ssl_ctx);

    AGENT *agent = malloc(sizeof(AGENT));
    agent->descriptor = descriptor;
    agent->ssl = ssl;

    agent->in = BIO_new(BIO_s_mem());
    agent->out = BIO_new(BIO_s_mem());
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

static char *get_error_reason()
{
    BIO *bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);

    char *buf = NULL;
    size_t len = BIO_get_mem_data(bio, &buf);
    char *ret = (char *)calloc(1, 1 + len);
    if (ret != NULL)
    {
        memcpy(ret, buf, len);
    }

    BIO_free(bio);

    return ret;
}

static AGENT *as_agent(void *ptr)
{
    return (AGENT *)ptr;
}

// TODO: `_log` implementation should be linked to tlspuffin
//
//     There is no need to reimplement this logging function for every C PUT.
//     The implementation should be statically linked inside tlspuffin.
void _log(void (*logger)(const char *), const char *format, ...)
{
    char *message = NULL;
    va_list args;

    va_start(args, format);
    vasprintf(&message, format, args);
    va_end(args);
    logger(message);

    free(message);
}