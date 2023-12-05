#include <stdio.h>
#include <stdlib.h>

#include <openssl/decoder.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <tlspuffin/put.h>

typedef struct
{
    uint8_t name;

    SSL *ssl;

    BIO *in;
    BIO *out;
} AGENT;

const char *openssl_version();
void *openssl_create(const AGENT_DESCRIPTOR *descriptor);
void *openssl_create_client(const AGENT_DESCRIPTOR *descriptor);
void *openssl_create_server(const AGENT_DESCRIPTOR *descriptor);
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
static SSL_CTX *set_store(SSL_CTX *ssl_ctx, const PEM *const *pems, size_t store_length);

static AGENT *make_agent(SSL_CTX *ssl_ctx, const AGENT_DESCRIPTOR *descriptor);
static X509_STORE *make_store(const PEM *const *pems, size_t store_length);
static X509 *load_inmem_cert(const PEM *pem);
static EVP_PKEY *load_inmem_pkey(const PEM *pem);

const C_PUT_TYPE CPUT = {
    .create = openssl_create,
    .destroy = openssl_destroy,
    .version = openssl_version,

    .progress = openssl_progress,
    .reset = openssl_reset,
    .rename = openssl_rename,
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

void *openssl_create(const AGENT_DESCRIPTOR *descriptor)
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
    agent->name = agent_name;
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

RAND_METHOD stdlib_rand_meth;
void openssl_set_deterministic(void *agent)
{
    // FIXME use of deprecated OpenSSL API
    //
    //     The deterministic RNG's registration uses an API deprecated since
    //     version 3.0 of OpenSSL. Because external builds of OpenSSL can hide
    //     these functions, the PUT interface creation might fail.
    //
    //     To support a wide range of OpenSSL versions, we need to detect API
    //     support in the provided OpenSSL headers and only fallback to this
    //     implementation for older versions, providing a more modern
    //     implementation for 3.0 onwards.
    //
    //     - see also: https://www.openssl.org/docs/man3.2/man3/RAND_set_rand_method.html

    RAND_set_rand_method(&stdlib_rand_meth);
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

void *openssl_create_client(const AGENT_DESCRIPTOR *descriptor)
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

    SSL_CTX_set_options(ssl_ctx, SSL_OP_ALLOW_NO_DHE_KEX);
    SSL_CTX_clear_options(ssl_ctx, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);

    SSL_CTX_set_max_proto_version(ssl_ctx, tls_version[descriptor->tls_version]);

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

static X509_STORE *make_store(const PEM *const *pems, size_t store_length)
{
    X509_STORE *store = X509_STORE_new();
    if (store == NULL)
    {
        return NULL;
    }

    for (size_t i = 0; i < store_length; ++i)
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

static SSL_CTX *set_store(SSL_CTX *ssl_ctx, const PEM *const *pems, size_t store_length)
{
    X509_STORE *store = make_store(pems, store_length);
    if (store == NULL)
    {
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    SSL_CTX_set_cert_store(ssl_ctx, store);

    return ssl_ctx;
}

static AGENT *make_agent(SSL_CTX *ssl_ctx, const AGENT_DESCRIPTOR *descriptor)
{
    SSL *ssl = SSL_new(ssl_ctx);

    AGENT *agent = malloc(sizeof(AGENT));
    agent->name = descriptor->name;
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

// NOTE implements a deterministic RNG for OpenSSL
//
//     The deterministic random generator uses stdlib's RNG `srand`, which has
//     been part of the C standard since C89 and should be available on
//     virtually all platforms.
//
//     - based on: https://stackoverflow.com/a/7510354
//     - see also: https://maxammann.org/posts/2021/06/openssl-no-random/
//     - see also: https://www.openssl.org/docs/man3.2/man3/RAND_set_rand_method.html
//     - see also: https://en.cppreference.com/w/c/numeric/random/srand

static int stdlib_rand_seed(const void *buf, int num);
static int stdlib_rand_bytes(unsigned char *buf, int num);
static int stdlib_rand_add(const void *buf, int num, double add_entropy);
static int stdlib_rand_status();
static void stdlib_rand_cleanup();

RAND_METHOD stdlib_rand_meth = {stdlib_rand_seed, stdlib_rand_bytes, stdlib_rand_cleanup, stdlib_rand_add, stdlib_rand_bytes, stdlib_rand_status};

static int stdlib_rand_seed(const void *buf, int num)
{
    // FIXME confusing behavior: seemingly different seeds have the same effect
    //
    //     We seed the stdlib random generator through `srand()` which only
    //     seeds from a single unsigned int. In the current implementation, when
    //     a longer seed is provided, the remainder is simply ignored.
    //
    //     This implies that if we ever try to seed the PUT in deterministic
    //     mode, providing seemingly different seeds will likely result in the
    //     same RNG initialization, which might be confusing. Since we cannot
    //     change `srand` we cannot improve the collision rate but at least we
    //     could make sure that seeds that are visually very similar for a human
    //     user (bit-flip, additional bytes, ...) are less likely to have the
    //     same effect.
    //
    //     A reasonable solution could be to XOR the buffer by portions of size
    //     `sizeof(unsigned int)` to make use of the entire seed provided.

    if (num < 1)
    {
        srand(0);

        // FIXME (question) Should we really signal an error here?
        //
        //     A return value of zero from this function signals an error: The
        //     documentation for this function was not up-to-date for a long
        //     time and even now it is unclear what the return value should be,
        //     but from looking at the current code base for OpenSSL, zero
        //     signals an error.
        //
        //     We only care about seeding the RNG in a deterministic manner and
        //     we can still do it when the seed is empty. In fact, at least some
        //     RNG providers in OpenSSL seem to work when the size of the
        //     additional seed data provided by the user is zero.
        //
        //     - see also: https://github.com/openssl/openssl/blob/b6dcdbfc94c482f6c15ba725754fc9e827e41851/crypto/rand/md_rand.c#L190
        return 0;
    }

    // FIXME possible out-of-bounds memory read
    //
    //     If `buf` length is less than `sizeof(unsigned int)` bytes, `srand`
    //     will read out-of-bounds memory. The previous guard `(num < 1)` does
    //     not prevent this case.
    srand(*((unsigned int *)buf));
    return 1;
}

static int stdlib_rand_bytes(unsigned char *buf, int num)
{
    for (int index = 0; index < num; ++index)
    {
        // FIXME dubious modulo computation
        //
        //     A C assignment implicitly converts the rhs to the (unqualified)
        //     lvalue type. When integer narrowing occurs (like in this case),
        //     this process is not straightforward:
        //       - for unsigned target types modulo arithmetic applies
        //       - for signed target types the behavior is
        //         implementation-defined
        //
        //     In the general case, when implementing an RNG, it seems unwise to
        //     explicitely set most bits to zero by performing a modulo before
        //     handing the result to the compiler for narrowing. In this
        //     instance, because the lvalue is of type "unsigned int" the modulo
        //     is (probably) merely redundant.
        //
        //     see also: https://en.cppreference.com/w/c/language/conversion
        //     see also: https://wiki.sei.cmu.edu/confluence/display/c/INT31-C.+Ensure+that+integer+conversions+do+not+result+in+lost+or+misinterpreted+data
        buf[index] = rand() % 256;
    }

    return 1;
}

static void stdlib_rand_cleanup()
{
}

static int stdlib_rand_status()
{
    return 1;
}

#define UNUSED(x) (void)(x)
static int stdlib_rand_add(const void *buf, int num, double add_entropy)
{

    UNUSED(buf);
    UNUSED(num);
    UNUSED(add_entropy);

    return 1;
}