#include "bindings.h"
#include "rng.h"

#include <string.h>

void openssl_init()
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    OPENSSL_config(NULL);
    SSL_library_init();
#else
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);
#endif

    SSL_load_error_strings();
    OPENSSL_add_all_algorithms_noconf();
    rng_init();
}

#if OPENSSL_VERSION_NUMBER < 0x10101000L
int BIO_write_ex(BIO *b, const void *data, size_t dlen, size_t *written)
{
    int ret = BIO_write(b, data, (int)dlen);
    if (ret <= 0 && BIO_should_retry(b))
    {
        ret = 0;
    }

    if (ret >= 0 && written != NULL)
    {
        *written = (size_t)ret;
    }

    return (ret >= 0) ? 1 : 0;
}

int BIO_read_ex(BIO *b, void *data, size_t dlen, size_t *readbytes)
{
    int ret = BIO_read(b, data, (int)dlen);
    if (ret <= 0 && BIO_should_retry(b))
    {
        ret = 0;
    }

    if (ret >= 0 && readbytes != NULL)
    {
        *readbytes = (size_t)ret;
    }

    return (ret >= 0) ? 1 : 0;
}
#endif

char *get_error_reason()
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

X509 *load_inmem_cert(const PEM *pem)
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

EVP_PKEY *load_inmem_pkey(const PEM *pem)
{
    BIO *pkey_bio = BIO_new_mem_buf(pem->bytes, pem->length);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(pkey_bio, NULL, NULL, NULL);
    BIO_free(pkey_bio);
    return pkey;
}

X509_STORE *make_store(const PEM *const *pems, size_t store_length)
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

SSL_CTX *set_cert(SSL_CTX *ssl_ctx, const PEM *pem_cert)
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

SSL_CTX *set_pkey(SSL_CTX *ssl_ctx, const PEM *pem_pkey)
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

SSL_CTX *set_store(SSL_CTX *ssl_ctx, const PEM *const *pems, size_t store_length)
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
