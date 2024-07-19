#ifndef PUFFIN_HARNESS_TLS_OPENSSL_BINDINGS_H
#define PUFFIN_HARNESS_TLS_OPENSSL_BINDINGS_H

#include "tlspuffin/put.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

void openssl_init();

char *get_error_reason();

SSL_CTX *set_cert(SSL_CTX *ssl_ctx, const PEM *pem_cert);
SSL_CTX *set_pkey(SSL_CTX *ssl_ctx, const PEM *pem_pkey);
SSL_CTX *set_store(SSL_CTX *ssl_ctx, const PEM *const *pems, size_t store_length);

X509_STORE *make_store(const PEM *const *pems, size_t store_length);
X509 *load_inmem_cert(const PEM *pem);
EVP_PKEY *load_inmem_pkey(const PEM *pem);

#if OPENSSL_VERSION_NUMBER < 0x10101000L
int BIO_write_ex(BIO *b, const void *data, size_t dlen, size_t *written);
int BIO_read_ex(BIO *b, void *data, size_t dlen, size_t *readbytes);
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define TLS_method SSLv23_method
#endif

#define TLS_UNSUPPORTED_VERSION 0x0

#ifndef TLS1_3_VERSION
#define TLS1_3_VERSION TLS_UNSUPPORTED_VERSION
#else
#define HAS_TLS1_3_VERSION
#endif

#endif // PUFFIN_HARNESS_TLS_OPENSSL_BINDINGS_H
