#ifndef PUFFIN_HARNESS_TLS_BORINGSSL_BINDINGS_H
#define PUFFIN_HARNESS_TLS_BORINGSSL_BINDINGS_H

#include "puffin/puffin.h"
#include "puffin/tls.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

void boringssl_init();

char *get_error_reason();

SSL_CTX *set_cert(SSL_CTX *ssl_ctx, const PEM *pem_cert);
SSL_CTX *set_pkey(SSL_CTX *ssl_ctx, const PEM *pem_pkey);
SSL_CTX *set_store(SSL_CTX *ssl_ctx, const PEM *const *pems, size_t store_length);

X509_STORE *make_store(const PEM *const *pems, size_t store_length);
X509 *load_inmem_cert(const PEM *pem);
EVP_PKEY *load_inmem_pkey(const PEM *pem);

#define TLS_UNSUPPORTED_VERSION 0x0

#ifndef TLS1_3_VERSION
#define TLS1_3_VERSION TLS_UNSUPPORTED_VERSION
#else
#define HAS_TLS1_3_VERSION
#endif

#endif // PUFFIN_HARNESS_TLS_BORINGSSL_BINDINGS_H
