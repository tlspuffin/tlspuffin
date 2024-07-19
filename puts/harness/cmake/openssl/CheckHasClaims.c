#include <openssl/ssl.h>

#ifndef TLS_method
#define TLS_method SSLv23_method
#endif

#include "claim-interface.h"

void dummy_claimer(Claim claim, void *ctx)
{
    // do nothing
}

int main()
{
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_method());
    SSL *ssl = SSL_new(ssl_ctx);

    register_claimer(ssl, dummy_claimer, NULL);

    return 0;
}