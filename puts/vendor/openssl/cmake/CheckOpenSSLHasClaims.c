#include <assert.h>
#include <openssl/ssl.h>

#include "claim-interface.h"

void dummy_claimer(Claim claim, void *ctx)
{
}

int main()
{
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_method());
    SSL *ssl = SSL_new(ssl_ctx);

    register_claimer(ssl, dummy_claimer, NULL);

    return 0;
}