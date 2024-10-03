// NOTE the order of include statements is relevant here
//
//     The header "wolfssl/options.h" MUST be included first. It contains all
//     the configuration options set during the wolfssl's library build. The
//     configuration cascades to all the headers included afterwards and
//     prevents the definition of conflicting defaults.
//
//     - see also: https://www.wolfssl.com/how-do-i-manage-the-build-configuration-of-wolfssl/
#include <wolfssl/options.h>

#include <wolfssl/openssl/ssl.h>
#include <wolfssl/ssl.h>
