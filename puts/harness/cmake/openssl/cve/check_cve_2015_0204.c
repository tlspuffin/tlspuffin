#include <openssl/opensslv.h>

// check for FREAK: CVE-2015-0204
// see: https://www.openssl.org/news/vulnerabilities.html#y2015
int main()
{
#if OPENSSL_VERSION_NUMBER >= 0x10000000L && OPENSSL_VERSION_NUMBER < 0x10000100L
    // vulnerable versions in [1.0.0 ; 1.0.0o]
    return 0;
#elif OPENSSL_VERSION_NUMBER >= 0x10001000L && OPENSSL_VERSION_NUMBER < 0x100010b0L
    // vulnerable versions in [1.0.1 ; 1.0.1j]
    return 0;
#else
    return 1;
#endif
}