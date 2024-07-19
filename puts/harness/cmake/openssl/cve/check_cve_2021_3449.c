#include <openssl/opensslv.h>

// check for CVE-2021-3449
// see: https://www.openssl.org/news/vulnerabilities.html#y2021
int main()
{
#if OPENSSL_VERSION_NUMBER >= 0x10101000L && OPENSSL_VERSION_NUMBER < 0x101010a0L
    // vulnerable versions in [1.1.1 ; 1.1.1j]
    return 0;
#else
    return 1;
#endif
}