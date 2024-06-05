#include <openssl/opensslv.h>

// check for Heartbleed: CVE-2014-0160
// see: https://www.openssl.org/news/vulnerabilities.html#y2014
int main()
{
#if OPENSSL_VERSION_NUMBER >= 0x10001000L && OPENSSL_VERSION_NUMBER < 0x10001070L
    // vulnerable versions in [1.0.1 ; 1.0.1f]
    return 0;
#else
    return 1;
#endif
}