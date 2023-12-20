#include <openssl/crypto.h>
#include <openssl/opensslv.h>
#include <stdio.h>

int main()
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    printf("%s", OpenSSL_version(OPENSSL_FULL_VERSION_STRING));
    return 1;
#elif OPENSSL_VERSION_NUMBER >= 0x00906000L
    long v_major = (OPENSSL_VERSION_NUMBER >> 28) & 0xffL;
    long v_minor = (OPENSSL_VERSION_NUMBER >> 20) & 0xffL;
    long v_fix = (OPENSSL_VERSION_NUMBER >> 12) & 0xffL;
    long v_patch = (OPENSSL_VERSION_NUMBER >> 4) & 0xffL;
    long v_status = OPENSSL_VERSION_NUMBER & 0x0fL;

    printf("%ld.%ld.%ld", v_major, v_minor, v_fix);

    while (v_patch > 0)
    {
        if (v_patch >= 26)
        {
            printf("z");
        }
        else
        {
            printf("%c", v_patch + ('a' - 1));
        }

        v_patch = v_patch - 25;
    }

    if (v_status != 0xfL)
    {
        if (v_status == 0)
        {
            printf("-dev");
        }

        printf("-beta%lu", v_status);
    }

    return 0;
#else
    error("openssl version < 0.9.6 are not supported")
#endif
}