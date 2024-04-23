#include <openssl/crypto.h>

int main()
{
    char *buf;
    buf = (char *)OPENSSL_malloc(sizeof(char) * 10);

    char *dest;
    dest = (char *)OPENSSL_malloc(sizeof(char) * 5000);

    memcpy(dest, buf, 5000);
    return 0;
}
