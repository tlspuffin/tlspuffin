/* Export an ML-DSA-44 key as (1) SubjectPublicKeyInfo DER and (2) private key DER.
 * Usage: mldsa_export <in-private-key.der> <out-spki.der> <out-priv.der> */
#include <stdio.h>
#include <stdlib.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

static int read_file(const char *path, byte **buf, long *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    *len = ftell(f);
    fseek(f, 0, SEEK_SET);
    *buf = malloc(*len);
    if (fread(*buf, 1, *len, f) != (size_t)*len) { fclose(f); return -1; }
    fclose(f);
    return 0;
}

static int write_file(const char *path, const byte *buf, int len)
{
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    fwrite(buf, 1, len, f);
    fclose(f);
    return 0;
}

int main(int argc, char **argv)
{
    byte *in = NULL, out[8192];
    long inLen = 0;
    word32 idx = 0;
    int ret;
    dilithium_key key;

    if (argc != 4) { fprintf(stderr, "usage: %s in.der spki.der priv.der\n", argv[0]); return 1; }
    if (read_file(argv[1], &in, &inLen) != 0) { perror("read"); return 1; }

    wc_dilithium_init(&key);
    wc_dilithium_set_level(&key, WC_ML_DSA_44);
    ret = wc_Dilithium_PrivateKeyDecode(in, &idx, &key, (word32)inLen);
    if (ret != 0) { fprintf(stderr, "PrivateKeyDecode: %d\n", ret); return 1; }

    /* the public part must be present for KeyToDer / PublicKeyToDer */
    ret = wc_Dilithium_PublicKeyToDer(&key, out, sizeof(out), 1 /* with AlgorithmIdentifier */);
    if (ret <= 0) { fprintf(stderr, "PublicKeyToDer: %d\n", ret); return 1; }
    write_file(argv[2], out, ret);
    printf("spki: %d bytes\n", ret);

    ret = wc_Dilithium_KeyToDer(&key, out, sizeof(out));
    if (ret <= 0) {
        ret = wc_Dilithium_PrivateKeyToDer(&key, out, sizeof(out));
    }
    if (ret <= 0) { fprintf(stderr, "KeyToDer: %d\n", ret); return 1; }
    write_file(argv[3], out, ret);
    printf("priv: %d bytes\n", ret);

    wc_dilithium_free(&key);
    free(in);
    return 0;
}

/* The tlspuffin wolfSSL build uses USER_TICKS: the harness normally provides these. */
word32 LowResTimer(void) { return 0; }
word64 TimeNowInMilliseconds(void) { return 0; }
