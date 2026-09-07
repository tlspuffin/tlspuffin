#ifndef PUFFIN_SEED_PROTO_H
#define PUFFIN_SEED_PROTO_H

/* Prototype for the deterministic entropy source wired in via
 * -DCUSTOM_RAND_GENERATE_SEED=puffin_wolfssl_seed. Force-included into every
 * wolfSSL TU (see build_wolfssl_dep.sh) so wc_GenerateSeed() compiles cleanly
 * under -Werror; the definition lives in the wolfSSH harness (put.c). */
int puffin_wolfssl_seed(unsigned char *output, unsigned int sz);

#endif /* PUFFIN_SEED_PROTO_H */
