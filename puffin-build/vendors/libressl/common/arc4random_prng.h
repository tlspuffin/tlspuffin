#ifndef LIBCRYPTOCOMPAT_ARC4RANDOM_H
#define LIBCRYPTOCOMPAT_ARC4RANDOM_H

#include <stdint.h>
#include <sys/param.h>

uint32_t arc4random(void);
void arc4random_buf(void *buf, size_t n);

#endif // LIBCRYPTOCOMPAT_ARC4RANDOM_H
