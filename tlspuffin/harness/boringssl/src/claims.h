#ifndef BORINGSSL_CLAIMS_H
#define BORINGSSL_CLAIMS_H
#include <openssl/ssl.h>
#include <claim-interface.h>

#ifdef __cplusplus
extern "C" {
#endif

void boringssl_fill_claim(const SSL *ssl, Claim *claim);
void boringssl_fill_claim_for_message(const SSL *ssl,
									  Claim *claim,
									  const uint8_t *msg,
									  size_t msg_len,
									  int append_msg_to_transcript);

#ifdef __cplusplus
}
#endif
#endif
