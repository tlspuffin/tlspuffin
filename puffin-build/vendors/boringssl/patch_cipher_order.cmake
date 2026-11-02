# Swap TLS 1.3 cipher preference order: AES-256-GCM first (matching OpenSSL).
#
# BoringSSL's default kCiphersAESHardware[] puts AES-128-GCM before AES-256-GCM.
# OpenSSL defaults to AES-256-GCM first. For differential fuzzing, both PUTs
# must negotiate the same cipher. This patch swaps the order so BoringSSL's
# client prefers AES-256-GCM, matching OpenSSL.
file(READ "${FILE}" content)
string(REPLACE
  "static const uint16_t kCiphersAESHardware[] = {
        SSL_CIPHER_AES_128_GCM_SHA256,
        SSL_CIPHER_AES_256_GCM_SHA384,"
  "static const uint16_t kCiphersAESHardware[] = {
        SSL_CIPHER_AES_256_GCM_SHA384,
        SSL_CIPHER_AES_128_GCM_SHA256,"
  content "${content}")
file(WRITE "${FILE}" "${content}")
