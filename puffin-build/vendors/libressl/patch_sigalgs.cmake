# Patch ssl_sigalgs.c to reorder the default signature algorithm preference lists.
# LibreSSL defaults to RSA_PSS_SHA512 first, while OpenSSL defaults to RSA_PSS_SHA256.
# This reordering aligns LibreSSL with OpenSSL for differential fuzzing.
file(READ "${FILE}" content)


# Reorder TLS 1.3 sigalgs: move SHA256 variants before SHA512 variants
set(before "${content}")

string(REPLACE
  "const uint16_t tls13_sigalgs[] = {\n\tSIGALG_RSA_PSS_RSAE_SHA512,\n\tSIGALG_RSA_PKCS1_SHA512,\n\tSIGALG_ECDSA_SECP521R1_SHA512,\n\tSIGALG_RSA_PSS_RSAE_SHA384,\n\tSIGALG_RSA_PKCS1_SHA384,\n\tSIGALG_ECDSA_SECP384R1_SHA384,\n\tSIGALG_RSA_PSS_RSAE_SHA256,\n\tSIGALG_RSA_PKCS1_SHA256,\n\tSIGALG_ECDSA_SECP256R1_SHA256,"
  "const uint16_t tls13_sigalgs[] = {\n\tSIGALG_RSA_PSS_RSAE_SHA256,\n\tSIGALG_RSA_PKCS1_SHA256,\n\tSIGALG_ECDSA_SECP256R1_SHA256,\n\tSIGALG_RSA_PSS_RSAE_SHA384,\n\tSIGALG_RSA_PKCS1_SHA384,\n\tSIGALG_ECDSA_SECP384R1_SHA384,\n\tSIGALG_RSA_PSS_RSAE_SHA512,\n\tSIGALG_RSA_PKCS1_SHA512,\n\tSIGALG_ECDSA_SECP521R1_SHA512,"
  content "${content}")

if("${content}" STREQUAL "${before}")
  message(FATAL_ERROR
    "patch_sigalgs: tls13_sigalgs reordering had no effect in '${FILE}'.\n"
    "The LibreSSL source may have changed (renamed variables, added/removed sigalgs, "
    "or changed whitespace). Update this patch to match the new source.")
endif()


# Reorder TLS 1.2 sigalgs: move SHA256 variants before SHA512 variants
set(before "${content}")

string(REPLACE
  "const uint16_t tls12_sigalgs[] = {\n\tSIGALG_RSA_PSS_RSAE_SHA512,\n\tSIGALG_RSA_PKCS1_SHA512,\n\tSIGALG_ECDSA_SECP521R1_SHA512,\n\tSIGALG_RSA_PSS_RSAE_SHA384,\n\tSIGALG_RSA_PKCS1_SHA384,\n\tSIGALG_ECDSA_SECP384R1_SHA384,\n\tSIGALG_RSA_PSS_RSAE_SHA256,\n\tSIGALG_RSA_PKCS1_SHA256,\n\tSIGALG_ECDSA_SECP256R1_SHA256,"
  "const uint16_t tls12_sigalgs[] = {\n\tSIGALG_RSA_PSS_RSAE_SHA256,\n\tSIGALG_RSA_PKCS1_SHA256,\n\tSIGALG_ECDSA_SECP256R1_SHA256,\n\tSIGALG_RSA_PSS_RSAE_SHA384,\n\tSIGALG_RSA_PKCS1_SHA384,\n\tSIGALG_ECDSA_SECP384R1_SHA384,\n\tSIGALG_RSA_PSS_RSAE_SHA512,\n\tSIGALG_RSA_PKCS1_SHA512,\n\tSIGALG_ECDSA_SECP521R1_SHA512,"
  content "${content}")

if("${content}" STREQUAL "${before}")
  message(FATAL_ERROR
    "patch_sigalgs: tls12_sigalgs reordering had no effect in '${FILE}'.\n"
    "The LibreSSL source may have changed (renamed variables, added/removed sigalgs, "
    "or changed whitespace). Update this patch to match the new source.")
endif()

file(WRITE "${FILE}" "${content}")