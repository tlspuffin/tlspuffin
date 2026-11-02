# Patch tls13_key_schedule.c to set secrets->insecure = 1 at creation time.
# This prevents LibreSSL from zeroing intermediate TLS 1.3 secrets
# (extracted_early, extracted_handshake, extracted_master) after derivation,
# allowing the fuzzer harness to read them for security claims.
file(READ "${FILE}" content)

set(before "${content}")

string(REPLACE "secrets->init_done = 1;" "secrets->init_done = 1; secrets->insecure = 1;" content "${content}")

if("${content}" STREQUAL "${before}")
  message(FATAL_ERROR
    "patch_insecure: replacement had no effect in '${FILE}'.\n"
    "The LibreSSL source may have changed (renamed variable, restructured init logic, "
    "or changed whitespace). Update this patch to match the new source.")
endif()

file(WRITE "${FILE}" "${content}")
