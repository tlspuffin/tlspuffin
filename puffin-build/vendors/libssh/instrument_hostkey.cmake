# PUFFIN fuzzing instrumentation for libssh (applied to src/packet_cb.c).
#
# The record of the entity-authentication invariant C1 (client: keyed => host key checked). A libssh
# client verifies the server's host-key signature over H inside the library, in ssh_packet_newkeys,
# with no callback the harness could observe. This routes that one call through a wrapper that returns
# exactly what ssh_pki_signature_verify returns and records, per session, that it returned SSH_OK; the
# harness reads the record with puffin_ssh_client_hostkey_verified(). Pure observation.
#
# Anchored on the call `ssh_pki_signature_verify(session,`, which packet_cb.c has exactly once in
# libssh 0.9.5, 0.10.4 and 0.12.2. Where there is not exactly one (libssh 0.8.x has another
# key-exchange code), nothing is changed and the accessor is not defined: the harness then does not
# check C1 on that build (see the support matrix) rather than misread every keyed client as a bypass.

file(READ "${FILE}" content)

# Idempotent: PATCH_COMMANDS may re-run against already-patched source.
if(content MATCHES "puffin_ssh_hostkey_verify")
  message(STATUS "PUFFIN libssh instrument: host-key record already applied to ${FILE}; skipping")
  return()
endif()

string(REGEX MATCHALL "ssh_pki_signature_verify\\(session," calls "${content}")
list(LENGTH calls ncalls)
if(NOT ncalls EQUAL 1)
  message(STATUS "PUFFIN libssh instrument: ${ncalls} host-key verification calls in ${FILE}, expected 1: C1 is not instrumented on this version")
  return()
endif()

# A file-scope prototype right after the last #include, where every type it names is declared.
string(FIND "${content}" "\n#include" last_include REVERSE)
math(EXPR line_start "${last_include} + 1")
string(SUBSTRING "${content}" ${line_start} -1 from_include)
string(FIND "${from_include}" "\n" line_len)
math(EXPR cut "${line_start} + ${line_len} + 1")
string(SUBSTRING "${content}" 0 ${cut} head)
string(SUBSTRING "${content}" ${cut} -1 body)
set(prototype "
/* PUFFIN fuzzing instrumentation: the host-key record of invariant C1 (defined at the end of the file) */
int puffin_ssh_hostkey_verify(ssh_session session, ssh_signature sig, const ssh_key key,
                              const unsigned char *digest, size_t dlen);
")
string(REPLACE "ssh_pki_signature_verify(session," "puffin_ssh_hostkey_verify(session," body "${body}")

set(record "
/* ===== PUFFIN fuzzing instrumentation: the host-key record of invariant C1 ===== */
#define PUFFIN_HOSTKEY_SESSIONS 16
static ssh_session puffin_hostkey_verified[PUFFIN_HOSTKEY_SESSIONS];
static unsigned int puffin_hostkey_verified_next;

/* The host-key signature verification of ssh_packet_newkeys, unchanged, plus the record that it
 * succeeded for <session>. */
int puffin_ssh_hostkey_verify(ssh_session session, ssh_signature sig, const ssh_key key,
                              const unsigned char *digest, size_t dlen)
{
    int rc = ssh_pki_signature_verify(session, sig, key, digest, dlen);
    if (rc == SSH_OK) {
        puffin_hostkey_verified[puffin_hostkey_verified_next++ % PUFFIN_HOSTKEY_SESSIONS] = session;
    }
    return rc;
}

/* 1 iff the server's host-key signature over H verified for <session>: the record the harness pairs
 * with puffin_ssh_client_keyed() for invariant C1. Default visibility so the harness (which declares
 * it __attribute__((weak))) links it. */
__attribute__((visibility(\"default\")))
int puffin_ssh_client_hostkey_verified(ssh_session session)
{
    unsigned int i;
    for (i = 0; session != NULL && i < PUFFIN_HOSTKEY_SESSIONS; i++) {
        if (puffin_hostkey_verified[i] == session) {
            return 1;
        }
    }
    return 0;
}
")

file(WRITE "${FILE}" "${head}${prototype}${body}${record}")
message(STATUS "PUFFIN libssh instrument: host-key record of invariant C1 added to ${FILE}")
