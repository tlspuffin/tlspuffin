# PUFFIN fuzzing instrumentation for libssh (applied to src/packet.c).
#
# Exposes, for the matching-conversation security oracle, two things the public
# API does not give us:
#
#   1. puffin_ssh_get_session_id()  -- the SSH session identifier (exchange hash
#      H of the first KEX, RFC 4253 §7.2). Equal on both honest peers iff they
#      had a matching key-exchange conversation. Used for KEX-transcript
#      agreement.
#
#   2. puffin_ssh_get_secure_{tx,rx}_digest() -- an order-sensitive FNV-1a digest
#      over the message *type byte* of every packet processed on the secure
#      channel (after the first NEWKEYS), per direction. The post-NEWKEYS stream
#      is MAC-authenticated (RFC 4253 §6.4), so in a faithful relay one peer's
#      outbound digest equals its partner's inbound digest; a dropped / injected
#      / reordered secure-channel message (Terrapin prefix truncation stripping
#      EXT_INFO) breaks that crosswise equality. Used for channel-data integrity.
#
# Implementation: a tiny per-session thread-local digest table (the differential
# / two-party harness runs client and server sessions in one thread), updated
# from hooks injected at the single incoming-dispatch and outgoing-encrypt
# choke points. Pure observation -- it never alters protocol behaviour. The hook
# anchors are byte-identical across libssh 0.10.4 and 0.11.4.

file(READ "${FILE}" content)

# Idempotent: PATCH_COMMANDS may re-run against already-patched source, and the
# anchor signature still occurs after patching, so guard against re-insertion.
if(content MATCHES "puffin_ssh_digest_rx")
  message(STATUS "PUFFIN libssh instrument: already applied to ${FILE}; skipping")
  return()
endif()

set(helpers "/* ===== PUFFIN fuzzing instrumentation (matching-conversation oracle) ===== */
/* The hook calls injected below are statements at function entry, before each
 * function's existing declarations. libssh 0.11.4 compiles with
 * -Werror=declaration-after-statement (C90); disable just that diagnostic from
 * here on so the injected calls compile on every vendored version. */
#pragma GCC diagnostic ignored \"-Wdeclaration-after-statement\"
#define PUFFIN_MAX_SESS 8
static __thread const void *puffin_sess[PUFFIN_MAX_SESS];
static __thread uint64_t puffin_rxd[PUFFIN_MAX_SESS];
static __thread uint64_t puffin_txd[PUFFIN_MAX_SESS];
static __thread uint32_t puffin_rxn[PUFFIN_MAX_SESS];
static __thread uint32_t puffin_txn[PUFFIN_MAX_SESS];
static int puffin_find(const void *s)
{
    int i;
    for (i = 0; i < PUFFIN_MAX_SESS; i++) {
        if (puffin_sess[i] == s) {
            return i;
        }
    }
    return -1;
}
static int puffin_slot(const void *s)
{
    int i, freei = -1;
    for (i = 0; i < PUFFIN_MAX_SESS; i++) {
        if (puffin_sess[i] == s) {
            return i;
        }
        if (puffin_sess[i] == NULL && freei < 0) {
            freei = i;
        }
    }
    if (freei >= 0) {
        puffin_sess[freei] = s;
        puffin_rxd[freei] = 14695981039346656037ULL;
        puffin_txd[freei] = 14695981039346656037ULL;
        puffin_rxn[freei] = 0;
        puffin_txn[freei] = 0;
    }
    return freei;
}
__attribute__((visibility(\"default\")))
void puffin_ssh_digest_rx(ssh_session session, uint8_t type)
{
    int i;
    if (session == NULL) {
        return;
    }
    i = puffin_slot(session);
    if (i < 0) {
        return;
    }
    puffin_rxn[i]++; /* count ALL received packets (handshake depth) */
    if (session->current_crypto != NULL) { /* digest only the secure channel */
        puffin_rxd[i] = (puffin_rxd[i] ^ (uint64_t)type) * 1099511628211ULL;
    }
}
__attribute__((visibility(\"default\")))
void puffin_ssh_digest_tx(ssh_session session)
{
    int i;
    uint8_t *payload;
    if (session == NULL) {
        return;
    }
    i = puffin_slot(session);
    if (i < 0) {
        return;
    }
    puffin_txn[i]++; /* count ALL sent packets (handshake depth) */
    if (session->current_crypto == NULL) {
        return;
    }
    if (session->out_buffer == NULL || ssh_buffer_get_len(session->out_buffer) < 1) {
        return;
    }
    payload = (uint8_t *)ssh_buffer_get(session->out_buffer);
    puffin_txd[i] = (puffin_txd[i] ^ (uint64_t)payload[0]) * 1099511628211ULL;
}
__attribute__((visibility(\"default\")))
uint32_t puffin_ssh_get_rx_count(ssh_session session)
{
    int i = puffin_find(session);
    return i < 0 ? 0 : puffin_rxn[i];
}
__attribute__((visibility(\"default\")))
uint32_t puffin_ssh_get_tx_count(ssh_session session)
{
    int i = puffin_find(session);
    return i < 0 ? 0 : puffin_txn[i];
}
__attribute__((visibility(\"default\")))
uint64_t puffin_ssh_get_secure_tx_digest(ssh_session session)
{
    int i = puffin_find(session);
    return i < 0 ? 0 : puffin_txd[i];
}
__attribute__((visibility(\"default\")))
uint64_t puffin_ssh_get_secure_rx_digest(ssh_session session)
{
    int i = puffin_find(session);
    return i < 0 ? 0 : puffin_rxd[i];
}
__attribute__((visibility(\"default\")))
int puffin_ssh_get_session_id(ssh_session session, const unsigned char **out, size_t *len)
{
    if (session == NULL || session->current_crypto == NULL ||
        session->current_crypto->session_id == NULL) {
        return -1;
    }
    *out = session->current_crypto->session_id;
    *len = session->current_crypto->session_id_len;
    return 0;
}

void ssh_packet_process(ssh_session session, uint8_t type)
{
    puffin_ssh_digest_rx(session, type);")

string(REPLACE
  "void ssh_packet_process(ssh_session session, uint8_t type)
{"
  "${helpers}"
  patched "${content}")

if(patched STREQUAL content)
  message(FATAL_ERROR "PUFFIN libssh instrument: rx anchor 'ssh_packet_process' not found in ${FILE}")
endif()

string(REPLACE
  "static int packet_send2(ssh_session session)
{"
  "static int packet_send2(ssh_session session)
{
    puffin_ssh_digest_tx(session);"
  patched2 "${patched}")

if(patched2 STREQUAL patched)
  message(FATAL_ERROR "PUFFIN libssh instrument: tx anchor 'packet_send2' not found in ${FILE}")
endif()

file(WRITE "${FILE}" "${patched2}")
message(STATUS "PUFFIN libssh instrument: applied claim hooks to ${FILE}")
