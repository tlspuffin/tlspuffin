#ifndef PUFFIN_SSH_H
#define PUFFIN_SSH_H

#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>

#include <puffin/puffin.h>

#ifdef __cplusplus
extern "C"
{
#endif

    typedef enum
    {
        SSH_CLIENT,
        SSH_SERVER
    } SSH_AGENT_ROLE;

    /*
     * Completes the opaque <Claim> declared in <puffin/puffin.h>.
     *
     * An SSH claim captures the security-relevant transport state of an agent
     * at a claim point: when the first key exchange completes, when the
     * handshake completes, and when the agent switches to the keys of a rekey.
     * The negotiated-algorithm strings are fixed-size buffers so
     * that the whole structure is plain-old-data and can be mirrored by a
     * `#[repr(C)]` Rust type without any heap ownership crossing the FFI
     * boundary.
     */
#define SSH_CLAIM_STR_LEN 128
#define SSH_CLAIM_MAX_KEX 8
#define SSH_KEX_SECRET_MAX_K 1025

    /*
     * The secrets of one key exchange (RFC 4253 §7.2): its exchange hash H and its shared
     * secret K as an unsigned big-endian number, with or without leading zeros. K is at most
     * a DH group-18 secret (8192 bits) and a leading zero.
     */
    typedef struct
    {
        uint8_t h[64];
        uint8_t h_len;
        uint8_t k[SSH_KEX_SECRET_MAX_K];
        uint16_t k_len;
    } SSH_KEX_SECRET;

    struct Claim
    {
        /* Negotiated key-exchange algorithm. */
        char kex[SSH_CLAIM_STR_LEN];
        /* Negotiated incoming/outgoing ciphers. */
        char cipher_in[SSH_CLAIM_STR_LEN];
        char cipher_out[SSH_CLAIM_STR_LEN];
        /* Negotiated incoming/outgoing MACs. */
        char hmac_in[SSH_CLAIM_STR_LEN];
        char hmac_out[SSH_CLAIM_STR_LEN];
        /*
         * Authentication belief (server side): the method that succeeded
         * ("password" / "publickey" / ""), the user name, and — for publickey —
         * the SHA-256 fingerprint of the verified+authorized public key. Compared
         * between the two PUTs of a differential. SSH has no single-PUT security
         * oracle yet: `SshSecurityViolationPolicy` is a stub.
         */
        char auth_method[SSH_CLAIM_STR_LEN];
        char auth_user[SSH_CLAIM_STR_LEN];
        uint8_t auth_key_fp[32];
        uint8_t auth_key_fp_len;
        /*
         * KEX-transcript binding (RFC 4253 §7.2): the SSH session identifier,
         * i.e. the exchange hash H of the first key exchange. H binds
         * V_C,V_S,I_C,I_S,K_S,e,f,K (RFC 4253 §8), so two honest peers share it
         * iff they had a matching key-exchange conversation. The seeds derive
         * from it the keys that decrypt the PUT's replies. <session_id_len>
         * == 0 means "not available" (no completed KEX, or PUT not instrumented).
         */
        uint8_t session_id[64];
        uint8_t session_id_len;
        /*
         * The secrets of each key exchange of the agent so far, in order: the first one, then
         * each rekey, recorded as soon as the agent's outbound keys switched to it (its own
         * NEWKEYS sent). The differential derives from them the keys of every epoch of the
         * agent's output, also after a rekey. <kex_count> == 0 means "not available" (no
         * outbound keys yet, or PUT not instrumented).
         */
        SSH_KEX_SECRET kex_secrets[SSH_CLAIM_MAX_KEX];
        uint8_t kex_count;
        /*
         * Coarse protocol phase reached when this claim was emitted (liveness
         * depth): 0=init, 1=kex, 2=auth, 3=done. Intermediate (<3) claims are
         * emitted by runs that abort mid-handshake, and carry the session id once
         * KEX has completed.
         */
        uint8_t phase;
    };

    typedef struct
    {
        uint8_t name;
        SSH_AGENT_ROLE role;
        /*
         * Uniformised algorithm lists (comma-separated SSH wire names, e.g.
         * "ecdh-sha2-nistp256"). Used by differential fuzzing to make both PUTs
         * advertise the SAME negotiable algorithms so their KEXINIT no longer
         * diverges on static per-implementation capability. A NULL pointer means
         * "leave the PUT default" (single-PUT / non-differential runs).
         */
        const char *kex;
        const char *ciphers;
        const char *macs;
        const char *hostkey_algos;
        /*
         * Public-key algorithms the server ACCEPTS for user authentication —
         * advertised to the client in the EXT_INFO `server-sig-algs` extension
         * (RFC 8308 §3.1), which is DISTINCT from <hostkey_algos> (the KEXINIT
         * host-key algorithms). Uniformised so both PUTs advertise the same
         * server-sig-algs and their decrypted EXT_INFO no longer diverges on
         * static per-implementation capability. NULL leaves the PUT default.
         * libssh: SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES; wolfSSH:
         * wolfSSH_CTX_SetAlgoListKeyAccepted.
         */
        const char *server_sig_algs;
    } SSH_AGENT_DESCRIPTOR;

    typedef struct SSH_PUT_INTERFACE
    {
        /*
         * Creates a new agent following the specification in the <descriptor>.
         *
         * Returns a pointer to an opaque object representing the created agent, or
         * NULL on error. The caller retains ownership of <descriptor>.
         */
        AGENT (*const create)(const SSH_AGENT_DESCRIPTOR *descriptor);

        /*
         * Reseed the PUT's deterministic RNG. Called by the fuzzer before each
         * trace execution so that runs are reproducible (required for
         * differential fuzzing). Passing a NULL buffer resets to the default
         * seed.
         */
        void (*const rng_reseed)(const uint8_t *buffer, size_t length);

        AGENT_INTERFACE agent_interface;
    } SSH_PUT_INTERFACE;

#ifdef __cplusplus
}
#endif

#endif // PUFFIN_SSH_H
