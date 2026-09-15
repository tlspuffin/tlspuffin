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
     * at a claim point (currently emitted once when the transport handshake
     * completes). The negotiated-algorithm strings are fixed-size buffers so
     * that the whole structure is plain-old-data and can be mirrored by a
     * `#[repr(C)]` Rust type without any heap ownership crossing the FFI
     * boundary.
     */
#define SSH_CLAIM_STR_LEN 128
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
         * the SHA-256 fingerprint of the verified+authorized public key. Used by
         * the entity-authentication / impersonation oracle.
         */
        char auth_method[SSH_CLAIM_STR_LEN];
        char auth_user[SSH_CLAIM_STR_LEN];
        uint8_t auth_key_fp[32];
        uint8_t auth_key_fp_len;
        /*
         * KEX-transcript binding (RFC 4253 §7.2): the SSH session identifier,
         * i.e. the exchange hash H of the first key exchange. H binds
         * V_C,V_S,I_C,I_S,K_S,e,f,K (RFC 4253 §8), so two honest peers share it
         * iff they had a matching key-exchange conversation. Compared
         * cross-endpoint by the matching-conversation oracle. <session_id_len>
         * == 0 means "not available" (no completed KEX, or PUT not instrumented).
         */
        uint8_t session_id[64];
        uint8_t session_id_len;
        /*
         * Channel-data integrity (RFC 4253 §6.4 / RFC 4251 §9.3.2): an
         * order-sensitive FNV-1a digest over the *message type byte* of every
         * packet processed on the secure channel (after the first NEWKEYS), per
         * direction. The post-NEWKEYS stream is MAC-authenticated, so in a
         * faithful relay each peer's outbound digest equals its partner's
         * inbound digest; a dropped / injected / reordered secure-channel
         * message (e.g. the Terrapin prefix-truncation that strips EXT_INFO)
         * breaks that crosswise equality. 0 means "not available".
         */
        uint64_t secure_tx_digest;
        uint64_t secure_rx_digest;
        /*
         * Coarse protocol phase reached when this claim was emitted (liveness
         * depth): 0=init, 1=kex, 2=auth, 3=done. Intermediate (<3) claims are
         * emitted by runs that abort mid-handshake and feed only the
         * claim-coverage feedback; the security oracle considers only phase==3.
         */
        uint8_t phase;
        /*
         * Per-direction total packet counts (handshake depth). Refines the
         * liveness-depth coverage signal for runs that abort before the secure
         * channel (where the digests are still 0) and the coarse phase tag does
         * not distinguish how far they got. Bucketed in `coverage_key`.
         */
        uint32_t rx_count;
        uint32_t tx_count;
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
