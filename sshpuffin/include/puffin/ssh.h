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
    };

    typedef struct
    {
        uint8_t name;
        SSH_AGENT_ROLE role;
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

