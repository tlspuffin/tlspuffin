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
        /*
         * CVE-2025-14942 safety flag (client side): set when the client reached the
         * server-userauth-accepted state (serverState >= SERVER_USERAUTH_ACCEPT_DONE)
         * while the transport was STILL keying (isKeying != 0) — i.e. it accepted a
         * user-authentication-protocol message out of order, during key exchange,
         * which the fixed wolfSSH client rejects (message not allowed). An honest
         * handshake only reaches that state after NEWKEYS, so this is 0 on every
         * legitimate trace. Read by the security oracle (sshpuffin/src/violation.rs).
         */
        uint8_t auth_while_keying;
        /*
         * Entity-authentication oracle fields (sshpuffin/src/violation.rs).
         *
         * <role>: this agent's role, 0 = client, 1 = server. Lets the oracle pick
         * the client vs the server claim (host auth is client-only; user-auth
         * authorization is server-only; the two-party matching-conversation check
         * pairs one of each).
         *
         * <had_signature> (server side, P1 — user authentication): the library had
         * cryptographically verified a publickey signature by the time it decided
         * this login (wolfSSH `hasSignature`, libssh: a publickey request carrying a
         * signature). A server that reaches authenticated with had_signature == 0
         * accepted a login that proved no key.
         *
         * <host_authenticated> (client side, P2 — host authentication): the client
         * verified the server's host-key signature over H against the PINNED host
         * identity (the embedded server host key == authorized identity A). Pure
         * observation: the client still accepts any host key; the oracle enforces the
         * pin. A client that reaches user-auth-accepted with host_authenticated == 0
         * accepted a session from a server that proved no / the wrong host key.
         */
        uint8_t role;
        uint8_t had_signature;
        uint8_t host_authenticated;
        /*
         * Opt-in flag: 1 iff this harness populates the entity-authentication fields
         * above (role / had_signature / host_authenticated). The oracle applies the
         * P1/P2/P3 checks ONLY to claims with this set, so a harness that has not yet
         * been instrumented (its fields default to 0) is never mistaken for a
         * host-auth bypass. The wolfSSH harness sets it; others leave it 0 until
         * instrumented.
         */
        uint8_t entity_auth_checked;
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
