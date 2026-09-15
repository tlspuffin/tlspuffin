// ---------------------------------------------------------------------------
// BoringSSL claims extraction — C++ module.
//
// This file accesses BoringSSL internals (ssl/internal.h is C++) to extract
// handshake state: secrets, transcript hashes, randoms, ciphers.
//
// State is stored on the AGENT_TYPE struct (defined in put.c), not in global
// C++ containers.  The agent is associated with its SSL object via SSL
// ex_data so that the PUFFIN_store_ch_sh_transcript patch can reach it.
// ---------------------------------------------------------------------------

#include "claims.h"

#include "ssl/internal.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <string.h>

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

// ---------------------------------------------------------------------------
// Ex-data index for storing AGENT pointer on SSL objects.
// ---------------------------------------------------------------------------

static int g_agent_ex_data_index = -1;

static void ensure_ex_data_index(void)
{
    if (g_agent_ex_data_index < 0)
    {
        g_agent_ex_data_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    }
}

extern "C" void boringssl_set_agent_for_ssl(SSL *ssl, void *agent)
{
    ensure_ex_data_index();
    SSL_set_ex_data(ssl, g_agent_ex_data_index, agent);
}

static void *get_agent_for_ssl(const SSL *ssl)
{
    ensure_ex_data_index();
    return SSL_get_ex_data(ssl, g_agent_ex_data_index);
}

// ---------------------------------------------------------------------------
// PUFFIN_store_ch_sh_transcript — called from BoringSSL patch
//
// Called from ssl/tls13_enc.cc::tls13_derive_handshake_secrets at the exact
// moment when:
//   - hs->transcript = hash(ClientHello || ServerHello)
//   - hs->secret     = HKDF-Extract(derived_early, DHE)  [handshake secret]
//
// Both values must be captured NOW because they are overwritten immediately
// after (transcript advances, secret becomes master secret).
//
// We store them on the AGENT_TYPE struct via ex_data.
// ---------------------------------------------------------------------------

// Forward-declare the AGENT_TYPE struct fields we need.
// We access them via byte offsets defined in claims.h (AGENT_FIELD_OFFSETS).
// Actually, we include the full struct definition indirectly through puffin/tls.h
// which defines the AGENT typedef. But AGENT_TYPE is defined in put.c, so we
// use a minimal struct layout that matches the fields we need.
//
// We define a struct matching the stored_* fields layout in AGENT_TYPE.
// The fields we write are:
//   agent->stored_ch_sh_transcript[EVP_MAX_MD_SIZE]
//   agent->stored_ch_sh_transcript_len
//   agent->stored_handshake_secret[EVP_MAX_MD_SIZE]
//   agent->stored_handshake_secret_len
//
// Since we can't include the full struct definition from put.c (it's C),
// we access through the opaque AGENT pointer using the accessors in claims.h.

// Note: PUFFIN_store_ch_sh_transcript is defined in the BoringSSL patch
// (ssl_lib.cc), not here.  It stores the CH+SH transcript hash in
// thread-local globals.  We retrieve it via PUFFIN_extract_ch_sh_transcript.
//
// The old approach of defining PUFFIN_store_ch_sh_transcript here didn't
// work because the C++ definition in ssl_lib.cc takes precedence over our
// extern "C" definition (different name mangling).

// ---------------------------------------------------------------------------
// Transcript extraction — safe wrapper around PUFFIN_extract_transcript.
//
// Returns 0 if the transcript hash context is not initialised (avoids the
// INPUT_NOT_INITIALIZED crash from the old code).
// ---------------------------------------------------------------------------

extern "C" int boringssl_extract_transcript_safe(const SSL *ssl, uint8_t *out, size_t out_max)
{
    if (ssl == NULL || ssl->s3 == NULL || ssl->s3->hs == NULL)
    {
        return 0;
    }

    bssl::SSL_HANDSHAKE *hs = ssl->s3->hs.get();

    const EVP_MD *md = hs->transcript.Digest();
    if (md == NULL)
    {
        return 0;
    }

    size_t hash_len = 0;
    ERR_clear_error();
    if (!hs->transcript.GetHash(out, &hash_len))
    {
        ERR_clear_error();
        return 0;
    }

    return (int)MIN(hash_len, out_max);
}

// Like boringssl_extract_transcript_safe, but INCLUDES the given message
// in the hash.  BoringSSL fires msg_callback BEFORE updating the transcript,
// so the live transcript at callback time is missing the current message.
extern "C" int boringssl_extract_transcript_with_msg(const SSL *ssl,
                                                     const uint8_t *msg,
                                                     size_t msg_len,
                                                     uint8_t *out,
                                                     size_t out_max)
{
    if (ssl == NULL || ssl->s3 == NULL || ssl->s3->hs == NULL)
    {
        return 0;
    }

    bssl::SSL_HANDSHAKE *hs = ssl->s3->hs.get();

    const EVP_MD *md = hs->transcript.Digest();
    if (md == NULL)
    {
        return 0;
    }

    // Copy the transcript hash context, update with the current message,
    // and finalize to get Hash(transcript || msg).
    bssl::ScopedEVP_MD_CTX ctx;
    if (!hs->transcript.CopyToHashContext(ctx.get(), md))
    {
        return 0;
    }

    if (msg != NULL && msg_len > 0)
    {
        if (!EVP_DigestUpdate(ctx.get(), msg, msg_len))
        {
            return 0;
        }
    }

    unsigned int hash_len = 0;
    if (!EVP_DigestFinal_ex(ctx.get(), out, &hash_len))
    {
        return 0;
    }

    return (int)MIN(hash_len, out_max);
}

// ---------------------------------------------------------------------------
// boringssl_store_ch_sh_data — called from PUFFIN_store_ch_sh_transcript
//
// Stores the CH+SH transcript hash and the handshake secret on the agent.
// ---------------------------------------------------------------------------

extern "C" void boringssl_store_ch_sh_data(void *agent_opaque,
                                           const uint8_t *hash,
                                           size_t hash_len,
                                           void *hs_opaque)
{
    // We receive the agent as opaque void* and cast to the field offsets.
    // Rather than depending on the full AGENT_TYPE layout, we use the
    // accessor functions declared in claims.h.
    //
    // Actually, since AGENT_TYPE is defined in a C file, we duplicate
    // the relevant field offsets here.  This is fragile but necessary
    // because the C++ file cannot include the C struct definition directly
    // (it lives in put.c, not a header).
    //
    // ALTERNATIVE: we expose setter functions from put.c (C code) and call
    // them here.  This is cleaner.  Let's do that.
    //
    // For now, we call back into the C setter functions.

    // Dead code — this function is never called because the BoringSSL patch
    // defines its own PUFFIN_store_ch_sh_transcript in ssl_lib.cc.
    // Kept for reference; actual extraction uses boringssl_extract_ch_sh_and_secrets.
    (void)agent_opaque;
    (void)hash;
    (void)hash_len;
    (void)hs_opaque;
}

// ---------------------------------------------------------------------------
// boringssl_extract_ch_sh_and_secrets — retrieves CH+SH transcript from
// BoringSSL patch's thread-local storage and captures handshake secret.
//
// Must be called AFTER BoringSSL has processed the relevant handshake
// message (so tls13_derive_handshake_secrets has run).  The right moment
// is right after a Finished message is seen in msg_callback, or at
// progress() time — by then, both transcript and secrets are available.
// ---------------------------------------------------------------------------

extern "C" void boringssl_extract_ch_sh_and_secrets(void *agent_opaque)
{
    SSL *ssl = boringssl_agent_get_ssl(agent_opaque);
    if (ssl == NULL)
    {
        return;
    }

    // Extract CH+SH transcript from BoringSSL patch's thread-local storage
    uint8_t hash[EVP_MAX_MD_SIZE];
    size_t hash_len = sizeof(hash);
    int ret = PUFFIN_extract_ch_sh_transcript(ssl, hash, &hash_len);
    if (ret && hash_len > 0)
    {
        boringssl_agent_set_ch_sh_transcript(agent_opaque, hash, hash_len);
        boringssl_agent_fixup_ch_sh_transcript(agent_opaque, hash, hash_len);
    }

    // Capture handshake secret from PUFFIN patch's thread-local storage.
    {
        uint8_t hs_secret[EVP_MAX_MD_SIZE];
        size_t hs_secret_len = sizeof(hs_secret);
        int got = PUFFIN_extract_handshake_secret(ssl, hs_secret, &hs_secret_len);
        if (got && hs_secret_len > 0)
        {
            boringssl_agent_set_handshake_secret(agent_opaque, hs_secret, hs_secret_len);
        }
    }
}

// ---------------------------------------------------------------------------
// boringssl_snapshot_secrets — captures TLS 1.3 secrets while hs is alive.
//
// Called from msg_callback when a Finished message is seen.  At that point
// hs is still alive and secrets are fully derived.  After SSL_do_handshake()
// returns, BoringSSL frees hs, making these secrets inaccessible.
// ---------------------------------------------------------------------------

extern "C" void boringssl_snapshot_secrets(void *agent_opaque)
{
    SSL *ssl = boringssl_agent_get_ssl(agent_opaque);
    if (ssl == NULL || ssl->s3 == NULL || ssl->s3->hs == NULL)
    {
        return;
    }

    bssl::SSL_HANDSHAKE *hs = ssl->s3->hs.get();

    SnappedTLS13Secrets secrets;
    memset(&secrets, 0, sizeof(secrets));

    // Master secret (hs->secret at Finished time = master secret)
    secrets.master_secret_len = MIN(hs->secret.size(), (size_t)CLAIM_MAX_SECRET_SIZE);
    if (secrets.master_secret_len > 0)
    {
        memcpy(secrets.master_secret, hs->secret.data(), secrets.master_secret_len);
    }

    // Client application traffic secret
    secrets.client_app_traffic_len =
        MIN(hs->client_traffic_secret_0.size(), (size_t)CLAIM_MAX_SECRET_SIZE);
    if (secrets.client_app_traffic_len > 0)
    {
        memcpy(secrets.client_app_traffic,
               hs->client_traffic_secret_0.data(),
               secrets.client_app_traffic_len);
    }

    // Server application traffic secret
    secrets.server_app_traffic_len =
        MIN(hs->server_traffic_secret_0.size(), (size_t)CLAIM_MAX_SECRET_SIZE);
    if (secrets.server_app_traffic_len > 0)
    {
        memcpy(secrets.server_app_traffic,
               hs->server_traffic_secret_0.data(),
               secrets.server_app_traffic_len);
    }

    // Exporter master secret (on ssl->s3, not hs)
    secrets.exporter_secret_len =
        MIN(ssl->s3->exporter_secret.size(), (size_t)CLAIM_MAX_SECRET_SIZE);
    if (secrets.exporter_secret_len > 0)
    {
        memcpy(secrets.exporter_secret,
               ssl->s3->exporter_secret.data(),
               secrets.exporter_secret_len);
    }

    // Early traffic secret
    secrets.early_traffic_len = MIN(hs->early_traffic_secret.size(), (size_t)CLAIM_MAX_SECRET_SIZE);
    if (secrets.early_traffic_len > 0)
    {
        memcpy(secrets.early_traffic, hs->early_traffic_secret.data(), secrets.early_traffic_len);
    }

    // Signature algorithm (TLS wire format, e.g. 0x0804 for rsa_pss_rsae_sha256)
    secrets.signature_algorithm = hs->signature_algorithm;

    boringssl_agent_store_snapped_secrets(agent_opaque, &secrets);
}

// ---------------------------------------------------------------------------
// boringssl_fill_claim — populates a Claim struct from current SSL state.
//
// Called from progress() after SSL_do_handshake() returns, when the SSL
// state is stable.  The agent pointer provides access to cached randoms
// and stored secrets.
// ---------------------------------------------------------------------------

extern "C" void boringssl_fill_claim(void *agent_opaque, Claim *claim)
{
    if (agent_opaque == NULL || claim == NULL)
    {
        return;
    }

    // Access agent fields through C accessor functions.
    SSL *ssl = boringssl_agent_get_ssl(agent_opaque);
    if (ssl == NULL)
    {
        return;
    }

    // TLS version
    uint16_t version = SSL_version(ssl);
    if (version == TLS1_3_VERSION)
    {
        claim->version.data = CLAIM_TLS_VERSION_V1_3;
    }
    else if (version == TLS1_2_VERSION)
    {
        claim->version.data = CLAIM_TLS_VERSION_V1_2;
    }
    else
    {
        claim->version.data = CLAIM_TLS_VERSION_UNDEFINED;
    }

    if (claim->version.data == CLAIM_TLS_VERSION_UNDEFINED)
    {
        return;
    }

    // write flag: 0 when handshake is complete (for Finished claims)
    claim->write = SSL_in_init(ssl) ? 1 : 0;

    // server flag
    claim->server = SSL_is_server(ssl);

    // Peer authentication
    X509 *peer_cert = SSL_get_peer_certificate(ssl);
    claim->peer_authentication = (peer_cert != NULL);

    // Session ID
    const SSL_SESSION *session = SSL_get_session(ssl);
    if (session != NULL)
    {
        unsigned int sess_id_len = 0;
        const unsigned char *sess_id = SSL_SESSION_get_id(session, &sess_id_len);
        if (sess_id != NULL && sess_id_len > 0)
        {
            claim->session_id.length = MIN(sess_id_len, CLAIM_SESSION_ID_LENGTH);
            memcpy(claim->session_id.data, sess_id, claim->session_id.length);
        }
    }

    // Client random: try SSL API, fall back to cached from msg_callback
    {
        size_t cr_len =
            SSL_get_client_random(ssl, claim->client_random.data, CLAIM_SESSION_ID_LENGTH);
        if (cr_len == 0)
        {
            const uint8_t *cached_cr = NULL;
            size_t cached_cr_len = 0;
            boringssl_agent_get_cached_client_random(agent_opaque, &cached_cr, &cached_cr_len);
            if (cached_cr != NULL && cached_cr_len > 0)
            {
                memcpy(claim->client_random.data,
                       cached_cr,
                       MIN(cached_cr_len, CLAIM_SESSION_ID_LENGTH));
            }
        }
    }

    // Server random: try SSL API, fall back to cached from msg_callback
    {
        size_t sr_len =
            SSL_get_server_random(ssl, claim->server_random.data, CLAIM_SESSION_ID_LENGTH);
        if (sr_len == 0)
        {
            const uint8_t *cached_sr = NULL;
            size_t cached_sr_len = 0;
            boringssl_agent_get_cached_server_random(agent_opaque, &cached_sr, &cached_sr_len);
            if (cached_sr != NULL && cached_sr_len > 0)
            {
                memcpy(claim->server_random.data,
                       cached_sr,
                       MIN(cached_sr_len, CLAIM_SESSION_ID_LENGTH));
            }
        }
    }

    // Own certificate
    {
        X509 *own_cert = SSL_get_certificate(ssl);
        if (own_cert != NULL)
        {
            unsigned char *der = NULL;
            int der_len = i2d_X509(own_cert, &der);
            if (der_len > 0 && der != NULL)
            {
                claim->cert.data_length = MIN(der_len, CLAIM_MAX_CERTIFICATE_LENGTH);
                memcpy(claim->cert.data, der, claim->cert.data_length);
                OPENSSL_free(der);
            }
            EVP_PKEY *pkey = X509_get_pubkey(own_cert);
            if (pkey != NULL)
            {
                claim->cert.key_length = EVP_PKEY_bits(pkey);
                int pkey_id = EVP_PKEY_id(pkey);
                switch (pkey_id)
                {
                case EVP_PKEY_RSA:
                    claim->cert.key_type = CLAIM_KEY_TYPE_RSA;
                    break;
                case EVP_PKEY_EC:
                    claim->cert.key_type = CLAIM_KEY_TYPE_EC;
                    break;
                case EVP_PKEY_ED25519:
                    claim->cert.key_type = CLAIM_KEY_TYPE_ED25519;
                    break;
                default:
                    claim->cert.key_type = CLAIM_KEY_TYPE_UNKNOWN;
                    break;
                }
                EVP_PKEY_free(pkey);
            }
        }
    }

    // Peer certificate
    if (peer_cert != NULL)
    {
        unsigned char *der = NULL;
        int der_len = i2d_X509(peer_cert, &der);
        if (der_len > 0 && der != NULL)
        {
            claim->peer_cert.data_length = MIN(der_len, CLAIM_MAX_CERTIFICATE_LENGTH);
            memcpy(claim->peer_cert.data, der, claim->peer_cert.data_length);
            OPENSSL_free(der);
        }
        EVP_PKEY *pkey = X509_get_pubkey(peer_cert);
        if (pkey != NULL)
        {
            claim->peer_cert.key_length = EVP_PKEY_bits(pkey);
            int pkey_id = EVP_PKEY_id(pkey);
            switch (pkey_id)
            {
            case EVP_PKEY_RSA:
                claim->peer_cert.key_type = CLAIM_KEY_TYPE_RSA;
                break;
            case EVP_PKEY_EC:
                claim->peer_cert.key_type = CLAIM_KEY_TYPE_EC;
                break;
            case EVP_PKEY_ED25519:
                claim->peer_cert.key_type = CLAIM_KEY_TYPE_ED25519;
                break;
            default:
                claim->peer_cert.key_type = CLAIM_KEY_TYPE_UNKNOWN;
                break;
            }
            EVP_PKEY_free(pkey);
        }
        X509_free(peer_cert);
    }

    // Secrets
    if (claim->version.data == CLAIM_TLS_VERSION_V1_2)
    {
        // TLS 1.2 master secret
        if (session != NULL)
        {
            size_t mk_len = SSL_SESSION_get_master_key(session,
                                                       claim->master_secret_12.secret,
                                                       CLAIM_MAX_SECRET_SIZE);
            (void)mk_len;
        }
    }
    else if (claim->version.data == CLAIM_TLS_VERSION_V1_3)
    {
        // Handshake secret: always from stored CH+SH data (PUFFIN patch).
        {
            const uint8_t *stored_hs = NULL;
            size_t stored_hs_len = 0;
            boringssl_agent_get_stored_handshake_secret(agent_opaque, &stored_hs, &stored_hs_len);
            if (stored_hs != NULL && stored_hs_len > 0)
            {
                memcpy(claim->handshake_secret.secret,
                       stored_hs,
                       MIN(stored_hs_len, (size_t)CLAIM_MAX_SECRET_SIZE));
            }
        }

        // Other TLS 1.3 secrets: prefer live hs internals (mid-handshake),
        // fall back to snapped secrets (hs freed after handshake completion).
        SnappedTLS13Secrets snapped;
        bool have_snapped = boringssl_agent_get_snapped_secrets(agent_opaque, &snapped);

        if (ssl->s3 != NULL && ssl->s3->hs != NULL)
        {
            bssl::SSL_HANDSHAKE *hs = ssl->s3->hs.get();

            auto copy_secret =
                [](ClaimSecret &dest, const bssl::InplaceVector<uint8_t, SSL_MAX_MD_SIZE> &src)
            {
                size_t len = src.size();
                if (len > 0)
                {
                    memcpy(dest.secret, src.data(), MIN(len, (size_t)CLAIM_MAX_SECRET_SIZE));
                }
            };

            copy_secret(claim->master_secret, hs->secret);
            copy_secret(claim->early_secret, hs->early_traffic_secret);
            copy_secret(claim->client_app_traffic_secret, hs->client_traffic_secret_0);
            copy_secret(claim->server_app_traffic_secret, hs->server_traffic_secret_0);
        }
        else if (have_snapped)
        {
            // hs freed after handshake — use snapped secrets
            if (snapped.master_secret_len > 0)
                memcpy(claim->master_secret.secret,
                       snapped.master_secret,
                       snapped.master_secret_len);
            if (snapped.client_app_traffic_len > 0)
                memcpy(claim->client_app_traffic_secret.secret,
                       snapped.client_app_traffic,
                       snapped.client_app_traffic_len);
            if (snapped.server_app_traffic_len > 0)
                memcpy(claim->server_app_traffic_secret.secret,
                       snapped.server_app_traffic,
                       snapped.server_app_traffic_len);
            if (snapped.early_traffic_len > 0)
                memcpy(claim->early_secret.secret,
                       snapped.early_traffic,
                       snapped.early_traffic_len);
        }

        // Exporter master secret: try live (ssl->s3), fall back to snapped
        if (ssl->s3 != NULL && ssl->s3->exporter_secret.size() > 0)
        {
            size_t elen = ssl->s3->exporter_secret.size();
            memcpy(claim->exporter_master_secret.secret,
                   ssl->s3->exporter_secret.data(),
                   MIN(elen, (size_t)CLAIM_MAX_SECRET_SIZE));
        }
        else if (have_snapped && snapped.exporter_secret_len > 0)
        {
            memcpy(claim->exporter_master_secret.secret,
                   snapped.exporter_secret,
                   snapped.exporter_secret_len);
        }
    }

    // Available ciphers.
    // BoringSSL's SSL_get_ciphers only returns TLS 1.2 ciphers.
    // TLS 1.3 ciphers are always enabled and must be added manually.
    {
        claim->available_ciphers.length = 0;

        // Add TLS 1.3 ciphers (always available in BoringSSL).
        // IANA IDs: AES-128-GCM=0x1301, AES-256-GCM=0x1302, CHACHA20=0x1303
        static const unsigned short tls13_ciphers[] = {0x1301, 0x1302, 0x1303};
        for (int i = 0; i < 3; ++i)
        {
            claim->available_ciphers.ciphers[claim->available_ciphers.length].data =
                tls13_ciphers[i];
            claim->available_ciphers.length++;
        }

        // Add TLS 1.2 ciphers from SSL_get_ciphers.
        STACK_OF(SSL_CIPHER) *ciphers = SSL_get_ciphers(ssl);
        if (ciphers != NULL)
        {
            int n = sk_SSL_CIPHER_num(ciphers);
            for (int i = 0; i < n && claim->available_ciphers.length < CLAIM_MAX_AVAILABLE_CIPHERS;
                 ++i)
            {
                const SSL_CIPHER *c = sk_SSL_CIPHER_value(ciphers, i);
                if (c != NULL)
                {
                    claim->available_ciphers.ciphers[claim->available_ciphers.length].data =
                        (unsigned short)(SSL_CIPHER_get_id(c) & 0xFFFF);
                    claim->available_ciphers.length++;
                }
            }
        }
    }

    // Chosen cipher
    {
        const SSL_CIPHER *chosen = SSL_get_current_cipher(ssl);
        if (chosen != NULL)
        {
            claim->chosen_cipher.data = (unsigned short)(SSL_CIPHER_get_id(chosen) & 0xFFFF);
        }
    }

    // Signature algorithm: read from snapped secrets (hs freed after handshake).
    // hs->signature_algorithm holds the TLS wire value (e.g. 0x0804 for rsa_pss_rsae_sha256).
    {
        SnappedTLS13Secrets snapped_sigalg;
        bool have_snapped_sigalg =
            boringssl_agent_get_snapped_secrets(agent_opaque, &snapped_sigalg);
        if (have_snapped_sigalg && snapped_sigalg.signature_algorithm != 0)
        {
            claim->signature_algorithm = (int)snapped_sigalg.signature_algorithm;
        }
    }

    // Transcript hash — current point in handshake (safe extraction)
    {
        int tlen =
            boringssl_extract_transcript_safe(ssl, claim->transcript.data, CLAIM_MAX_SECRET_SIZE);
        claim->transcript.length = tlen;
    }
}
