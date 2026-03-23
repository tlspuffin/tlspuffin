#include "claims.h"
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include "ssl/internal.h"
#include <string.h>
#include <unordered_map>

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

// ---------------------------------------------------------------------------
// Per-SSL storage for data captured at tls13_derive_handshake_secrets time.
//
// PUFFIN_store_ch_sh_transcript is called from within BoringSSL at the exact
// moment when:
//   - hs->transcript  = hash(ClientHello || ServerHello)   [CH+SH transcript]
//   - hs->secret      = HKDF-Extract(derived_early, DHE)   [handshake secret]
//
// Both values must be captured here because:
//   - hs->transcript advances past this state immediately after
//   - hs->secret is overwritten by tls13_advance_key_schedule when deriving
//     the master secret before CLAIM_FINISHED fires
// ---------------------------------------------------------------------------

struct PuffinHandshakeState {
    uint8_t transcript[EVP_MAX_MD_SIZE];
    size_t  transcript_len;
    uint8_t handshake_secret[EVP_MAX_MD_SIZE];
    size_t  handshake_secret_len;
};

static std::unordered_map<const SSL *, PuffinHandshakeState> g_puffin_state;

// Called from ssl/tls13_enc.cc :: tls13_derive_handshake_secrets
extern "C" void PUFFIN_store_ch_sh_transcript(const SSL *ssl,
                                               const uint8_t *hash,
                                               size_t hash_len) {
    PuffinHandshakeState s = {};

    // Transcript hash (CH+SH)
    s.transcript_len = MIN(hash_len, sizeof(s.transcript));
    memcpy(s.transcript, hash, s.transcript_len);

    // HKDF-extracted handshake secret: hs->secret at this exact call site
    // is the handshake secret (after tls13_advance_key_schedule with DHE,
    // before the second advance that produces the master secret).
    bssl::SSL_HANDSHAKE *hs = ssl->s3->hs.get();
    if (hs != nullptr) {
        size_t slen = hs->secret.size();
        s.handshake_secret_len = MIN(slen, sizeof(s.handshake_secret));
        memcpy(s.handshake_secret, hs->secret.data(), s.handshake_secret_len);
    }

    g_puffin_state[ssl] = s;
}

extern "C" void boringssl_clear_ch_sh_transcript(const SSL *ssl) {
    g_puffin_state.erase(ssl);
}

extern "C" void boringssl_fill_claim(const SSL *ssl, Claim *claim) {
    if (!ssl) return;

    memset(claim, 0, sizeof(Claim));

    // TLS Version
    uint16_t version = SSL_version(ssl);
    if (version == TLS1_3_VERSION) {
        claim->version.data = CLAIM_TLS_VERSION_V1_3;
    } else if (version == TLS1_2_VERSION) {
        claim->version.data = CLAIM_TLS_VERSION_V1_2;
    } else {
        claim->version.data = CLAIM_TLS_VERSION_UNDEFINED;
    }

    claim->server = ssl->server;

    // Randoms
    if (ssl->s3) {
        memcpy(claim->client_random.data, ssl->s3->client_random, SSL3_RANDOM_SIZE);
        memcpy(claim->server_random.data, ssl->s3->server_random, SSL3_RANDOM_SIZE);
    }

    // Session ID
    SSL_SESSION *session = SSL_get_session(ssl);
    if (session) {
        claim->session_id.length = session->session_id.size();
        memcpy(claim->session_id.data, session->session_id.data(),
               MIN(claim->session_id.length, CLAIM_SESSION_ID_LENGTH));

        // TLS 1.2 Master Secret
        if (version <= TLS1_2_VERSION) {
            size_t len = session->secret.size();
            memcpy(claim->master_secret_12.secret, session->secret.data(),
                   MIN(len, CLAIM_MAX_SECRET_SIZE));
        }
    }

    // TLS 1.3 Secrets
    if (ssl->s3) {
        if (ssl->s3->hs) {
            bssl::SSL_HANDSHAKE *hs = ssl->s3->hs.get();

            auto copy_secret = [](ClaimSecret &dest,
                                  const bssl::InplaceVector<uint8_t, SSL_MAX_MD_SIZE> &src) {
                size_t len = src.size();
                memcpy(dest.secret, src.data(), MIN(len, CLAIM_MAX_SECRET_SIZE));
            };

            // handshake_secret field = HKDF-extracted handshake secret.
            // Use the value stored by PUFFIN_store_ch_sh_transcript if available
            // (captured before hs->secret was overwritten by master secret derivation).
            // Fall back to current hs->secret only if no stored state yet.
            auto it = g_puffin_state.find(ssl);
            if (it != g_puffin_state.end() && it->second.handshake_secret_len > 0) {
                size_t slen = MIN(it->second.handshake_secret_len,
                                  (size_t)CLAIM_MAX_SECRET_SIZE);
                memcpy(claim->handshake_secret.secret,
                       it->second.handshake_secret, slen);
            } else {
                // Fallback: hs->secret at this point may already be master_secret,
                // but use it as best-effort.
                copy_secret(claim->handshake_secret, hs->secret);
            }

            // master_secret = current hs->secret at Finished time = master secret.
            copy_secret(claim->master_secret, hs->secret);

            copy_secret(claim->early_secret, hs->early_traffic_secret);
            copy_secret(claim->client_app_traffic_secret, hs->client_traffic_secret_0);
            copy_secret(claim->server_app_traffic_secret, hs->server_traffic_secret_0);
        }

        // exporter master secret (lives in ssl->s3 after application secrets are derived)
        {
            size_t elen = ssl->s3->exporter_secret.size();
            if (elen > 0) {
                memcpy(claim->exporter_master_secret.secret,
                       ssl->s3->exporter_secret.data(),
                       MIN(elen, CLAIM_MAX_SECRET_SIZE));
            }
        }
    }

    // Cipher
    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
    if (cipher) {
        claim->chosen_cipher.data = (unsigned short)(SSL_CIPHER_get_id(cipher) & 0xFFFF);
    }

    // Transcript extraction (current point in handshake)
    size_t transcript_len = CLAIM_MAX_SECRET_SIZE;
    ERR_clear_error();
    if (PUFFIN_extract_transcript((SSL*)ssl, claim->transcript.data, &transcript_len)) {
        claim->transcript.length = transcript_len;
    } else {
        ERR_clear_error();
    }
}

extern "C" void boringssl_fill_claim_for_message(const SSL *ssl,
                                                   Claim *claim,
                                                   const uint8_t *msg,
                                                   size_t msg_len,
                                                   int append_msg_to_transcript) {
    ClaimType preserved_type = claim->typ;
    int preserved_write = claim->write;
    boringssl_fill_claim(ssl, claim);
    claim->typ = preserved_type;
    claim->write = preserved_write;
    if (!ssl || !claim) return;

    // For CH+SH transcript: use the hash stored by PUFFIN_store_ch_sh_transcript,
    // which was captured at the exact right point in tls13_derive_handshake_secrets.
    if (preserved_type == CLAIM_TRANSCRIPT_CH_SH) {
        auto it = g_puffin_state.find(ssl);
        if (it != g_puffin_state.end() && it->second.transcript_len > 0) {
            size_t tlen = MIN(it->second.transcript_len, (size_t)CLAIM_MAX_SECRET_SIZE);
            memcpy(claim->transcript.data, it->second.transcript, tlen);
            claim->transcript.length = (int)tlen;
            return;
        }
        // Fall through to live computation if no stored state yet.
    }

    if (!ssl->s3 || !ssl->s3->hs) {
        return;
    }

    bssl::SSL_HANDSHAKE *hs = ssl->s3->hs.get();
    const EVP_MD *md = hs->transcript.Digest();
    if (md == nullptr) {
        return;
    }

    bssl::ScopedEVP_MD_CTX md_ctx;
    if (!hs->transcript.CopyToHashContext(md_ctx.get(), md)) {
        ERR_clear_error();
        return;
    }

    if (append_msg_to_transcript && msg != nullptr && msg_len > 0) {
        if (!EVP_DigestUpdate(md_ctx.get(), msg, msg_len)) {
            ERR_clear_error();
            return;
        }
    }

    unsigned int digest_len = 0;
    if (!EVP_DigestFinal_ex(md_ctx.get(), claim->transcript.data, &digest_len)) {
        ERR_clear_error();
        return;
    }
    claim->transcript.length = (int)MIN((size_t)digest_len, (size_t)CLAIM_MAX_SECRET_SIZE);
}
