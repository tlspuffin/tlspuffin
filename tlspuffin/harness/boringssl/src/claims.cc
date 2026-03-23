#include "claims.h"
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include "ssl/internal.h"
#include <string.h>

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

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
        memcpy(claim->session_id.data, session->session_id.data(), MIN(claim->session_id.length, CLAIM_SESSION_ID_LENGTH));

        // TLS 1.2 Master Secret
        if (version <= TLS1_2_VERSION) {
            size_t len = session->secret.size();
            memcpy(claim->master_secret_12.secret, session->secret.data(), MIN(len, CLAIM_MAX_SECRET_SIZE));
        }
    }

    // TLS 1.3 Secrets
    if (ssl->s3 && ssl->s3->hs) {
        bssl::SSL_HANDSHAKE *hs = ssl->s3->hs.get();
        
        auto copy_secret = [](ClaimSecret &dest, const bssl::InplaceVector<uint8_t, SSL_MAX_MD_SIZE> &src) {
            size_t len = src.size();
            memcpy(dest.secret, src.data(), MIN(len, CLAIM_MAX_SECRET_SIZE));
        };

        copy_secret(claim->early_secret, hs->early_traffic_secret);
        copy_secret(claim->handshake_secret, hs->client_handshake_secret);
        copy_secret(claim->master_secret, hs->secret);
        copy_secret(claim->client_app_traffic_secret, hs->client_traffic_secret_0);
        copy_secret(claim->server_app_traffic_secret, hs->server_traffic_secret_0);
    }
    
    // Cipher
    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
    if (cipher) {
        claim->chosen_cipher.data = (unsigned short)(SSL_CIPHER_get_id(cipher) & 0xFFFF);
    }

    // Transcript extraction
    size_t transcript_len = CLAIM_MAX_SECRET_SIZE;
    ERR_clear_error();
    if (PUFFIN_extract_transcript((SSL*)ssl, claim->transcript.data, &transcript_len)) {
        claim->transcript.length = transcript_len;
    } else {
        // Transcript is not always initialized when callbacks fire.
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

