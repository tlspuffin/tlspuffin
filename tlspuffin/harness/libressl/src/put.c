#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <claim-interface.h>
#include <puffin/tls.h>

// LibreSSL internal headers (installed by builder.cmake).
// These macros are normally defined by LibreSSL's own CMakeLists.txt.
#ifndef __BEGIN_HIDDEN_DECLS
#define __BEGIN_HIDDEN_DECLS
#endif
#ifndef __END_HIDDEN_DECLS
#define __END_HIDDEN_DECLS
#endif
#include <libressl_internal/ssl_local.h>

#include "bindings.h"
#include "rng.h"

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

extern const TLS_PUT_INTERFACE *REGISTER();

struct AGENT_TYPE
{
    uint8_t name;

    TLS_AGENT_DESCRIPTOR descriptor;

    SSL_CTX *ctx;
    SSL *ssl;

    BIO *in;
    BIO *out;

    const CLAIMER_CB *claimer;

// Queue of pending claims for deferred emission
#define CLAIM_QUEUE_SIZE 8
    struct
    {
        enum ClaimType type;
        uint8_t transcript[EVP_MAX_MD_SIZE];
        int transcript_len;
    } claimQueue[8];
    int claimQueueLen;

    // Cached randoms captured from handshake messages.
    // TLS 1.3 in LibreSSL doesn't store server_random in s3 on the client side.
    unsigned char cached_server_random[SSL3_RANDOM_SIZE];
    unsigned char cached_client_random[SSL3_RANDOM_SIZE];
    bool has_cached_server_random;
    bool has_cached_client_random;
};

AGENT openssl_create(const TLS_AGENT_DESCRIPTOR *descriptor);
AGENT openssl_create_client(const TLS_AGENT_DESCRIPTOR *descriptor);
AGENT openssl_create_server(const TLS_AGENT_DESCRIPTOR *descriptor);
void openssl_destroy(AGENT agent);
RESULT openssl_progress(AGENT agent);
RESULT openssl_reset(AGENT agent, uint8_t new_name, uint8_t use_clear);
bool openssl_is_successful(AGENT agent);
const char *openssl_describe_state(AGENT agent);
RESULT openssl_add_inbound(AGENT agent, const uint8_t *bytes, size_t length, size_t *written);
RESULT openssl_take_outbound(AGENT agent, uint8_t *bytes, size_t max_length, size_t *readbytes);
void openssl_register_claimer(AGENT agent, const CLAIMER_CB *claimer);

static TLSVersion openssl_get_tls_version(SSL *ssl);

static RESULT get_result(AGENT agent, int retcode, bool allow_would_block);

static bool recreate_ssl_from_agent_ctx(AGENT agent);
static AGENT make_agent(SSL_CTX *ssl_ctx, const TLS_AGENT_DESCRIPTOR *descriptor);

static bool is_numeric_token(const char *token)
{
    if (token == NULL || token[0] == '\0')
    {
        return false;
    }

    for (const unsigned char *p = (const unsigned char *)token; *p != '\0'; ++p)
    {
        if (!isdigit(*p))
        {
            return false;
        }
    }

    return true;
}

static bool append_str(char *out, size_t out_len, size_t *offset, const char *s)
{
    size_t s_len = strlen(s);
    if (*offset + s_len + 1 > out_len)
    {
        return false;
    }
    memcpy(out + *offset, s, s_len);
    *offset += s_len;
    out[*offset] = '\0';
    return true;
}

static bool append_char(char *out, size_t out_len, size_t *offset, char c)
{
    if (*offset + 2 > out_len)
    {
        return false;
    }
    out[*offset] = c;
    *offset += 1;
    out[*offset] = '\0';
    return true;
}

// Convert a TLS 1.2 IANA cipher name (e.g. TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
// into the OpenSSL/LibreSSL cipher alias (e.g. ECDHE-RSA-AES128-GCM-SHA256).
static bool map_tls12_iana_cipher_name(const char *iana, char *out, size_t out_len)
{
    if (iana == NULL || out == NULL || out_len == 0)
    {
        return false;
    }

    const char *prefix = "TLS_";
    const char *with_sep = "_WITH_";
    if (strncmp(iana, prefix, strlen(prefix)) != 0)
    {
        return false;
    }

    const char *with_pos = strstr(iana, with_sep);
    if (with_pos == NULL)
    {
        return false;
    }

    size_t lhs_len = (size_t)(with_pos - (iana + strlen(prefix)));
    const char *rhs = with_pos + strlen(with_sep);
    if (lhs_len == 0 || rhs[0] == '\0' || lhs_len >= 128)
    {
        return false;
    }

    char lhs[128] = {0};
    memcpy(lhs, iana + strlen(prefix), lhs_len);

    char rhs_copy[256] = {0};
    if (strlen(rhs) >= sizeof(rhs_copy))
    {
        return false;
    }
    memcpy(rhs_copy, rhs, strlen(rhs));

    out[0] = '\0';
    size_t offset = 0;

    // Key-exchange/auth part: ECDHE_RSA -> ECDHE-RSA
    for (size_t i = 0; i < lhs_len; ++i)
    {
        char ch = lhs[i] == '_' ? '-' : lhs[i];
        if (!append_char(out, out_len, &offset, ch))
        {
            return false;
        }
    }
    if (!append_char(out, out_len, &offset, '-'))
    {
        return false;
    }

    char *tokens[32] = {0};
    size_t token_count = 0;
    char *saveptr = NULL;
    for (char *tok = strtok_r(rhs_copy, "_", &saveptr); tok != NULL;
         tok = strtok_r(NULL, "_", &saveptr))
    {
        if (token_count >= (sizeof(tokens) / sizeof(tokens[0])))
        {
            return false;
        }
        tokens[token_count++] = tok;
    }

    if (token_count == 0)
    {
        return false;
    }

    size_t i = 0;
    if (token_count >= 2 &&
        ((strcmp(tokens[0], "AES") == 0) || (strcmp(tokens[0], "CAMELLIA") == 0) ||
         (strcmp(tokens[0], "ARIA") == 0)) &&
        is_numeric_token(tokens[1]))
    {
        // AES_128 -> AES128, CAMELLIA_256 -> CAMELLIA256, etc.
        if (!append_str(out, out_len, &offset, tokens[0]) ||
            !append_str(out, out_len, &offset, tokens[1]))
        {
            return false;
        }
        i = 2;
    }
    else
    {
        if (!append_str(out, out_len, &offset, tokens[0]))
        {
            return false;
        }
        i = 1;
    }

    for (; i < token_count; ++i)
    {
        if (strcmp(tokens[i], "CCM") == 0 && (i + 1) < token_count &&
            strcmp(tokens[i + 1], "8") == 0)
        {
            if (!append_str(out, out_len, &offset, "-CCM8"))
            {
                return false;
            }
            ++i;
            continue;
        }

        if (!append_char(out, out_len, &offset, '-') ||
            !append_str(out, out_len, &offset, tokens[i]))
        {
            return false;
        }
    }

    return true;
}

static bool map_tls13_cipher_name(const char *in, char *out, size_t out_len)
{
    if (in == NULL || out == NULL || out_len == 0)
    {
        return false;
    }

    if (strcmp(in, "TLS_AES_256_GCM_SHA384") == 0 || strcmp(in, "TLS13-AES-256-GCM-SHA384") == 0)
    {
        snprintf(out, out_len, "%s", "TLS_AES_256_GCM_SHA384");
        return true;
    }
    if (strcmp(in, "TLS_CHACHA20_POLY1305_SHA256") == 0 ||
        strcmp(in, "TLS13-CHACHA20-POLY1305-SHA256") == 0)
    {
        snprintf(out, out_len, "%s", "TLS_CHACHA20_POLY1305_SHA256");
        return true;
    }
    if (strcmp(in, "TLS_AES_128_GCM_SHA256") == 0 || strcmp(in, "TLS13-AES-128-GCM-SHA256") == 0)
    {
        snprintf(out, out_len, "%s", "TLS_AES_128_GCM_SHA256");
        return true;
    }
    if (strcmp(in, "TLS_AES_128_CCM_SHA256") == 0 || strcmp(in, "TLS13-AES-128-CCM-SHA256") == 0)
    {
        snprintf(out, out_len, "%s", "TLS_AES_128_CCM_SHA256");
        return true;
    }
    if (strcmp(in, "TLS_AES_128_CCM_8_SHA256") == 0 ||
        strcmp(in, "TLS13-AES-128-CCM-8-SHA256") == 0)
    {
        snprintf(out, out_len, "%s", "TLS_AES_128_CCM_8_SHA256");
        return true;
    }

    return false;
}

// Translate a colon-separated TLS1.2 cipher list; unknown entries are preserved as-is.
static void map_tls12_iana_cipher_list(const char *input, char *output, size_t output_len)
{
    if (output_len == 0)
    {
        return;
    }

    output[0] = '\0';
    if (input == NULL)
    {
        return;
    }

    char input_copy[16384] = {0};
    size_t input_len = strlen(input);
    if (input_len >= sizeof(input_copy))
    {
        // Fall back to the original input if it does not fit in the temp buffer.
        snprintf(output, output_len, "%s", input);
        return;
    }
    memcpy(input_copy, input, input_len);

    size_t out_off = 0;
    bool first = true;
    char *saveptr = NULL;
    for (char *tok = strtok_r(input_copy, ":", &saveptr); tok != NULL;
         tok = strtok_r(NULL, ":", &saveptr))
    {
        if (tok[0] == '\0')
        {
            continue;
        }

        char mapped[256] = {0};
        const char *chosen = tok;
        if (map_tls12_iana_cipher_name(tok, mapped, sizeof(mapped)))
        {
            chosen = mapped;
        }

        if (!first)
        {
            if (!append_char(output, output_len, &out_off, ':'))
            {
                break;
            }
        }
        if (!append_str(output, output_len, &out_off, chosen))
        {
            break;
        }
        first = false;
    }

    if (output[0] == '\0')
    {
        snprintf(output, output_len, "%s", input);
    }
}

// Normalize a colon-separated TLS 1.3 cipher list to names accepted by LibreSSL.
// Non-TLS1.3 entries are skipped so mixed lists (e.g. when tls_version=Both) do not
// make SSL_CTX_set_ciphersuites fail.
static void map_tls13_cipher_list(const char *input, char *output, size_t output_len)
{
    if (output_len == 0)
    {
        return;
    }

    output[0] = '\0';
    if (input == NULL)
    {
        return;
    }

    char input_copy[16384] = {0};
    size_t input_len = strlen(input);
    if (input_len >= sizeof(input_copy))
    {
        snprintf(output, output_len, "%s", input);
        return;
    }
    memcpy(input_copy, input, input_len);

    size_t out_off = 0;
    bool first = true;
    char *saveptr = NULL;
    for (char *tok = strtok_r(input_copy, ":", &saveptr); tok != NULL;
         tok = strtok_r(NULL, ":", &saveptr))
    {
        if (tok[0] == '\0')
        {
            continue;
        }

        char mapped[128] = {0};
        if (!map_tls13_cipher_name(tok, mapped, sizeof(mapped)))
        {
            continue;
        }

        if (!first)
        {
            if (!append_char(output, output_len, &out_off, ':'))
            {
                break;
            }
        }
        if (!append_str(output, output_len, &out_off, mapped))
        {
            break;
        }
        first = false;
    }

    // Keep behavior permissive if we could not normalize anything.
    if (output[0] == '\0')
    {
        snprintf(output, output_len, "%s", input);
    }
}

// Extract the current transcript hash from the SSL handshake state.
// Returns the hash length, or 0 if not available.
static int extract_transcript_hash(AGENT agent, uint8_t *buffer, size_t buffer_size)
{
    if (agent == NULL || agent->ssl == NULL)
    {
        return 0;
    }

    // Try the maintained handshake_hash first (available after cipher negotiation).
    size_t out_len = 0;
    if (tls1_transcript_hash_value(agent->ssl, buffer, buffer_size, &out_len))
    {
        return (int)out_len;
    }

    // Fallback: in TLS 1.3, the handshake_hash may not be initialized yet
    // (e.g., at the ServerHello point). Compute the hash from the raw transcript.
    const unsigned char *data = NULL;
    size_t data_len = 0;
    if (tls1_transcript_data(agent->ssl, &data, &data_len) && data != NULL && data_len > 0)
    {
        const EVP_MD *md = NULL;
        if (!ssl_get_handshake_evp_md(agent->ssl, &md) || md == NULL)
        {
            // Before cipher negotiation, fall back to SHA-256
            md = EVP_sha256();
        }

        unsigned int hash_len = 0;
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        if (mdctx != NULL)
        {
            if (EVP_DigestInit_ex(mdctx, md, NULL) && EVP_DigestUpdate(mdctx, data, data_len) &&
                EVP_DigestFinal_ex(mdctx, buffer, &hash_len))
            {
                EVP_MD_CTX_free(mdctx);
                return (int)hash_len;
            }
            EVP_MD_CTX_free(mdctx);
        }
    }

    return 0;
}

// Populate a Claim structure from the current LibreSSL state
static void fill_claim(AGENT agent, struct Claim *claim)
{
    // TLS version
    claim->version.data = openssl_get_tls_version(agent->ssl);
    if (claim->version.data == CLAIM_TLS_VERSION_UNDEFINED)
    {
        return;
    }

    // write flag: used to determine outbound direction for Finished claims
    // Only Finished claims with write == 0 are used to check security properties.
    claim->write = !openssl_is_successful(agent);

    // server flag
    claim->server = agent->ssl->server;

    // peer_authentication: true only when a peer certificate was actually received
    X509 *peer_check = SSL_get_peer_certificate(agent->ssl);
    claim->peer_authentication = (peer_check != NULL);
    if (peer_check != NULL)
    {
        X509_free(peer_check);
    }

    // Session ID
    unsigned int sess_id_len = 0;
    const unsigned char *sess_id = SSL_SESSION_get_id(SSL_get_session(agent->ssl), &sess_id_len);
    if (sess_id != NULL && sess_id_len > 0)
    {
        claim->session_id.length = MIN(sess_id_len, CLAIM_SESSION_ID_LENGTH);
        memcpy(claim->session_id.data, sess_id, claim->session_id.length);
    }

    // Client random: try s3 first, fall back to cached from msg_callback
    size_t cr_len =
        SSL_get_client_random(agent->ssl, claim->client_random.data, CLAIM_SESSION_ID_LENGTH);
    if (cr_len == 0 || claim->client_random.data[0] == 0)
    {
        // Check if s3 has it (may be zero in TLS 1.3)
        bool all_zero = true;
        for (int i = 0; i < CLAIM_SESSION_ID_LENGTH && all_zero; i++)
            all_zero = (claim->client_random.data[i] == 0);
        if (all_zero && agent->has_cached_client_random)
        {
            memcpy(claim->client_random.data,
                   agent->cached_client_random,
                   MIN(SSL3_RANDOM_SIZE, CLAIM_SESSION_ID_LENGTH));
        }
    }

    // Server random: try s3 first, fall back to cached from msg_callback
    size_t sr_len =
        SSL_get_server_random(agent->ssl, claim->server_random.data, CLAIM_SESSION_ID_LENGTH);
    if (sr_len == 0 || claim->server_random.data[0] == 0)
    {
        bool all_zero = true;
        for (int i = 0; i < CLAIM_SESSION_ID_LENGTH && all_zero; i++)
            all_zero = (claim->server_random.data[i] == 0);
        if (all_zero && agent->has_cached_server_random)
        {
            memcpy(claim->server_random.data,
                   agent->cached_server_random,
                   MIN(SSL3_RANDOM_SIZE, CLAIM_SESSION_ID_LENGTH));
        }
    }

    // Own certificate
    claim->cert.key_length = 0;
    claim->cert.data_length = 0;
    X509 *own_cert = SSL_get_certificate(agent->ssl);
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

    // Peer certificate
    claim->peer_cert.key_length = 0;
    claim->peer_cert.data_length = 0;
    X509 *peer_cert = SSL_get_peer_certificate(agent->ssl);
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
    SSL_SESSION *session = SSL_get_session(agent->ssl);
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
        // TLS 1.3 secrets from LibreSSL internal state
        SSL_HANDSHAKE *hs = &agent->ssl->s3->hs;
        struct tls13_secrets *secrets = hs->tls13.secrets;

        if (secrets != NULL)
        {
            if (secrets->extracted_master.data != NULL)
            {
                memcpy(claim->master_secret.secret,
                       secrets->extracted_master.data,
                       MIN(secrets->extracted_master.len, CLAIM_MAX_SECRET_SIZE));
            }
            if (secrets->extracted_early.data != NULL)
            {
                memcpy(claim->early_secret.secret,
                       secrets->extracted_early.data,
                       MIN(secrets->extracted_early.len, CLAIM_MAX_SECRET_SIZE));
            }
            if (secrets->extracted_handshake.data != NULL)
            {
                memcpy(claim->handshake_secret.secret,
                       secrets->extracted_handshake.data,
                       MIN(secrets->extracted_handshake.len, CLAIM_MAX_SECRET_SIZE));
            }
            if (secrets->client_application_traffic.data != NULL)
            {
                memcpy(claim->client_app_traffic_secret.secret,
                       secrets->client_application_traffic.data,
                       MIN(secrets->client_application_traffic.len, CLAIM_MAX_SECRET_SIZE));
            }
            if (secrets->server_application_traffic.data != NULL)
            {
                memcpy(claim->server_app_traffic_secret.secret,
                       secrets->server_application_traffic.data,
                       MIN(secrets->server_application_traffic.len, CLAIM_MAX_SECRET_SIZE));
            }
            if (secrets->exporter_master.data != NULL)
            {
                memcpy(claim->exporter_master_secret.secret,
                       secrets->exporter_master.data,
                       MIN(secrets->exporter_master.len, CLAIM_MAX_SECRET_SIZE));
            }
            if (secrets->early_exporter_master.data != NULL)
            {
                memcpy(claim->early_exporter_master_secret.secret,
                       secrets->early_exporter_master.data,
                       MIN(secrets->early_exporter_master.len, CLAIM_MAX_SECRET_SIZE));
            }
            if (secrets->client_handshake_traffic.data != NULL)
            {
                memcpy(claim->handshake_traffic_hash.secret,
                       secrets->client_handshake_traffic.data,
                       MIN(secrets->client_handshake_traffic.len, CLAIM_MAX_SECRET_SIZE));
            }
        }
    }

    // Available ciphers
    STACK_OF(SSL_CIPHER) *ciphers = SSL_get_ciphers(agent->ssl);
    if (ciphers != NULL)
    {
        int n = sk_SSL_CIPHER_num(ciphers);
        claim->available_ciphers.length = 0;
        for (int i = 0; i < n && claim->available_ciphers.length < CLAIM_MAX_AVAILABLE_CIPHERS; ++i)
        {
            const SSL_CIPHER *c = sk_SSL_CIPHER_value(ciphers, i);
            if (c != NULL)
            {
                // SSL_CIPHER_get_id returns a 32-bit value with the protocol prefix;
                // the low 16 bits are the cipher suite value.
                claim->available_ciphers.ciphers[claim->available_ciphers.length].data =
                    (unsigned short)(SSL_CIPHER_get_id(c) & 0xFFFF);
                claim->available_ciphers.length++;
            }
        }
    }

    // Chosen cipher
    const SSL_CIPHER *chosen = SSL_get_current_cipher(agent->ssl);
    if (chosen != NULL)
    {
        claim->chosen_cipher.data = (unsigned short)(SSL_CIPHER_get_id(chosen) & 0xFFFF);
    }

    // Transcript hash
    claim->transcript.length =
        extract_transcript_hash(agent, claim->transcript.data, CLAIM_MAX_SECRET_SIZE);
}

static void default_claimer_notify(void *context, Claim *claim)
{
    _log(PUFFIN.trace, "call to default claimer `notify`");
};

static void default_claimer_destroy(void *context)
{
    _log(PUFFIN.trace, "call to default claimer `destroy`");
};

static const CLAIMER_CB DEFAULT_CLAIMER_CB = {.context = NULL,
                                              .notify = default_claimer_notify,
                                              .destroy = default_claimer_destroy};

// Message callback to track handshake message types for transcript emission.
// Called by LibreSSL whenever a handshake message is sent or received.
static void libressl_msg_callback(int write_p,
                                  int version,
                                  int content_type,
                                  const void *buf,
                                  size_t len,
                                  SSL *ssl,
                                  void *arg)
{
    AGENT agent = (AGENT)arg;
    if (agent == NULL)
    {
        return;
    }

    uint8_t type = 0;
    // content_type 22 = handshake
    if (content_type == 22 && len >= 1)
    {
        type = *((const uint8_t *)buf);
    }

    // Capture randoms from handshake messages.
    // Format: type(1) + length(3) + body. Body starts with version(2) + random(32).
    // So random is at offset 6 in buf, needs at least 38 bytes.
    if (content_type == 22 && type == 0x01 && len >= 38) // ClientHello
    {
        memcpy(agent->cached_client_random, (const uint8_t *)buf + 6, SSL3_RANDOM_SIZE);
        agent->has_cached_client_random = true;
    }
    if (content_type == 22 && type == 0x02 && len >= 38) // ServerHello
    {
        memcpy(agent->cached_server_random, (const uint8_t *)buf + 6, SSL3_RANDOM_SIZE);
        agent->has_cached_server_random = true;
    }

    // Prevent LibreSSL from zeroing intermediate TLS 1.3 secrets
    // (extracted_early, extracted_handshake, extracted_master).
    // The `insecure` flag disables explicit_bzero in tls13_key_schedule.c.
    {
        struct tls13_secrets *secrets = agent->ssl->s3->hs.tls13.secrets;
        if (secrets != NULL)
        {
            secrets->insecure = 1;
        }
    }

// Helper macro to enqueue a claim type
// Enqueue a claim type and snapshot the current transcript hash.
// The transcript hash must be captured now because it advances
// as the handshake continues within the same SSL_do_handshake() call.
#define ENQUEUE_CLAIM(agent, ctype)                                                                \
    do                                                                                             \
    {                                                                                              \
        if ((agent)->claimQueueLen < CLAIM_QUEUE_SIZE)                                             \
        {                                                                                          \
            int _idx = (agent)->claimQueueLen++;                                                   \
            (agent)->claimQueue[_idx].type = (ctype);                                              \
            (agent)->claimQueue[_idx].transcript_len =                                             \
                extract_transcript_hash((agent),                                                   \
                                        (agent)->claimQueue[_idx].transcript,                      \
                                        sizeof((agent)->claimQueue[_idx].transcript));             \
        }                                                                                          \
    } while (0)

    if (write_p == 0) // packet being read
    {
        switch (type)
        {
        case 0x02: // ServerHello
            ENQUEUE_CLAIM(agent, CLAIM_TRANSCRIPT_CH_SH);
            break;
        case 0x0b: // Certificate
            ENQUEUE_CLAIM(agent, CLAIM_TRANSCRIPT_CH_CERT);
            break;
        case 0x0f: // CertificateVerify
            ENQUEUE_CLAIM(agent, CLAIM_CERTIFICATE_VERIFY);
            break;
        case 0x14: // Finished (from peer)
            if (agent->descriptor.role == CLIENT)
            {
                ENQUEUE_CLAIM(agent, CLAIM_TRANSCRIPT_CH_SERVER_FIN);
            }
            else
            {
                ENQUEUE_CLAIM(agent, CLAIM_TRANSCRIPT_CH_CLIENT_FIN);
            }
            break;
        default:
            break;
        }
    }
    else // write_p == 1, packet being sent
    {
        switch (type)
        {
        case 0x02: // Server sending ServerHello
            ENQUEUE_CLAIM(agent, CLAIM_TRANSCRIPT_CH_SH);
            break;
        case 0x14: // Finished (outbound)
            if (agent->descriptor.role == SERVER)
            {
                ENQUEUE_CLAIM(agent, CLAIM_TRANSCRIPT_CH_SERVER_FIN);
            }
            else
            {
                ENQUEUE_CLAIM(agent, CLAIM_TRANSCRIPT_CH_CLIENT_FIN);
            }
            break;
        default:
            break;
        }
    }

#undef ENQUEUE_CLAIM
}

static const TLS_PUT_INTERFACE OPENSSL_PUT = {
    .create = openssl_create,
    .rng_reseed = rng_reseed,
    .supports = NULL,

    .agent_interface =
        {
            .destroy = openssl_destroy,
            .progress = openssl_progress,
            .reset = openssl_reset,
            .describe_state = openssl_describe_state,
            .is_state_successful = openssl_is_successful,
            .register_claimer = openssl_register_claimer,

            .add_inbound = openssl_add_inbound,
            .take_outbound = openssl_take_outbound,
        },
};

const TLS_PUT_INTERFACE *REGISTER()
{
    libressl_init();

    return &OPENSSL_PUT;
}

const char *version_str[] = {"V1_3", "V1_2", "Both"};
const char *type_str[] = {"client", "server"};

AGENT openssl_create(const TLS_AGENT_DESCRIPTOR *descriptor)
{
    _log(PUFFIN.debug,
         "descriptor %u version: %s type: %s",
         descriptor->name,
         version_str[descriptor->tls_version],
         type_str[descriptor->role]);

    if ((descriptor->tls_version == V1_3 || descriptor->tls_version == Both) &&
        TLS1_3_VERSION == TLS_UNSUPPORTED_VERSION)
    {
        _log(PUFFIN.error,
             "unsupported TLS version: %s for config %s",
             version_str[V1_3],
             version_str[descriptor->tls_version]);
        return NULL;
    }

    if ((descriptor->tls_version == V1_2 || descriptor->tls_version == Both) &&
        TLS1_2_VERSION == TLS_UNSUPPORTED_VERSION)
    {
        _log(PUFFIN.error,
             "unsupported TLS version: %s for config %s",
             version_str[V1_2],
             version_str[descriptor->tls_version]);
        return NULL;
    }

    if (descriptor->role == CLIENT)
    {
        return openssl_create_client(descriptor);
    }

    if (descriptor->role == SERVER)
    {
        return openssl_create_server(descriptor);
    }

    _log(PUFFIN.error,
         "unknown agent type for descriptor %u: %u",
         descriptor->name,
         descriptor->role);
    return NULL;
}

void openssl_destroy(AGENT agent)
{
    if (agent->claimer != NULL)
    {
        agent->claimer->destroy(agent->claimer->context);
    }

    SSL_CTX_free(agent->ctx);
    SSL_free(agent->ssl);
    free(agent);
}

RESULT openssl_progress(AGENT agent)
{
    RESULT result;

    if (!openssl_is_successful(agent))
    {
        // not connected yet -> do handshake
        int ret = SSL_do_handshake(agent->ssl);
        result = get_result(agent, ret, true);
    }
    else
    {
        // trigger another read
        uint8_t buf[128];
        int ret = SSL_read(agent->ssl, &buf, 128);
        if (ret > 0)
        {
            result = get_result(agent, SSL_ERROR_NONE, false);
        }
        else
        {
            result = get_result(agent, ret, true);
        }
    }

    // Process queued claims (deferred from msg_callback)
    if (agent->claimer != NULL && agent->claimer->notify != NULL && agent->claimQueueLen > 0)
    {
        for (int i = 0; i < agent->claimQueueLen; i++)
        {
            enum ClaimType ct = agent->claimQueue[i].type;
            int tlen = agent->claimQueue[i].transcript_len;

            // For Finished-related transcripts, also emit a CLAIM_FINISHED first
            if (ct == CLAIM_TRANSCRIPT_CH_CLIENT_FIN || ct == CLAIM_TRANSCRIPT_CH_SERVER_FIN)
            {
                struct Claim claim = {};
                claim.typ = CLAIM_FINISHED;
                fill_claim(agent, &claim);
                // Override transcript with the one captured at event time
                if (tlen > 0)
                {
                    memcpy(claim.transcript.data, agent->claimQueue[i].transcript, tlen);
                    claim.transcript.length = tlen;
                }
                agent->claimer->notify(agent->claimer->context, &claim);
            }

            // Emit the transcript/message claim itself
            struct Claim claim = {};
            claim.typ = ct;
            fill_claim(agent, &claim);
            // Override transcript with the one captured at event time
            if (tlen > 0)
            {
                memcpy(claim.transcript.data, agent->claimQueue[i].transcript, tlen);
                claim.transcript.length = tlen;
            }
            agent->claimer->notify(agent->claimer->context, &claim);
        }
        agent->claimQueueLen = 0;
    }

    return result;
}

static void setup_msg_callback(AGENT agent)
{
    SSL_set_msg_callback(agent->ssl, libressl_msg_callback);
    SSL_set_msg_callback_arg(agent->ssl, agent);
}

static bool recreate_ssl_from_agent_ctx(AGENT agent)
{
    SSL_free(agent->ssl); // also frees BIOs (SSL_set_bio transferred ownership)
    agent->ssl = NULL;
    agent->in = NULL;
    agent->out = NULL;

    agent->ssl = SSL_new(agent->ctx);
    if (agent->ssl == NULL)
    {
        return false;
    }
    agent->in = BIO_new(BIO_s_mem());
    agent->out = BIO_new(BIO_s_mem());
    SSL_set_bio(agent->ssl, agent->in, agent->out);
    agent->claimQueueLen = 0;
    agent->has_cached_server_random = false;
    agent->has_cached_client_random = false;
    memset(agent->cached_server_random, 0, SSL3_RANDOM_SIZE);
    memset(agent->cached_client_random, 0, SSL3_RANDOM_SIZE);
    setup_msg_callback(agent);

    if (agent->descriptor.role == CLIENT)
    {
        SSL_set_connect_state(agent->ssl);
    }
    else
    {
        SSL_set_accept_state(agent->ssl);
    }
    return true;
}

RESULT openssl_reset(AGENT agent, uint8_t new_name, uint8_t use_clear)
{
    if (agent == NULL)
    {
        _log(PUFFIN.error, "fatal error openssl_reset called with agent == NULL");
        return PUFFIN.make_result(RESULT_ERROR_OTHER,
                                  "fatal error openssl_reset called with agent == NULL");
    }

    if (use_clear)
    {
        agent->name = new_name;
        agent->claimQueueLen = 0;
        int ret = SSL_clear(agent->ssl);
        setup_msg_callback(agent);
        if (ret == 0)
        {
            return get_result(agent, SSL_ERROR_SSL, false);
        }
    }
    else
    {
        agent->descriptor.name = new_name;
        if (!recreate_ssl_from_agent_ctx(agent))
        {
            _log(PUFFIN.error, "fatal error in openssl_reset, make_agent returned NULL");
            return PUFFIN.make_result(RESULT_ERROR_OTHER,
                                      "fatal error in openssl_reset, make_agent returned NULL");
        }
    }
    return get_result(agent, SSL_ERROR_NONE, false);
}

const char *openssl_describe_state(AGENT agent)
{
    return SSL_state_string_long(agent->ssl);
}

bool openssl_is_successful(AGENT agent)
{
    return (strstr(openssl_describe_state(agent), "SSL negotiation finished successfully") != NULL);
}

void openssl_register_claimer(AGENT agent, const CLAIMER_CB *claimer)
{
    if (agent->claimer != NULL)
    {
        agent->claimer->destroy(agent->claimer->context);
    }

    CLAIMER_CB *new_claimer = malloc(sizeof(CLAIMER_CB));
    memcpy(new_claimer, claimer, sizeof(CLAIMER_CB));
    agent->claimer = new_claimer;
}

RESULT openssl_add_inbound(AGENT agent, const uint8_t *bytes, size_t length, size_t *written)
{
    int ret = BIO_write_ex(agent->in, bytes, length, written);

    return get_result(agent, ret, false);
}

RESULT openssl_take_outbound(AGENT agent, uint8_t *bytes, size_t max_length, size_t *readbytes)
{
    int ret = BIO_read_ex(agent->out, bytes, max_length, readbytes);

    return get_result(agent, ret, false);
}

static TLSVersion openssl_get_tls_version(SSL *ssl)
{
    const int tls_version = SSL_version(ssl);
    if (tls_version == TLS1_2_VERSION)
    {
        return CLAIM_TLS_VERSION_V1_2;
    }
    else if (tls_version == TLS1_3_VERSION)
    {
        return CLAIM_TLS_VERSION_V1_3;
    }
    return CLAIM_TLS_VERSION_UNDEFINED;
}

void openssl_set_protocol_version(SSL_CTX *ssl_ctx, int version)
{
    switch (version)
    {
    case V1_3:
        SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
        SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);
        break;
    case V1_2:
        SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_2_VERSION);
        break;
    case Both:
        SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);
        break;
    default:
        _log(PUFFIN.error, "unknown TLS version: %u", version);
    }
}

AGENT openssl_create_client(const TLS_AGENT_DESCRIPTOR *descriptor)
{
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_method());

#ifdef SSL_OP_ENABLE_MIDDLEBOX_COMPAT
    SSL_CTX_clear_options(ssl_ctx, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);
#endif

    openssl_set_protocol_version(ssl_ctx, descriptor->tls_version);

    if (descriptor->tls_version == V1_3 || descriptor->tls_version == Both)
    {
        char mapped_tls13[16384] = {0};
        map_tls13_cipher_list(descriptor->cipher_string_tls13, mapped_tls13, sizeof(mapped_tls13));
        SSL_CTX_set_ciphersuites(ssl_ctx, mapped_tls13);
    }
    if (descriptor->tls_version == V1_2 || descriptor->tls_version == Both)
    {
        char mapped_cipher_list[16384] = {0};
        map_tls12_iana_cipher_list(descriptor->cipher_string_tls12,
                                   mapped_cipher_list,
                                   sizeof(mapped_cipher_list));
        SSL_CTX_set_cipher_list(ssl_ctx, mapped_cipher_list);
    }

    if (descriptor->group_list != NULL)
    {
        SSL_CTX_set1_groups_list(ssl_ctx, descriptor->group_list);
    }
    else
    {
        // LibreSSL 4.2.1 may offer post-quantum or non-standard groups by default.
        // Constrain to groups the fuzzer's Rust code supports.
        SSL_CTX_set1_groups_list(ssl_ctx, "X25519:P-256:P-384");
    }

    // LibreSSL 4.2.1 does not provide SSL_CTX_set1_sigalgs_list (or SSL_CTX_set1_sigalgs).
    // The sigalgs_list field from the descriptor is therefore ignored here.
    // Sigalgs preference is instead patched at build time (see patch_sigalgs.cmake).

    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);

    if (descriptor->client_authentication)
    {
        ssl_ctx = set_cert(ssl_ctx, descriptor->cert);
        ssl_ctx = set_pkey(ssl_ctx, descriptor->pkey);
        if (ssl_ctx == NULL)
        {
            return NULL;
        }
    }

    if (descriptor->server_authentication)
    {
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

        ssl_ctx = set_store(ssl_ctx, descriptor->store, descriptor->store_length);
        if (ssl_ctx == NULL)
        {
            return NULL;
        }
    }

    AGENT agent = make_agent(ssl_ctx, descriptor);
    if (agent == NULL)
    {
        return NULL;
    }

    SSL_set_connect_state(agent->ssl);

    return agent;
}

AGENT openssl_create_server(const TLS_AGENT_DESCRIPTOR *descriptor)
{
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_method());

#ifdef SSL_OP_ALLOW_NO_DHE_KEX
    SSL_CTX_set_options(ssl_ctx, SSL_OP_ALLOW_NO_DHE_KEX);
#endif
#ifdef SSL_OP_ENABLE_MIDDLEBOX_COMPAT
    SSL_CTX_clear_options(ssl_ctx, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);
#endif

    openssl_set_protocol_version(ssl_ctx, descriptor->tls_version);

#ifdef SSL_CTX_set_ecdh_auto
    SSL_CTX_set_ecdh_auto(ssl_ctx, 1);
#endif

    if (descriptor->tls_version == V1_3 || descriptor->tls_version == Both)
    {
        char mapped_tls13[16384] = {0};
        map_tls13_cipher_list(descriptor->cipher_string_tls13, mapped_tls13, sizeof(mapped_tls13));
        SSL_CTX_set_ciphersuites(ssl_ctx, mapped_tls13);
    }
    if (descriptor->tls_version == V1_2 || descriptor->tls_version == Both)
    {
        char mapped_cipher_list[16384] = {0};
        map_tls12_iana_cipher_list(descriptor->cipher_string_tls12,
                                   mapped_cipher_list,
                                   sizeof(mapped_cipher_list));
        SSL_CTX_set_cipher_list(ssl_ctx, mapped_cipher_list);
    }

    if (descriptor->group_list != NULL)
    {
        SSL_CTX_set1_groups_list(ssl_ctx, descriptor->group_list);
    }
    else
    {
        SSL_CTX_set1_groups_list(ssl_ctx, "X25519:P-256:P-384");
    }

    // LibreSSL 4.2.1 does not provide SSL_CTX_set1_sigalgs_list (or SSL_CTX_set1_sigalgs).
    // The sigalgs_list field from the descriptor is therefore ignored here.
    // Sigalgs preference is instead patched at build time (see patch_sigalgs.cmake).

    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);

    ssl_ctx = set_cert(ssl_ctx, descriptor->cert);
    ssl_ctx = set_pkey(ssl_ctx, descriptor->pkey);
    if (ssl_ctx == NULL)
    {
        return NULL;
    }

    if (descriptor->client_authentication)
    {
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

        ssl_ctx = set_store(ssl_ctx, descriptor->store, descriptor->store_length);
        if (ssl_ctx == NULL)
        {
            return NULL;
        }
    }

    AGENT agent = make_agent(ssl_ctx, descriptor);
    if (agent == NULL)
    {
        return NULL;
    }

    SSL_set_accept_state(agent->ssl);

    return agent;
}

static AGENT make_agent(SSL_CTX *ssl_ctx, const TLS_AGENT_DESCRIPTOR *descriptor)
{
    SSL *ssl = SSL_new(ssl_ctx);

    AGENT agent = malloc(sizeof(struct AGENT_TYPE));
    agent->name = descriptor->name;
    agent->ssl = ssl;
    agent->in = BIO_new(BIO_s_mem());
    agent->out = BIO_new(BIO_s_mem());

    agent->claimer = &DEFAULT_CLAIMER_CB;
    agent->claimQueueLen = 0;
    agent->has_cached_server_random = false;
    agent->has_cached_client_random = false;
    memset(agent->cached_server_random, 0, SSL3_RANDOM_SIZE);
    memset(agent->cached_client_random, 0, SSL3_RANDOM_SIZE);

    SSL_set_bio(agent->ssl, agent->in, agent->out);
    memcpy(&(agent->descriptor), descriptor, sizeof(TLS_AGENT_DESCRIPTOR));

    agent->ctx = ssl_ctx;

    // Register msg_callback for handshake state tracking
    setup_msg_callback(agent);

    return agent;
}

static RESULT get_result(AGENT agent, int retcode, bool allow_would_block)
{
    int ssl_ecode = SSL_get_error(agent->ssl, retcode);

    char *reason = get_error_reason();
    char *error_type;
    RESULT_CODE res = RESULT_OK;

    switch (ssl_ecode)
    {
    case SSL_ERROR_NONE:
        error_type = strdup("no error");
        break;
    case SSL_ERROR_ZERO_RETURN:
        error_type = strdup("SSL_ERROR_ZERO_RETURN");
        break;
    case SSL_ERROR_WANT_CONNECT:
        error_type = strdup("SSL_ERROR_WANT_CONNECT");
        if (!allow_would_block)
        {
            res = RESULT_IO_WOULD_BLOCK;
        }
        break;
    case SSL_ERROR_WANT_ACCEPT:
        error_type = strdup("SSL_ERROR_WANT_ACCEPT");
        if (!allow_would_block)
        {
            res = RESULT_IO_WOULD_BLOCK;
        }
        break;
    case SSL_ERROR_WANT_X509_LOOKUP:
        error_type = strdup("SSL_ERROR_WANT_X509_LOOKUP");
        if (!allow_would_block)
        {
            res = RESULT_IO_WOULD_BLOCK;
        }
        break;
#ifdef SSL_ERROR_WANT_ASYNC
    case SSL_ERROR_WANT_ASYNC:
        error_type = strdup("SSL_ERROR_WANT_ASYNC");
        if (!allow_would_block)
        {
            res = RESULT_IO_WOULD_BLOCK;
        }
        break;
#endif
#ifdef SSL_ERROR_WANT_ASYNC_JOB
    case SSL_ERROR_WANT_ASYNC_JOB:
        error_type = strdup("SSL_ERROR_WANT_ASYNC_JOB");
        if (!allow_would_block)
        {
            res = RESULT_IO_WOULD_BLOCK;
        }
        break;
#endif
#ifdef SSL_ERROR_WANT_CLIENT_HELLO_CB
    case SSL_ERROR_WANT_CLIENT_HELLO_CB:
        error_type = strdup("SSL_ERROR_WANT_CLIENT_HELLO_CB");
        break;
#endif
    case SSL_ERROR_SYSCALL:
        error_type = strdup("SSL_ERROR_SYSCALL");
        break;
    case SSL_ERROR_SSL:
        error_type = strdup("SSL_ERROR_SSL");
        res = RESULT_ERROR_OTHER;
        break;
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
        error_type = strdup("IO_WOULD_BLOCK");
        break;
    default:
        error_type = malloc(32 * sizeof(char));
        snprintf(error_type, 32, "UNKNOWN SSL ERROR %d", ssl_ecode);
        res = RESULT_ERROR_OTHER;
    }

    char *msg;
    if (strlen(reason) > 0)
    {
        msg = malloc((strlen(error_type) + strlen(reason) + 9) * sizeof(char));
        snprintf(msg,
                 strlen(error_type) + strlen(reason) + 9,
                 "%s (%d): %s",
                 error_type,
                 ssl_ecode,
                 reason);
    }
    else
    {
        msg = malloc((strlen(error_type) + 19) * sizeof(char));
        snprintf(msg, strlen(error_type) + 19, "%s (%d): no message", error_type, ssl_ecode);
    }
    RESULT result = PUFFIN.make_result(res, msg);
    free(reason);
    free(msg);
    free(error_type);
    return result;
}
