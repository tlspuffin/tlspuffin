/*
 * tlspuffin claim registration and extraction.
 *
 * Appended to ssl/ssl_lib.c by the vendor builder (see builder.cmake), so it can use the internal
 * SSL structures. The few differences between OpenSSL versions are hidden by the macros below.
 */
#include "puffin_claims.h"

#if OPENSSL_VERSION_NUMBER >= 0x30200000L
/* the connection state lives in a separate structure */
#define PUFFIN_CONN_T SSL_CONNECTION
#define PUFFIN_CONN(s) SSL_CONNECTION_FROM_SSL(s)
#else
#define PUFFIN_CONN_T SSL
#define PUFFIN_CONN(s) (s)
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#define PUFFIN_S3(c) ((c)->s3)
#else
#define PUFFIN_S3(c) (*(c)->s3)
#endif

/*
 * The claimed signature algorithm is the TLS code point since OpenSSL 3.4, the NID before.
 */
#if OPENSSL_VERSION_NUMBER >= 0x30400000L
#define PUFFIN_SIGALG(lu) ((lu)->sigalg)
#else
#define PUFFIN_SIGALG(lu) ((lu)->sig)
#endif

void register_claimer(const void *tls_like, void (*claim)(Claim claim, void *ctx), void *claim_ctx)
{
    SSL *ssl = ((SSL *)tls_like);
    PUFFIN_CONN_T *sc = PUFFIN_CONN(ssl);
    if (sc == NULL)
        return;

    sc->claim = claim;
    sc->claim_ctx = claim_ctx;

    /* makes the server keep the same identity for PSK tickets.
        int keys[80]= { 0 }; // 32 + 32 + 16
        SSL_CTX_set_tlsext_ticket_keys(ssl->ctx, keys, 80);
    */
}

void *deregister_claimer(const void *tls_like)
{
    SSL *ssl = ((SSL *)tls_like);
    PUFFIN_CONN_T *sc = PUFFIN_CONN(ssl);
    if (sc == NULL)
        return NULL;

    void *ret = sc->claim_ctx;

    sc->claim = NULL;
    sc->claim_ctx = NULL;
    return ret;
}

ClaimKeyType match_key_type(const EVP_PKEY *key)
{
    switch (EVP_PKEY_base_id(key))
    {
    default:
        return CLAIM_KEY_TYPE_UNKNOWN;
    case EVP_PKEY_RSA:
        return CLAIM_KEY_TYPE_RSA;
    case EVP_PKEY_DH:
        return CLAIM_KEY_TYPE_DH;
    case EVP_PKEY_EC:
        return CLAIM_KEY_TYPE_EC;
    case EVP_PKEY_POLY1305:
        return CLAIM_KEY_TYPE_POLY1305;
    case EVP_PKEY_SIPHASH:
        return CLAIM_KEY_TYPE_SIPHASH;
    case EVP_PKEY_X25519:
        return CLAIM_KEY_TYPE_X25519;
    case EVP_PKEY_ED25519:
        return CLAIM_KEY_TYPE_ED25519;
    case EVP_PKEY_X448:
        return CLAIM_KEY_TYPE_X448;
    case EVP_PKEY_ED448:
        return CLAIM_KEY_TYPE_ED448;
    case EVP_PKEY_DSA:
        return CLAIM_KEY_TYPE_DSA;
    }
}

int create_handshake_hash(SSL *s, unsigned char *out, size_t outlen, size_t *hashlen)
{
    EVP_MD_CTX *ctx = NULL;
    int ret = 0;

    PUFFIN_CONN_T *sc = PUFFIN_CONN(s);
    if (sc == NULL)
        goto err;

    EVP_MD_CTX *hdgst = PUFFIN_S3(sc).handshake_dgst;
    int hashleni = EVP_MD_CTX_size(hdgst);

    if (hashleni < 0 || (size_t)hashleni > outlen)
    {
        goto err;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
    {
        goto err;
    }

    if (!EVP_MD_CTX_copy_ex(ctx, hdgst) || EVP_DigestFinal_ex(ctx, out, NULL) <= 0)
    {
        goto err;
    }

    *hashlen = hashleni;

    ret = 1;
err:
    EVP_MD_CTX_free(ctx);
    return ret;
}

void fill_claim(SSL *s, Claim *claim)
{
    PUFFIN_CONN_T *sc = PUFFIN_CONN(s);
    if (sc == NULL)
        return;

    switch (sc->version)
    {
    case TLS1_2_VERSION:
        claim->version.data = CLAIM_TLS_VERSION_V1_2;
    case TLS1_3_VERSION:
        claim->version.data = CLAIM_TLS_VERSION_V1_3;
    default:
        claim->version.data = CLAIM_TLS_VERSION_UNDEFINED;
    }

    claim->server = sc->server;

    if (sc->session == 0 || sc->version == TLS1_3_VERSION)
    {
        // fallback for TLS 1.3, as session_id is not filled until the handshake is done
        claim->session_id.length = sc->tmp_session_id_len;
        memcpy(claim->session_id.data, sc->tmp_session_id, sc->tmp_session_id_len);
    }
    else
    {
        claim->session_id.length = sc->session->session_id_length;
        memcpy(claim->session_id.data, sc->session->session_id, 32);
    }
    memcpy(claim->client_random.data, PUFFIN_S3(sc).client_random, 32);
    memcpy(claim->server_random.data, PUFFIN_S3(sc).server_random, 32);

    // ciphers
    ClaimCiphers claim_ciphers = {0};
    STACK_OF(SSL_CIPHER) *ciphers = SSL_get_ciphers(s);
    int available_ciphers_len = sk_SSL_CIPHER_num(ciphers);
    claim_ciphers.length = available_ciphers_len;
    for (int j = 0; j < available_ciphers_len; ++j)
    {
        const SSL_CIPHER *c = sk_SSL_CIPHER_value(ciphers, j);
        if (j < CLAIM_MAX_AVAILABLE_CIPHERS)
        {
            claim_ciphers.ciphers[j].data = c->id & 0xffff;
        }
    }
    claim->available_ciphers = claim_ciphers;

    // cert
    const X509 *cert = SSL_get_certificate(s);
    if (cert != NULL)
    {
        const EVP_PKEY *cert_pkey = X509_get0_pubkey(cert);
        if (cert_pkey != NULL)
        {
            claim->cert.key_type = match_key_type(cert_pkey);
            claim->cert.key_length = EVP_PKEY_bits(cert_pkey);
            /*specific for RSA: RSA_bits(EVP_PKEY_get0_RSA(cert_key));*/
        }

        // no need to free "cert", only peer_cert needs to be cleared
    }

    // peer cert
    const X509 *peer_cert = SSL_get_peer_certificate(s);
    if (peer_cert != NULL)
    {
        const EVP_PKEY *peer_cert_pkey = X509_get0_pubkey(peer_cert);
        if (peer_cert_pkey != NULL)
        {
            claim->peer_cert.key_type = match_key_type(peer_cert_pkey);
            claim->peer_cert.key_length = EVP_PKEY_bits(peer_cert_pkey);
        }

        X509_free(peer_cert);
    }

    // tls 1.3 secrets
    memcpy(claim->early_secret.secret, sc->early_secret, EVP_MAX_MD_SIZE);
    memcpy(claim->handshake_secret.secret, sc->handshake_secret, EVP_MAX_MD_SIZE);
    memcpy(claim->master_secret.secret, sc->master_secret, EVP_MAX_MD_SIZE);
    memcpy(claim->resumption_master_secret.secret, sc->resumption_master_secret, EVP_MAX_MD_SIZE);
    memcpy(claim->client_finished_secret.secret, sc->client_finished_secret, EVP_MAX_MD_SIZE);
    memcpy(claim->server_finished_secret.secret, sc->server_finished_secret, EVP_MAX_MD_SIZE);
    memcpy(claim->server_finished_hash.secret, sc->server_finished_hash, EVP_MAX_MD_SIZE);
    memcpy(claim->handshake_traffic_hash.secret, sc->handshake_traffic_hash, EVP_MAX_MD_SIZE);
    memcpy(claim->client_app_traffic_secret.secret, sc->client_app_traffic_secret, EVP_MAX_MD_SIZE);
    memcpy(claim->server_app_traffic_secret.secret, sc->server_app_traffic_secret, EVP_MAX_MD_SIZE);
    memcpy(claim->exporter_master_secret.secret, sc->exporter_master_secret, EVP_MAX_MD_SIZE);
    memcpy(claim->early_exporter_master_secret.secret,
           sc->early_exporter_master_secret,
           EVP_MAX_MD_SIZE);

    // 1.2 secret
    if (sc->session != 0 && sc->version == TLS1_2_VERSION)
    {
        memcpy(claim->master_secret_12.secret,
               sc->session->master_key,
               sc->session->master_key_length);
    }

    // chosen cipher
    const SSL_CIPHER *new_cipher = PUFFIN_S3(sc).tmp.new_cipher;
    if (new_cipher != 0)
    {
        claim->chosen_cipher.data = new_cipher->id;
    }

    // signature algorithm
    const SIGALG_LOOKUP *lu =
        PUFFIN_S3(sc).tmp.sigalg; /* Signature algorithm openssl actually uses */
    if (lu != 0)
    {
        claim->signature_algorithm = PUFFIN_SIGALG(lu);
    }
    const SIGALG_LOOKUP *peer_lu =
        PUFFIN_S3(sc).tmp.peer_sigalg; /* Signature algorithm openssl actually uses */
    if (peer_lu != 0)
    {
        claim->peer_signature_algorithm = PUFFIN_SIGALG(peer_lu);
    }

    // temporary/ephemeral peer key
    const EVP_PKEY *peer_tmp_skey = PUFFIN_S3(sc).peer_tmp; // same as: SSL_get_peer_tmp_key
    if (peer_tmp_skey != 0)
    {
        claim->peer_tmp_skey_type = match_key_type(peer_tmp_skey);
        claim->peer_tmp_skey_security_bits = EVP_PKEY_security_bits(peer_tmp_skey);
    }

    // temporary/ephemeral peer key
    // todo this is cleared on TLS 1.2 after the receiving a ClientKeyExchange on the server -> tmp
    // is shortlived
    const EVP_PKEY *tmp_skey = PUFFIN_S3(sc).tmp.pkey; // same as: SSL_get_tmp_key
    if (tmp_skey != 0)
    {
        claim->tmp_skey_type = match_key_type(tmp_skey);
    }
    // TLS 1.3: Group ID of PUFFIN_S3(sc).tmp.pkey
    claim->tmp_skey_group_id = PUFFIN_S3(sc).group_id;
    /*    const TLS_GROUP_INFO *cinf = tls1_group_id_lookup(PUFFIN_S3(sc).group_id);
        if (cinf != 0) {
            const char *name = OBJ_nid2sn(cinf->nid);
            printf("%s\n", name);
        }*/

    // transcript
    if (PUFFIN_S3(sc).handshake_dgst != 0)
    {
        size_t hashlen = 0;
        create_handshake_hash(s, claim->transcript.data, EVP_MAX_MD_SIZE, &hashlen);
        claim->transcript.length = hashlen;
    }
}

/* TLS state to claim type, used by the PUFFIN_CLAIM_READ / PUFFIN_CLAIM_WRITE hooks. */
ClaimType puffin_read_claim_type(int hand_state)
{
    switch (hand_state)
    {
    default:
        return CLAIM_UNKNOWN;
    // from statem_clnt.c
    case TLS_ST_CR_SRVR_HELLO:
        return CLAIM_SERVER_HELLO;
    case TLS_ST_CR_CERT:
        return CLAIM_CERTIFICATE;
    case TLS_ST_CR_CERT_VRFY:
        return CLAIM_CERTIFICATE_VERIFY;
    case TLS_ST_CR_CERT_STATUS:
        return CLAIM_CERTIFICATE_STATUS;
    case TLS_ST_CR_KEY_EXCH:
        return CLAIM_KEY_EXCHANGE;
    case TLS_ST_CR_CERT_REQ:
        return CLAIM_CERTIFICATE_REQUEST;
    case TLS_ST_CR_SRVR_DONE:
        return CLAIM_SERVER_DONE;
    case TLS_ST_CR_CHANGE:
        return CLAIM_CCS;
    case TLS_ST_CR_SESSION_TICKET:
        return CLAIM_SESSION_TICKET;
    case TLS_ST_CR_FINISHED:
        return CLAIM_FINISHED;
    case TLS_ST_CR_HELLO_REQ:
        return CLAIM_HELLO_REQUEST;
    case TLS_ST_CR_ENCRYPTED_EXTENSIONS:
        return CLAIM_ENCRYPTED_EXTENSIONS;
    case TLS_ST_CR_KEY_UPDATE:
        return CLAIM_KEY_UPDATE;
    // from statem_srvr.c
    case TLS_ST_SR_CLNT_HELLO:
        return CLAIM_CLIENT_HELLO;
    case TLS_ST_SR_END_OF_EARLY_DATA:
        return CLAIM_END_OF_EARLY_DATA;
    case TLS_ST_SR_CERT:
        return CLAIM_CERTIFICATE;
    case TLS_ST_SR_KEY_EXCH:
        return CLAIM_KEY_EXCHANGE;
    case TLS_ST_SR_CERT_VRFY:
        return CLAIM_CERTIFICATE_VERIFY;
    case TLS_ST_SR_CHANGE:
        return CLAIM_CCS;
    case TLS_ST_SR_FINISHED:
        return CLAIM_FINISHED;
    case TLS_ST_SR_KEY_UPDATE:
        return CLAIM_KEY_UPDATE;
    }
}

ClaimType puffin_write_claim_type(int hand_state)
{
    switch (hand_state)
    {
    default:
        return CLAIM_UNKNOWN;
    // from statem_clnt.c
    case TLS_ST_CW_CHANGE:
        return CLAIM_CCS;
    case TLS_ST_CW_CLNT_HELLO:
        return CLAIM_CLIENT_HELLO;
    case TLS_ST_CW_END_OF_EARLY_DATA:
        return CLAIM_END_OF_EARLY_DATA;
    case TLS_ST_CW_CERT:
        return CLAIM_CERTIFICATE;
    case TLS_ST_CW_KEY_EXCH:
        return CLAIM_KEY_EXCHANGE;
    case TLS_ST_CW_CERT_VRFY:
        return CLAIM_CERTIFICATE_VERIFY;
    case TLS_ST_CW_FINISHED:
        return CLAIM_FINISHED;
    case TLS_ST_CW_KEY_UPDATE:
        return CLAIM_KEY_UPDATE;
    // from statem_srv.c
    case TLS_ST_SW_CHANGE:
        return CLAIM_CCS;
    case TLS_ST_SW_HELLO_REQ:
        return CLAIM_HELLO_REQUEST;
    case TLS_ST_SW_SRVR_HELLO:
        return CLAIM_SERVER_HELLO;
    case TLS_ST_SW_CERT:
        return CLAIM_CERTIFICATE;
    case TLS_ST_SW_CERT_VRFY:
        return CLAIM_CERTIFICATE_VERIFY;
    case TLS_ST_SW_KEY_EXCH:
        return CLAIM_KEY_EXCHANGE;
    case TLS_ST_SW_CERT_REQ:
        return CLAIM_CERTIFICATE_REQUEST;
    case TLS_ST_SW_SRVR_DONE:
        return CLAIM_SERVER_DONE;
    case TLS_ST_SW_SESSION_TICKET:
        return CLAIM_SESSION_TICKET;
    case TLS_ST_SW_CERT_STATUS:
        return CLAIM_CERTIFICATE_STATUS;
    case TLS_ST_SW_FINISHED:
        return CLAIM_FINISHED;
    case TLS_ST_EARLY_DATA:
        return CLAIM_EARLY_DATA;
    case TLS_ST_SW_ENCRYPTED_EXTENSIONS:
        return CLAIM_ENCRYPTED_EXTENSIONS;
    case TLS_ST_SW_KEY_UPDATE:
        return CLAIM_KEY_UPDATE;
    }
}
