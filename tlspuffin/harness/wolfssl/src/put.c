#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/internal.h>

#include <puffin/puffin.h>
#include <puffin/tls.h>

#include <claim-interface.h>

#include <string.h>
#include <sys/time.h>

#define USE_CUSTOM_PRNG
#define CLOCKVALUE_DEFAULT 1742309173;

static uint8_t * rng_reseed_buffer = NULL;
static size_t rng_reseed_buffer_length = 0;
#ifdef USE_CUSTOM_PRNG
static word32 clock_value = 0;
#endif

struct AGENT_TYPE {
  uint8_t name;

  WOLFSSL *ssl;

  WOLFSSL_BIO *in;
  WOLFSSL_BIO *out;

  CLAIMER_CB const claimer;

  bool handshake_done;
  enum ClaimType transcriptType;
};

static ClaimKeyType map_keysum_claimkeytype(enum Key_Sum key) {
  switch(key) {
    case DSAk:
      return CLAIM_KEY_TYPE_DSA;
    case RSAk:
      return CLAIM_KEY_TYPE_RSA;
    case ECDSAk:
      return CLAIM_KEY_TYPE_UNKNOWN;
    case ED25519k:
      return CLAIM_KEY_TYPE_ED25519;
    case X25519k:
      return CLAIM_KEY_TYPE_X25519;
    case ED448k:
      return CLAIM_KEY_TYPE_ED448;
    case X448k:
      return CLAIM_KEY_TYPE_X448;
    case DHk:
      return CLAIM_KEY_TYPE_DH;
    case FALCON_LEVEL1k:
      return CLAIM_KEY_TYPE_UNKNOWN;
    case FALCON_LEVEL5k:
      return CLAIM_KEY_TYPE_UNKNOWN;
    default:
      return CLAIM_KEY_TYPE_UNKNOWN;
  }
}

static int extract_current_transcript(AGENT agent, unsigned char* buffer, int bufferSize) {
  if (agent == NULL) {
    _log(PUFFIN.warn, "agent is NULL");
    return 0;
  }
  if (agent->ssl == NULL) {
    _log(PUFFIN.warn, "agent->ssl is NULL");
    return 0;
  }
  if (agent->ssl->hsHashes == NULL) {
    _log(PUFFIN.warn, "agent->ssl->hsHashes is NULL");
    return 0;
  }
  if (bufferSize < WC_SHA256_DIGEST_SIZE) {
    _log(PUFFIN.warn, "buffer size for SHA256 digest is too small");
    return 0;
  }

  if (wc_Sha256GetHash(&agent->ssl->hsHashes->hashSha256, buffer) == 0) {
    return WC_SHA256_DIGEST_SIZE;
  } else {
    _log(PUFFIN.warn, "wc_Sha256GetHash failed");
    return 0;
  }
}

static void fill_claim(AGENT agent, struct Claim* claim) { 
  char* error_msg = "no error";

  if (agent->ssl->version.major != SSLv3_MAJOR) {
    _log(PUFFIN.warn, "not a tls ssl object");
    return;
  }
  switch (agent->ssl->version.minor) {
    case TLSv1_2_MINOR:
      claim->version.data = CLAIM_TLS_VERSION_V1_2;
      break;
    case TLSv1_3_MINOR:
      claim->version.data = CLAIM_TLS_VERSION_V1_3;
      break;
    default:
      _log(PUFFIN.warn, "unsupported tls version");
      return;
  }

  claim->server = agent->ssl->options.side == WOLFSSL_SERVER_END;

#if LIBWOLFSSL_VERSION_HEX >= 0x05003000
  WOLFSSL_SESSION* session = agent->ssl->session;
#else
  WOLFSSL_SESSION* session = &(agent->ssl->session);
#endif
  byte session_size = session->sessionIDSz;
  if (session_size > CLAIM_SESSION_ID_LENGTH) {
    session_size = CLAIM_SESSION_ID_LENGTH;
    _log(PUFFIN.warn, "not enough space in session buffer in claim");
  }
  // Working ?
  claim->session_id.length = session_size;
  memcpy(claim->session_id.data, session->sessionID, 
      claim->session_id.length);

  int buffer_size = wolfSSL_get_client_random(agent->ssl, NULL, 0);
  if (buffer_size > 0) {
    if (buffer_size > CLAIM_SESSION_ID_LENGTH) {
    buffer_size = CLAIM_SESSION_ID_LENGTH;
      _log(PUFFIN.warn, "not enough space in client random buffer in claim");
  }
    wolfSSL_get_client_random(agent->ssl, claim->client_random.data, 
      buffer_size);
  } else {
    _log(PUFFIN.warn, "unable to get client random buffer");
  }

  buffer_size = wolfSSL_get_server_random(agent->ssl, NULL, 0);
  if (buffer_size > 0) {
    if (buffer_size > CLAIM_SESSION_ID_LENGTH) {
    buffer_size = CLAIM_SESSION_ID_LENGTH;
      _log(PUFFIN.warn, "not enough space in server random buffer in claim");
  }
    wolfSSL_get_server_random(agent->ssl, claim->server_random.data, 
      buffer_size);
  } else {
    _log(PUFFIN.warn, "unable to get server random buffer");
  }

  STACK_OF(SSL_CIPHER) *ciphers = wolfSSL_get_ciphers_compat(agent->ssl);
  if (ciphers != NULL) {
  int available_ciphers_len = wolfSSL_sk_SSL_CIPHER_num(ciphers);
    if (available_ciphers_len != WOLFSSL_FATAL_ERROR) {
      if (available_ciphers_len > CLAIM_MAX_AVAILABLE_CIPHERS) {
        available_ciphers_len = CLAIM_MAX_AVAILABLE_CIPHERS;
    _log(PUFFIN.warn, "not enough space in ciphers list in claim");
  }
  claim->available_ciphers.length = available_ciphers_len;
  for (int i=0; i<available_ciphers_len; ++i) {
    SSL_CIPHER const *cipher = wolfSSL_sk_SSL_CIPHER_value(ciphers, i);
        if (cipher != NULL) {
      claim->available_ciphers.ciphers[i].data = 
          (unsigned short)((((short)cipher->cipherSuite0) << 8) + cipher->cipherSuite);
        } else {
          _log(PUFFIN.warn, "wolfSSL_sk_SSL_CIPHER_value return a NULL value");
    }
  }
    } else {
      _log(PUFFIN.warn, "sk_SSL_CIPHER_num return WOLFSSL_FATAL_ERROR");
    }
  } else {
    _log(PUFFIN.warn, "wolfSSL_get_ciphers_compat return NULL");
  }

  // cert
  WOLFSSL_X509 *cert = wolfSSL_get_certificate(agent->ssl);
  if (cert != NULL) {
    int key_type = wolfSSL_X509_get_pubkey_type(cert);
    if (key_type != WOLFSSL_FAILURE) {
      WOLFSSL_EVP_PKEY const *cert_pkey = wolfSSL_X509_get_pubkey(cert);
      if (cert_pkey != NULL) {
        claim->cert.key_length = wolfSSL_EVP_PKEY_bits(cert_pkey);
        if (claim->cert.key_length != 0) {
          claim->cert.key_type = map_keysum_claimkeytype((enum Key_Sum)key_type);
        }
      } else {
        _log(PUFFIN.warn, "wolfSSL_X509_get_pubkey return NULL");
      }
    }
  } else {
    _log(PUFFIN.warn, "wolfSSL_get_certificate return NULL");
  }

  // peer cert
  WOLFSSL_X509 *peer_cert = wolfSSL_get_peer_certificate(agent->ssl);
  if (peer_cert != NULL) {
    int key_type = wolfSSL_X509_get_pubkey_type(cert);
    if (key_type != WOLFSSL_FAILURE) {
      WOLFSSL_EVP_PKEY const *peer_cert_pkey = wolfSSL_X509_get_pubkey(peer_cert);
      if (peer_cert_pkey != NULL) {
        claim->peer_cert.key_length = wolfSSL_EVP_PKEY_bits(peer_cert_pkey);
        if (claim->peer_cert.key_length == 0) {
          claim->peer_cert.key_type = map_keysum_claimkeytype((enum Key_Sum)key_type);
        }
      } else {
        _log(PUFFIN.warn, "wolfSSL_X509_get_pubkey return NULL");
      }
    }
  } else {
    _log(PUFFIN.warn, "wolfSSL_get_peer_certificate return NULL");
  }

  if (agent->ssl->arrays != NULL) {
    /*if (claim->version.data == CLAIM_TLS_VERSION_V1_2) {
      memcpy(claim->master_secret_12.secret, agent->ssl->arrays->masterSecret, 
        MIN(SECRET_LEN, CLAIM_MAX_SECRET_SIZE));
    } else {
      memcpy(claim->master_secret.secret, agent->ssl->arrays->masterSecret, 
          MIN(SECRET_LEN, CLAIM_MAX_SECRET_SIZE));
    }*/
    memcpy(claim->handshake_secret.secret, agent->ssl->arrays->secret, 
        MIN(SECRET_LEN, CLAIM_MAX_SECRET_SIZE));
    /*memcpy(claim->handshake_secret.secret, agent->ssl->arrays->exporterSecret, 
        MIN(WC_MAX_DIGEST_SIZE, CLAIM_MAX_SECRET_SIZE));*/
  } else {
    _log(PUFFIN.warn, "ssl->arrays is NULL");
  }

  claim->chosen_cipher.data = wolfSSL_get_current_cipher_suite(agent->ssl);
  if (claim->chosen_cipher.data == 0) {
    _log(PUFFIN.warn, "wolfSSL_get_current_cipher returned NULL");
  }

  /*int nid = -1;
  int int_retval = wolfSSL_get_signature_nid(agent->ssl, &nid);
  if (int_retval == WOLFSSL_SUCCESS) {
    claim->signature_algorithm = nid;
  } else {
    claim->signature_algorithm = 0;
    _log(PUFFIN.warn, "wolfSSL_get_signature_nid failed");
  }*/

  /*int_retval = wolfSSL_get_peer_signature_nid(agent->ssl, &nid);
  if (int_retval == WOLFSSL_SUCCESS) {
    claim->peer_signature_algorithm = nid;
  } else {
    claim->peer_signature_algorithm = 0;
    _log(PUFFIN.warn, "wolfSSL_get_peer_signature_nid failed");
  }*/

  claim->transcript.length = 0;
  if (agent->ssl->hsHashes != NULL) {
    if (wc_Sha256GetHash(&agent->ssl->hsHashes->hashSha256, claim->transcript.data) == 0) {
      claim->transcript.length = WC_SHA256_DIGEST_SIZE;
    } else {
      _log(PUFFIN.warn, "wc_Sha256GetHash failed");
    }
  } else {
    _log(PUFFIN.warn, "agent->ssl->hsHashes is NULL");
  }

  return;
}

static void default_claimer_notify(void *context, Claim *claim) {
  _log(PUFFIN.trace, "call to default claimer `notify`");
};

static void default_claimer_destroy(void *context) {
  _log(PUFFIN.trace, "call to default claimer `destroy`");
};

static const CLAIMER_CB DEFAULT_CLAIMER_CB = {
    .context = NULL,
    .notify = default_claimer_notify,
    .destroy = default_claimer_destroy
};

static char* get_result_information(WOLFSSL* ssl, int retval, RESULT_CODE *result_code) {
  int error_code = wolfSSL_get_error(ssl, retval);

  if (result_code != NULL) {
    switch (error_code) {
      case WOLFSSL_ERROR_NONE:
        *result_code = RESULT_OK;
        break;
      case WOLFSSL_ERROR_WANT_READ:
      case WOLFSSL_ERROR_WANT_WRITE:
        *result_code = RESULT_IO_WOULD_BLOCK;
        break;
      default:
        *result_code = RESULT_ERROR_OTHER;
        break;
      }
  }

  if (error_code == WOLFSSL_ERROR_NONE) {
    return strdup("no wolfssl error");
  }
  char* error_msg = (char*)calloc(1, 81);
  wolfSSL_ERR_error_string_n(error_code, error_msg, 80);
  return error_msg;
}

static RESULT wolfssl_take_outbound(AGENT agent, uint8_t *bytes, size_t max_length, size_t *readbytes) {
  int ret = wolfSSL_BIO_read(agent->out, bytes, max_length);
  *readbytes = ret > 0 ? ret : 0;
  /* ToDo check it bring something
  if (((ret <= 0) && wolfSSL_BIO_should_retry(agent->out)) || (ret > 0)) {
    ret = 0;
  }*/
  RESULT_CODE result_code = RESULT_ERROR_OTHER;
  char* reason = get_result_information(agent->ssl, 
      ret >= 0 ? WOLFSSL_SUCCESS : WOLFSSL_FAILURE, &result_code);
  RESULT result = PUFFIN.make_result(result_code, reason);
  free(reason);
  return result;
}

static RESULT wolfssl_add_inbound(AGENT agent, const uint8_t *bytes, size_t length, size_t *written) {
  int ret = wolfSSL_BIO_write(agent->in, bytes, length);
  *written = ret > 0 ? ret : 0;
  /* ToDo check it bring something
  if (((ret <= 0) && wolfSSL_BIO_should_retry(agent->out)) || (ret > 0)) {
    ret = 0;
  }*/
  RESULT_CODE result_code = RESULT_ERROR_OTHER;
  char* reason = get_result_information(agent->ssl, 
      ret >= 0 ? WOLFSSL_SUCCESS : WOLFSSL_FAILURE, &result_code);
  RESULT result = PUFFIN.make_result(result_code, reason);
  free(reason);
  return result;
}

static void wolfssl_message_callback(int write_p, int version, int content_type,
    const void *buf, size_t len, WOLFSSL *ssl, void *arg) {
  AGENT agent = (AGENT)arg;
  if (agent == NULL) {
    return;
  }

  struct Claim claim = {};
  claim.typ = CLAIM_UNKNOWN;
  uint8_t type = 0;
  if (content_type == 22) {
    type = *((uint8_t*)buf);
  }
  if (write_p != 1) {
    switch (type) {
      case 0x0b:
        agent->transcriptType = CLAIM_TRANSCRIPT_CH_CERT;
        break;
      case 0x0f:
        agent->transcriptType = CLAIM_CERTIFICATE_VERIFY;
        break;
      case 0x14:
        agent->transcriptType = CLAIM_TRANSCRIPT_CH_CLIENT_FIN;
        {
          struct Claim claim = {};
          claim.typ = CLAIM_FINISHED;
          fill_claim(agent, &claim);
          agent->claimer.notify(agent->claimer.context, &claim);
        }
        break;
      default:
        break;
    }
  }

  unsigned char buffer[WC_SHA256_DIGEST_SIZE] = {};
  int transcript_lenght = extract_current_transcript(agent, buffer, WC_SHA256_DIGEST_SIZE);
  if (transcript_lenght == 0) {
    return;
  }
  if (agent->ssl->options.serverState == SERVER_HELLO_COMPLETE) {
    agent->transcriptType = CLAIM_CERTIFICATE_VERIFY;
    struct Claim claim = {};
    claim.typ = CLAIM_TRANSCRIPT_CH_SH;
    fill_claim(agent, &claim);
    agent->claimer.notify(agent->claimer.context, &claim);
  }
}

static void wolfssl_register_claimer(AGENT agent, const CLAIMER_CB *claimer) {
  if (agent->claimer.destroy != NULL) {
    agent->claimer.destroy(agent->claimer.context);
  }
  if (claimer != NULL) {
    memcpy((void*)&agent->claimer, claimer, sizeof(CLAIMER_CB));
  } else {
    memset((void*)&agent->claimer, 0, sizeof(CLAIMER_CB));
  }
}

char const* map_state_statestr(enum states state) {
  switch(state) {
    case NULL_STATE:
      return "NULL_STATE";
    case SERVER_HELLOVERIFYREQUEST_COMPLETE:
      return "SERVER_HELLOVERIFYREQUEST_COMPLETE";
    case SERVER_HELLO_RETRY_REQUEST_COMPLETE:
      return "SERVER_HELLO_RETRY_REQUEST_COMPLETE";
    case SERVER_HELLO_COMPLETE:
      return "SERVER_HELLO_COMPLETE";
    case SERVER_ENCRYPTED_EXTENSIONS_COMPLETE:
      return "SERVER_ENCRYPTED_EXTENSIONS_COMPLETE";
    case SERVER_CERT_COMPLETE:
      return "SERVER_CERT_COMPLETE";
    case SERVER_CERT_VERIFY_COMPLETE:
      return "SERVER_CERT_VERIFY_COMPLETE";
    case SERVER_KEYEXCHANGE_COMPLETE:
      return "SERVER_KEYEXCHANGE_COMPLETE";
    case SERVER_HELLODONE_COMPLETE:
      return "SERVER_HELLODONE_COMPLETE";
    case SERVER_CHANGECIPHERSPEC_COMPLETE:
      return "SERVER_CHANGECIPHERSPEC_COMPLETE";
    case SERVER_FINISHED_COMPLETE:
      return "SERVER_FINISHED_COMPLETE";
    case CLIENT_HELLO_RETRY:
      return "CLIENT_HELLO_RETRY";
    case CLIENT_HELLO_COMPLETE:
      return "CLIENT_HELLO_COMPLETE";
    case CLIENT_KEYEXCHANGE_COMPLETE:
      return "CLIENT_KEYEXCHANGE_COMPLETE";
    case CLIENT_CHANGECIPHERSPEC_COMPLETE:
      return "CLIENT_CHANGECIPHERSPEC_COMPLETE";
    case CLIENT_FINISHED_COMPLETE:
      return "CLIENT_FINISHED_COMPLETE";
    case HANDSHAKE_DONE:
      return "HANDSHAKE_DONE";
    default:
      return "UNKNOWN STATE";
  }
}

static enum states wolfssl_query_state(AGENT agent) {
  if (wolfSSL_is_server(agent->ssl)) {
    return (enum states)agent->ssl->options.serverState;
  } else {
    return (enum states)agent->ssl->options.clientState;
  }
}

static const char *wolfssl_describe_state(AGENT agent) {
#if 0
  char const* state = wolfSSL_state_string_long(agent->ssl);
  return state;
#else
  enum states state = wolfssl_query_state(agent);
  char const * state_string = map_state_statestr(state);
  return state_string;
#endif
}

static RESULT wolfssl_reset(AGENT agent, uint8_t new_name) {
  agent->name = new_name;

  CLAIMER_CB current_claimer_cb = {};
  memcpy(&current_claimer_cb, (void*)&agent->claimer, sizeof(CLAIMER_CB));
  memset((void*)&agent->claimer, 0, sizeof(CLAIMER_CB));

  int ret = wolfSSL_clear(agent->ssl);
  if (ret != WOLFSSL_SUCCESS) {
    char* reason = get_result_information(agent->ssl, ret, NULL);
    RESULT result = PUFFIN.make_result(RESULT_ERROR_OTHER, reason);
    free(reason);
    return result;
  }

  if (current_claimer_cb.notify != NULL) {
    memcpy((void*)&agent->claimer, &current_claimer_cb, sizeof(CLAIMER_CB));
  }

  return PUFFIN.make_result(RESULT_OK, NULL);
}

static inline bool wolfssl_is_successful(AGENT agent) {
  return wolfSSL_get_state(agent->ssl) == HANDSHAKE_DONE;
}

static RESULT wolfssl_progress(AGENT agent) {
  RESULT_CODE result_code = RESULT_ERROR_OTHER;
  RESULT result = NULL;

  if (!wolfssl_is_successful(agent)) {
    // not connected yet -> do handshake
    int ret = wolfSSL_SSL_do_handshake(agent->ssl);
    if (ret == WOLFSSL_SUCCESS) {
      agent->handshake_done = true;
      result = PUFFIN.make_result(RESULT_OK, "handshake done"); 
    } else {
      char* reason = get_result_information(agent->ssl, ret, &result_code);
      result = PUFFIN.make_result(result_code == RESULT_IO_WOULD_BLOCK ? RESULT_OK : result_code, 
        reason);
      free(reason);
  }
  } else {
  // trigger another read
  uint8_t buf[128];
  int ret = wolfSSL_read(agent->ssl, &buf, 128);
  if (ret > 0) {
    buf[ret] = 0;
    printf("Got: %s\n", buf);
      result = PUFFIN.make_result(RESULT_OK, NULL);
    } else {
      char* reason = get_result_information(agent->ssl, ret, &result_code);
      result = PUFFIN.make_result(
          result_code == RESULT_IO_WOULD_BLOCK ? RESULT_OK : result_code, reason);
      free(reason);
    }
  }

  //deferred_transcript_extraction
  if ((agent->claimer.notify != NULL) && (agent->transcriptType != CLAIM_NOT_SET)) {
    struct Claim claim = {};
    claim.typ = agent->transcriptType;
    fill_claim(agent, &claim);
    agent->claimer.notify(agent->claimer.context, &claim);
  }

  return result;
}

static void wolfssl_destroy(AGENT agent) {
  if (agent == NULL) {
    return;
  }
  wolfssl_register_claimer(agent, NULL);
  if (agent->ssl != NULL) {
  wolfSSL_free(agent->ssl);
    agent->ssl = NULL;
  }
  free(agent);
  agent = NULL;
}

static AGENT make_agent(AGENT agent, WOLFSSL_CTX *ctx, TLS_AGENT_DESCRIPTOR const *descriptor) {
  char error_msg[128] = {};
  snprintf(error_msg, sizeof(error_msg), "no error");
  int int_retval = 0;

  agent->ssl = wolfSSL_new(ctx);
  if (agent->ssl == NULL) {
    strncpy(error_msg, "wolfSSL_new returned NULL", 128);
    goto ERROR__make_agent;
  }

  agent->name = descriptor->name;

  int_retval = wolfSSL_set_msg_callback(agent->ssl, wolfssl_message_callback);
  if (int_retval != WOLFSSL_SUCCESS) {
    strncpy(error_msg, "fatal error in wolfssl_register_claimer, unable to register callback", 128);
    goto ERROR__make_agent;
  }
  int_retval = wolfSSL_set_msg_callback_arg(agent->ssl, agent);
  if (int_retval != WOLFSSL_SUCCESS) {
    strncpy(error_msg, "fatal error in wolfssl_register_claimer, unable to register arg callback", 128);
    goto ERROR__make_agent;
  }

  agent->in = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
  if (agent->in == NULL) {
    strncpy(error_msg, "wolfSSL_BIO_new returned NULL", 128);
    goto ERROR__make_agent;
  }
  agent->out = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
  if (agent->out == NULL) {
    strncpy(error_msg, "wolfSSL_BIO_new returned NULL", 128);
    goto ERROR__make_agent;
  }

  agent->handshake_done = false;
  agent->transcriptType = CLAIM_NOT_SET;

  memset((void*)&agent->claimer, 0, sizeof(CLAIMER_CB));
  wolfssl_register_claimer(agent, &DEFAULT_CLAIMER_CB);

  wolfSSL_set_bio(agent->ssl, agent->in, agent->out);

  return agent;

ERROR__make_agent:
  _log(PUFFIN.error, "fatal error in make_agent: %s", error_msg);
  wolfssl_destroy(agent);
  return NULL;
}

#ifdef USE_CUSTOM_PRNG
static int myCryptoCb_Func(int devId, wc_CryptoInfo* info, void* ctx) {
  if ((rng_reseed_buffer == NULL) || (info->algo_type != WC_ALGO_TYPE_SEED)) {
    return CRYPTOCB_UNAVAILABLE;
  }
  if (info->seed.sz > rng_reseed_buffer_length) {
    _log(PUFFIN.warn, "wolfssl, provided seed buffer smaller than expected, filling missing part");
    uint8_t buf[255] = {};
    for(int i=0; i<rng_reseed_buffer_length; ++i) {
      ++buf[rng_reseed_buffer[i]];
    }
    memcpy(info->seed.seed, rng_reseed_buffer, rng_reseed_buffer_length);
    for(size_t i=rng_reseed_buffer_length, j=0; i<info->seed.sz; ++j) {
      if (buf[j] == 0) {
        info->seed.seed[i] = j;
        ++i;
      }
    }
    return 0;
  }
  memcpy(info->seed.seed, rng_reseed_buffer, info->seed.sz);
  return 0;
}
#endif

static AGENT wolfssl_create_agent(TLS_AGENT_DESCRIPTOR const *descriptor, WOLFSSL_METHOD* tls_method, 
    bool is_server, bool peer_authentication) {
  char error_msg[128] = {};
  snprintf(error_msg, sizeof(error_msg), "no error");
  WOLFSSL_CTX* ctx = NULL;
  int int_retval = WOLFSSL_FAILURE;
  AGENT agent = NULL;

  agent = (AGENT)calloc(1, sizeof(struct AGENT_TYPE));
  if (agent == NULL) {
    strncpy(error_msg, "calloc returned NULL", 128);
    goto ERROR__wolfssl_create_agent;
  }

  if (tls_method == NULL) {
    strncpy(error_msg, "retrieving wolfssl method failed", 128);
    goto ERROR__wolfssl_create_agent;
  }
  ctx = wolfSSL_CTX_new(tls_method);
  if (ctx == NULL) {
    strncpy(error_msg, "wolfssl create context failed", 128);
    goto ERROR__wolfssl_create_agent;
  }

  int_retval = wolfSSL_CTX_set_msg_callback(ctx, wolfssl_message_callback);
  if (int_retval != WOLFSSL_SUCCESS) {
    strncpy(error_msg, "wolfSSL_CTX_set_msg_callback failed", 128);
    goto ERROR__wolfssl_create_agent;
  }
  int_retval = wolfSSL_CTX_set_msg_callback_arg(ctx, agent);
  if (int_retval != WOLFSSL_SUCCESS) {
    strncpy(error_msg, "wolfSSL_CTX_set_msg_callback_arg failed", 128);
    goto ERROR__wolfssl_create_agent;
  }

#ifdef USE_CUSTOM_PRNG
  int_retval = wc_CryptoCb_RegisterDevice(1, myCryptoCb_Func, ctx);
  if (int_retval != 0) {
    strncpy(error_msg, "wolfssl register device failed", 128);
    goto ERROR__wolfssl_create_agent;
  }
  int_retval = wolfSSL_CTX_SetDevId(ctx, 1);
  if (int_retval != WOLFSSL_SUCCESS) {
    strncpy(error_msg, "wolfssl set device failed", 128);
    goto ERROR__wolfssl_create_agent;
  }
#endif

  int_retval = wolfSSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
  if (int_retval != WOLFSSL_SUCCESS) {
    strncpy(error_msg, "wolfssl set session cache mode failed", 128);
    goto ERROR__wolfssl_create_agent;
  }

  // Allow EXPORT in server
  // Disallow EXPORT in client
  int_retval = wolfSSL_CTX_set_cipher_list(ctx, descriptor->cipher_string);
  if (int_retval != WOLFSSL_SUCCESS) {
    snprintf(error_msg, 128, "wolfssl set cipher list %s failed", descriptor->cipher_string);
    goto ERROR__wolfssl_create_agent;
  }

  if (descriptor->group_list != NULL) {
    int_retval = wolfSSL_CTX_set1_groups_list(ctx, descriptor->group_list);
    if (int_retval != WOLFSSL_SUCCESS) {
      snprintf(error_msg, 128, "wolfssl set group list %s failed", descriptor->group_list);
      goto ERROR__wolfssl_create_agent;
    }
}

  if (peer_authentication) {
    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    for (size_t i=0; i<descriptor->store_length; ++i) {
      int_retval = wolfSSL_CTX_load_verify_buffer(ctx, 
          descriptor->store[i]->bytes, descriptor->store[i]->length, 
          SSL_FILETYPE_PEM);
      if (int_retval != WOLFSSL_SUCCESS) {
        break;
      }
    }
    if (int_retval != WOLFSSL_SUCCESS) {
      snprintf(error_msg, 128, "wolfssl setting store failed: %d", int_retval);
      goto ERROR__wolfssl_create_agent;
    }
  } else {
    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
  }

  if (is_server || descriptor->client_authentication) {
    int_retval = wolfSSL_CTX_use_certificate_buffer(ctx, 
        descriptor->cert->bytes, descriptor->cert->length, SSL_FILETYPE_PEM);
    if (int_retval != WOLFSSL_SUCCESS) {
      snprintf(error_msg, 128, "wolfssl use certificat failed: %d", int_retval);
      goto ERROR__wolfssl_create_agent;
    }
    int_retval = wolfSSL_CTX_use_PrivateKey_buffer(ctx, 
        descriptor->pkey->bytes, descriptor->pkey->length, SSL_FILETYPE_PEM);
    if (int_retval != WOLFSSL_SUCCESS) {
      snprintf(error_msg, 128, "wolfssl use private key failed: %d", int_retval);
      goto ERROR__wolfssl_create_agent;
    }
  }

  if (is_server) {
    int_retval = wolfSSL_CTX_set_num_tickets(ctx, 2);
    if (int_retval != WOLFSSL_SUCCESS) {
      snprintf(error_msg, 128, "wolfSSL_CTX_set_num_tickets");
      goto ERROR__wolfssl_create_agent;
    }
  }

  agent = make_agent(agent, ctx, descriptor);
  if (agent == NULL) {
    strncpy(error_msg, "creating wolfssl agent failed", 128);
    goto ERROR__wolfssl_create_agent;
  }

  if (!is_server) {
    int_retval = wolfSSL_UseSessionTicket(agent->ssl);
    if (int_retval != WOLFSSL_SUCCESS) {
      snprintf(error_msg, 128, "wolfSSL_UseSessionTicket failed");
      goto ERROR__wolfssl_create_agent;
    }
  }

  if (is_server) {
    wolfSSL_set_accept_state(agent->ssl);
  } else {
    wolfSSL_set_connect_state(agent->ssl);
  }

  wolfSSL_CTX_free(ctx);

  return agent;

ERROR__wolfssl_create_agent:
  _log(PUFFIN.error, "fatal error in wolfssl_create_agent: %s", error_msg);
  wolfssl_destroy(agent);
  if (ctx != NULL) {
      wolfSSL_CTX_free(ctx);
  }
  return NULL;
}

static AGENT wolfssl_create(TLS_AGENT_DESCRIPTOR const *descriptor) {
  WOLFSSL_METHOD *(*tls_methods[2])();
  char const* tls_version_str = NULL;
  switch(descriptor->tls_version) {
    case V1_3:
      tls_version_str = "V1_3";
      tls_methods[0] = wolfTLSv1_3_client_method;
      tls_methods[1] = wolfTLSv1_3_server_method;
      break;
    case V1_2:
      tls_version_str = "V1_2";
      tls_methods[0] = wolfTLSv1_2_client_method;
      tls_methods[1] = wolfTLSv1_2_server_method;
      break;
    default:
      _log(PUFFIN.error,
          "tls version is unknown, enum= %d, for %u: %u",
          descriptor->tls_version, descriptor->name, descriptor->role);
      return NULL;
      break;
  }

  switch(descriptor->role) {
    case CLIENT:
      _log(PUFFIN.info,
          "descriptor %u version: %s type: client",
          descriptor->name,
          tls_version_str);
      return wolfssl_create_agent(descriptor, tls_methods[0](), false, 
          descriptor->server_authentication);
      break;
    case SERVER:
      _log(PUFFIN.info,
          "descriptor %u version: %s type: server",
          descriptor->name, tls_version_str);
      return wolfssl_create_agent(descriptor, tls_methods[1](), true, 
          descriptor->client_authentication);
      break;
    default:
      _log(PUFFIN.error,
          "unknown agent type for descriptor %u: %u",
          descriptor->name, descriptor->role);
      return NULL;
      break;
  }
}

static void wolfssl_rng_reseed(uint8_t const *buffer, size_t length) {
#ifdef USE_CUSTOM_PRNG
  if ((buffer != NULL) && (length > 0)) {
    clock_value = CLOCKVALUE_DEFAULT;

    if (rng_reseed_buffer == NULL) {
      rng_reseed_buffer = (uint8_t*)malloc(length);
    } else if (rng_reseed_buffer_length != length) {
      rng_reseed_buffer = (uint8_t*)realloc(rng_reseed_buffer, length);
    }
    memcpy(rng_reseed_buffer, buffer, length);
  } else {
    clock_value = 0;

    if (rng_reseed_buffer != NULL) {
      free(rng_reseed_buffer);
      rng_reseed_buffer = NULL;
    }
    length = 0;
  }
  rng_reseed_buffer_length = length;
#endif
}

static TLS_PUT_INTERFACE const WOLFSSL_PUT = {
  .create = wolfssl_create,
  .rng_reseed = wolfssl_rng_reseed,
  .supports = NULL,

  .agent_interface = {
      .destroy = wolfssl_destroy,
      .progress = wolfssl_progress,
      .reset = wolfssl_reset,
      .describe_state = wolfssl_describe_state,
      .is_state_successful = wolfssl_is_successful,
      .register_claimer = wolfssl_register_claimer,

      .add_inbound = wolfssl_add_inbound,
      .take_outbound = wolfssl_take_outbound,
  },
};

#ifdef USE_CUSTOM_PRNG
time_t time_cb(time_t* t) {
  if (clock_value != 0) {
    if (t != NULL) {
      *t = clock_value;
      *t = 0;
    }
#ifdef TIME_CHANGE
    return clock_value++;
#else
    return clock_value;
    return 0;
#endif
  }
  return time(t);
}
#endif

#ifdef USE_CUSTOM_PRNG
word32 LowResTimer(void) {
  if (clock_value != 0) {
#ifdef TIME_CHANGE
    return clock_value++;
#else
    return clock_value;
#endif
  }
  return (word32)time(NULL);
}
#endif

#ifdef USE_CUSTOM_PRNG
word32 TimeNowInMilliseconds(void) {
  if (clock_value != 0) {
#ifdef TIME_CHANGE
    return 1000 * clock_value++;
#else
    return 1000 * clock_value;
#endif
  }
  struct timeval now;
  if (gettimeofday(&now, NULL) < 0)
    return (word32)GETTIME_ERROR;
  return (word32)(now.tv_sec * 1000 + now.tv_usec / 1000);
}
#endif

TLS_PUT_INTERFACE const * REGISTER () {
  /* ToDo needed ? where it should be set ?
  if (debug) {
    wolfSSL_Debugging_ON();
  }*/

#ifdef USE_CUSTOM_PRNG
  wc_SetTimeCb(time_cb);
#endif

  _log(PUFFIN.info, "wolfssl version %s", LIBWOLFSSL_VERSION_STRING);
  int int_retval = wolfSSL_Init();
  if (int_retval != WOLFSSL_SUCCESS) {
    _log(PUFFIN.error, "wolfssl init failed");
    return NULL; // ToDo check if possible to return NULL
  }

  return &WOLFSSL_PUT;
}
