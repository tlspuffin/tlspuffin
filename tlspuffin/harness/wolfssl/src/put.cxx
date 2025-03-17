#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/internal.h>

#include "puffin/puffin.h"
#include <puffin/tls.h>

#include <stdexcept>
#include <map>
#include <string>
#ifdef RESEED_ALLAGENTS
#include <set>
#endif

static uint8_t * rng_reseed_buffer = nullptr;
static size_t rng_reseed_buffer_length = 0;
#ifdef RESEED_ALLAGENTS
static std::set<AGENT> agents;
#endif

struct AGENT_TYPE {
  uint8_t name;

  WOLFSSL *ssl;

  WOLFSSL_BIO *in;
  WOLFSSL_BIO *out;

  bool handshake_done;

  CLAIMER_CB const claimer;
};

static void manage_claim(int32_t content_type, uint8_t *first_byte, size_t len, 
    bool outbound) {
  uint8_t type = 0;
  if (content_type == 22) {
    type = *first_byte;
  }

  if (!outbound) {
    switch (type) {
      case 0x0b: // Certificate
        break;
      case 0x0f: // CertificateVerify
        break;
      case 0x14: // Finished
        break;
      default:
        break;
    }
  }
}

static void default_claimer_notify(void *context, Claim *claim) {
  _log(PUFFIN.trace, "call to default claimer `notify`");
};

static void default_claimer_destroy(void *context) {
  _log(PUFFIN.trace, "call to default claimer `destroy`");
};

static const CLAIMER_CB DEFAULT_CLAIMER_CB = {
    .context = nullptr,
    .notify = default_claimer_notify,
    .destroy = default_claimer_destroy
};

static char* get_result_information(WOLFSSL* ssl, int retval, RESULT_CODE *result_code) {
  int error_code = wolfSSL_get_error(ssl, retval);

  if (result_code != nullptr) {
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
  if (agent == nullptr) {
    return;
  }

  //manage_claim(content_type, (uint8_t*)buf, len, write_p == 1);

  //std::cout << "\t" << content_type << std::endl;

  agent->claimer.notify(agent->claimer.context, nullptr);
}

static void wolfssl_register_claimer(AGENT agent, const CLAIMER_CB *claimer) {
  return;
  if (agent->claimer.destroy != nullptr) {
    agent->claimer.destroy(agent->claimer.context);
    memset((void*)&agent->claimer, 0, sizeof(CLAIMER_CB));
  }

  int ret = wolfSSL_set_msg_callback(
      agent->ssl, claimer != nullptr ? wolfssl_message_callback : nullptr);
  if (ret != WOLFSSL_SUCCESS) {
    _log(PUFFIN.error, "fatal error in wolfssl_register_claimer, unable to register callback");
    return;
  }
  ret = wolfSSL_set_msg_callback_arg(agent->ssl, claimer != nullptr ? agent : nullptr);
  if (ret != WOLFSSL_SUCCESS) {
    _log(PUFFIN.error, "fatal error in wolfssl_register_claimer, unable to register arg callback");
    wolfSSL_set_msg_callback(agent->ssl, nullptr);
    return;
  }

  if (claimer != nullptr) {
    memcpy((void*)&agent->claimer, claimer, sizeof(CLAIMER_CB));
  }
}

std::map<enum states, std::string> state_map = {
  { NULL_STATE, "UNKNOWN STATE"},
  { SERVER_HELLOVERIFYREQUEST_COMPLETE, "SERVER_HELLOVERIFYREQUEST_COMPLETE" },
  { SERVER_HELLO_RETRY_REQUEST_COMPLETE, "SERVER_HELLO_RETRY_REQUEST_COMPLETE" },
  { SERVER_HELLO_COMPLETE, "SERVER_HELLO_COMPLETE" },
  { SERVER_ENCRYPTED_EXTENSIONS_COMPLETE, "SERVER_ENCRYPTED_EXTENSIONS_COMPLETE" },
  { SERVER_CERT_COMPLETE, "SERVER_CERT_COMPLETE" },
  { SERVER_CERT_VERIFY_COMPLETE, "SERVER_CERT_VERIFY_COMPLETE" },
  { SERVER_KEYEXCHANGE_COMPLETE, "SERVER_KEYEXCHANGE_COMPLETE" },
  { SERVER_HELLODONE_COMPLETE, "SERVER_HELLODONE_COMPLETE" },
  { SERVER_CHANGECIPHERSPEC_COMPLETE, "SERVER_CHANGECIPHERSPEC_COMPLETE" },
  { SERVER_FINISHED_COMPLETE, "SERVER_FINISHED_COMPLETE" },
  { CLIENT_HELLO_RETRY, "CLIENT_HELLO_RETRY" },
  { CLIENT_HELLO_COMPLETE, "CLIENT_HELLO_COMPLETE" },
  { CLIENT_KEYEXCHANGE_COMPLETE, "CLIENT_KEYEXCHANGE_COMPLETE" },
  { CLIENT_CHANGECIPHERSPEC_COMPLETE, "CLIENT_CHANGECIPHERSPEC_COMPLETE" },
  { CLIENT_FINISHED_COMPLETE, "CLIENT_FINISHED_COMPLETE" },
  { HANDSHAKE_DONE, "HANDSHAKE_DONE" }
};

static const char *wolfssl_describe_state(AGENT agent) {
#if 0
  char const* state = wolfSSL_state_string_long(agent->ssl);
  //printf("state = %s\n", state);
  return state;
#else
  /*printf("state c= %d s= %d side= %c\n", agent->ssl->options.clientState, agent->ssl->options.serverState, 
      agent->ssl->options.side == WOLFSSL_SERVER_END ? 's' : 'c');*/
  enum states state = NULL_STATE;
  if (wolfSSL_is_server(agent->ssl))
  //if (agent->ssl->options.side == WOLFSSL_SERVER_END)
    state = (enum states)agent->ssl->options.serverState;
  else
    state = (enum states)agent->ssl->options.clientState;
  auto it = state_map.find(state);
  if (it == state_map.end()) {
    it = state_map.find(NULL_STATE);
  }
  //printf("state %s\n", it->second.c_str());
  return it->second.c_str();
#endif
}

static RESULT wolfssl_reset(AGENT agent, uint8_t new_name) {
  agent->name = new_name;

  wolfssl_register_claimer(agent, &DEFAULT_CLAIMER_CB);

  int ret = wolfSSL_clear(agent->ssl);
  if (ret != WOLFSSL_SUCCESS) {
    char* reason = get_result_information(agent->ssl, ret, nullptr);
    RESULT result = PUFFIN.make_result(RESULT_ERROR_OTHER, reason);
    free(reason);
    return result;
  }

  return PUFFIN.make_result(RESULT_OK, nullptr);
}

static inline bool wolfssl_is_successful(AGENT agent) {
  wolfssl_describe_state(agent);
  return agent->handshake_done;
}

static RESULT wolfssl_progress(AGENT agent) {
  RESULT_CODE result_code = RESULT_ERROR_OTHER;

  if (!wolfssl_is_successful(agent)) {
    // not connected yet -> do handshake
    int ret = wolfSSL_SSL_do_handshake(agent->ssl);
    if (ret == WOLFSSL_SUCCESS) {
      //printf("Handshake done = %s\n", wolfssl_describe_state(agent));
      agent->handshake_done = true;
      return PUFFIN.make_result(RESULT_OK, "handshake done"); 
    } else {
      //printf("More data....\n"); 
    }
    char* reason = get_result_information(agent->ssl, ret, &result_code);
    RESULT result = PUFFIN.make_result(result_code == RESULT_IO_WOULD_BLOCK ? RESULT_OK : result_code, 
        reason);
    free(reason);

    return result;
  }

  // trigger another read
  uint8_t buf[128];
  int ret = wolfSSL_read(agent->ssl, &buf, 128);
  if (ret > 0) {
    buf[ret] = 0;
    printf("Got: %s\n", buf);
    return PUFFIN.make_result(RESULT_OK, nullptr);
  }

  char* reason = get_result_information(agent->ssl, ret, &result_code);
  RESULT result = PUFFIN.make_result(result_code == RESULT_IO_WOULD_BLOCK ? RESULT_OK : result_code, 
      reason);
  free(reason);

  return result;
}

static void wolfssl_destroy(AGENT agent) {
#ifdef RESEED_ALLAGENTS
  agents.erase(agent);
#endif
  wolfssl_register_claimer(agent, nullptr);
  wolfSSL_free(agent->ssl);
  free(agent);
}

static AGENT make_agent(WOLFSSL_CTX *ctx, TLS_AGENT_DESCRIPTOR const *descriptor) {
  char const * error_msg = "no error";
  WOLFSSL *ssl = nullptr;
  AGENT agent = nullptr;

  try {
    ssl = wolfSSL_new(ctx);
    if (ssl == nullptr) {
      throw std::runtime_error("wolfSSL_new returned nullptr");
    }

    agent = (AGENT)calloc(1, sizeof(struct AGENT_TYPE));
    if (agent == nullptr) {
      throw std::runtime_error("calloc returned nullptr");
    }
    agent->name = descriptor->name;
    agent->ssl = ssl;
    agent->in = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    if (agent->in == nullptr) {
      throw std::runtime_error("wolfSSL_BIO_new returned nullptr");
    }
    agent->out = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    if (agent->out == nullptr) {
      throw std::runtime_error("wolfSSL_BIO_new returned nullptr");
    }

    agent->handshake_done = false;

    memset((void*)&agent->claimer, 0, sizeof(CLAIMER_CB));
    wolfssl_register_claimer(agent, &DEFAULT_CLAIMER_CB);

    wolfSSL_set_bio(agent->ssl, agent->in, agent->out);
    wolfSSL_CTX_free(ctx);

    return agent;
  } catch(std::runtime_error const &e) {
    _log(PUFFIN.error, "fatal error in make_agent: %s", e.what());
  }

  if (agent != nullptr) {
    if (agent->out != nullptr) {
      wolfSSL_BIO_free_all(agent->out);
      agent->out = nullptr;
    }
    if (agent->in != nullptr) {
      wolfSSL_BIO_free_all(agent->in);
      agent->in = nullptr;
    }
    free(agent);
    agent = nullptr;
  }
  if (ssl != nullptr) {
    wolfSSL_free(ssl);
    ssl = nullptr;
  }
  return nullptr;
}

static int myCryptoCb_Func(int devId, wc_CryptoInfo* info, void* ctx) {
  if ((rng_reseed_buffer == nullptr) || (info->algo_type != WC_ALGO_TYPE_SEED)) {
    return CRYPTOCB_UNAVAILABLE;
  }
  if (info->seed.sz > rng_reseed_buffer_length) {
    _log(PUFFIN.warn, "wolfssl, provided seed buffer smaller than expected, filling missing part");
    uint8_t buf[255] {};
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

static AGENT wolfssl_create_agent(TLS_AGENT_DESCRIPTOR const *descriptor, WOLFSSL_METHOD* tls_method, 
    bool is_server, bool peer_authentication) {
  char error_msg[128];
  snprintf(error_msg, sizeof(error_msg), "no error");
  WOLFSSL_CTX* ctx = nullptr;
  int int_retval = WOLFSSL_FAILURE;
  AGENT agent = nullptr;

  try {
    if (tls_method == nullptr) {
      throw std::runtime_error("retrieving wolfssl method failed");
    }
    ctx = wolfSSL_CTX_new(tls_method);
    if (ctx == nullptr) {
      throw std::runtime_error("wolfssl create context failed");
    }

    int_retval = wc_CryptoCb_RegisterDevice(1, myCryptoCb_Func, ctx);
    if (int_retval != 0) {
      throw std::runtime_error("wolfssl register device failed");
    }
    int_retval = wolfSSL_CTX_SetDevId(ctx, 1);
    if (int_retval != WOLFSSL_SUCCESS) {
      throw std::runtime_error("wolfssl set device failed");
    }

    int_retval = wolfSSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    if (int_retval != WOLFSSL_SUCCESS) {
      throw std::runtime_error("wolfssl set session cache mode failed");
    }

    // Allow EXPORT in server
    // Disallow EXPORT in client
    int_retval = wolfSSL_CTX_set_cipher_list(ctx, descriptor->cipher_string);
    if (int_retval != WOLFSSL_SUCCESS) {
      snprintf(error_msg, 128, "wolfssl set cipher list %s failed", descriptor->cipher_string);
      throw std::runtime_error(error_msg);
    }

    if (peer_authentication) {
      wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);

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
        throw std::runtime_error(error_msg);
      }
    } else {
      wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    }

    if (is_server || descriptor->client_authentication) {
      int_retval = wolfSSL_CTX_use_certificate_buffer(ctx, 
          descriptor->cert->bytes, descriptor->cert->length, SSL_FILETYPE_PEM);
      if (int_retval != WOLFSSL_SUCCESS) {
        snprintf(error_msg, 128, "wolfssl use certificat failed: %d", int_retval);
        throw std::runtime_error(error_msg);
      }
      int_retval = wolfSSL_CTX_use_PrivateKey_buffer(ctx, 
          descriptor->pkey->bytes, descriptor->pkey->length, SSL_FILETYPE_PEM);
      if (int_retval != WOLFSSL_SUCCESS) {
        snprintf(error_msg, 128, "wolfssl use private key failed: %d", int_retval);
        throw std::runtime_error(error_msg);
      }
    }

    if (is_server) {
      wolfSSL_CTX_set_num_tickets(ctx, 2);
    }

    agent = make_agent(ctx, descriptor);
    if (agent == nullptr) {
      throw std::runtime_error("creating wolfssl agent failed");
    }

    if (!is_server) {
      wolfSSL_UseSessionTicket(agent->ssl);
    }

#ifdef RESEED_ALLAGENTS
    agents.insert(agent);
#endif

    return agent;
  } catch (std::runtime_error const &e) {
    _log(PUFFIN.error, "fatal error in wolfssl_create_agent: %s", e.what());
  }

  if (ctx != nullptr) {
      wolfSSL_CTX_free(ctx);
  }
  return nullptr;
}

static AGENT wolfssl_create(TLS_AGENT_DESCRIPTOR const *descriptor) {
  WOLFSSL_METHOD *(*tls_methods[2])();
  char const* tls_version_str = nullptr;
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
      return nullptr;
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
      return nullptr;
      break;
  }
}

static void wolfssl_rng_reseed(uint8_t const *buffer, size_t length) {
  if ((buffer != nullptr) && (length > 0)) {
    if (rng_reseed_buffer == nullptr) {
      rng_reseed_buffer = (uint8_t*)malloc(length);
    } else if (rng_reseed_buffer_length != length) {
      rng_reseed_buffer = (uint8_t*)realloc(rng_reseed_buffer, length);
    }
    memcpy(rng_reseed_buffer, buffer, length);
  } else {
    if (rng_reseed_buffer != nullptr) {
      free(rng_reseed_buffer);
      rng_reseed_buffer = nullptr;
    }
    length = 0;
  }
  rng_reseed_buffer_length = length;

#ifdef RESEED_ALLAGENTS
  for(auto &agent: agents) {
    WC_RNG *rng = wolfSSL_GetRNG(agent->ssl);
    XFREE(rng->drbg, rng->heap, DYNAMIC_TYPE_RNG);
    rng->drbg = nullptr;
    wc_InitRng_ex(rng, rng->heap, rng->devId);
  }
#endif

}

static TLS_PUT_INTERFACE const WOLFSSL_PUT = {
  .create = wolfssl_create,
  .rng_reseed = wolfssl_rng_reseed,
  .supports = nullptr,

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

#ifdef __cplusplus
extern "C" {
#endif

TLS_PUT_INTERFACE const * REGISTER () {
  /* ToDo needed ? where it should be set ?
  if (debug) {
    wolfSSL_Debugging_ON();
  }*/

  _log(PUFFIN.info, "wolfssl version %s", LIBWOLFSSL_VERSION_STRING);
  int int_retval = wolfSSL_Init();
  if (int_retval != WOLFSSL_SUCCESS) {
    _log(PUFFIN.error, "wolfssl init failed");
    return nullptr; // ToDo check if possible to return nullptr
  }

  return &WOLFSSL_PUT;
}

#ifdef __cplusplus
}
#endif
