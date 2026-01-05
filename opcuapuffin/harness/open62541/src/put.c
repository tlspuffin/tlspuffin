#include <put.h>

#include <open62541/types.h>
#include <open62541/client.h>
#include <open62541/client_config_default.h>
#include <open62541/plugin/certificategroup_default.h>
//#include <open62541/client_highlevel.h>
#include <open62541/server.h>
#include <open62541/server_config_default.h>
//#include <open62541/plugin/accesscontrol.h>
//#include <open62541/plugin/accesscontrol_default.h>
#include <open62541/plugin/log.h>
#include <open62541/plugin/log_stdout.h>
//#include <open62541/plugin/pki.h>
//#include <open62541/plugin/pki_default.h>
#include <open62541/plugin/securitypolicy.h>
#include <open62541/plugin/securitypolicy_default.h>

#include "eventloop_puffin.h"

/* OPC UA PUT interface for Open62541 */
AGENT open62541_create(const APPLICATION_DESCRIPTOR *descriptor);
void open62541_destroy(AGENT agent);
RESULT open62541_progress(AGENT agent);
RESULT open62541_reset(AGENT agent, uint8_t new_name, uint8_t use_clear);
const char* open62541_describe_state(AGENT agent);
bool open62541_is_state_successful(AGENT agent);
void open62541_register_claimer(AGENT agent, const CLAIMER_CB *callback);
RESULT open62541_add_inbound(AGENT agent, const uint8_t *bytes, size_t length, size_t *written);
RESULT open62541_take_outbound(AGENT agent, uint8_t *bytes, size_t max_length, size_t *readbytes);
const char* open62541_version();

static const OPCUA_PUT_INTERFACE open62541_vtable = {
    .create = open62541_create,
    .rng_reseed = NULL,
    .supports = NULL,
    .version = open62541_version,
    .agent_interface = {
        .destroy = open62541_destroy,
        .progress = open62541_progress,
        .reset = open62541_reset,
        .describe_state = open62541_describe_state,
        .is_state_successful = open62541_is_state_successful,
        .register_claimer = open62541_register_claimer,
        .add_inbound = open62541_add_inbound,
        .take_outbound = open62541_take_outbound
    }
};

const OPCUA_PUT_INTERFACE open62541() {
    return open62541_vtable;
};

/* An APPLICATION is either an UA_Client or an UA_Server,
   depending on its role */
typedef struct Client_or_Server Application;

/* private AGENT type */
struct AGENT_TYPE {
    uint8_t id;

    OPCUA_AGENT_ROLE role;
    Application *application;

    UA_PuffinConnectionManager *connexion_manager;

    //const CLAIMER_CB *claimer;
};



AGENT open62541_create(const APPLICATION_DESCRIPTOR *descriptor) {

    if (descriptor->role == CLIENT)
    {
        /* Create the server and set its config */
        UA_Client *client = UA_Client_new(); /* Registers a null event source ?? Why ?? */
        UA_ClientConfig *config = UA_Client_getConfig(client);

        /* Exchange the logger */
        UA_LogLevel log_level = UA_LOGLEVEL_TRACE;
        UA_Logger logger = UA_Log_Stdout_withLevel( log_level );
        logger.clear = config->logging->clear;
        *config->logging = logger;

        /* Set securityMode and securityPolicyUri */
        config->securityMode = UA_MESSAGESECURITYMODE_SIGN;
        config->securityPolicyUri = UA_String_fromChars("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256");

        /* no need to UA_malloc, memcopy and then UA_ByteString_clear */
        /* the certificates and private keys are owned by the caller in open62541 */
        UA_ByteString certificate = UA_BYTESTRING_NULL;
        if (descriptor->cert->length > 0) {
            certificate.data = (UA_Byte*) descriptor->cert->bytes;
            if (certificate.data) {
                certificate.length = descriptor->cert->length;
            } else {
                certificate.data = (UA_Byte*) UA_EMPTY_ARRAY_SENTINEL;
            }
        }
        UA_ByteString privateKey = UA_BYTESTRING_NULL;
        if (descriptor->pkey->length > 0) {
            privateKey.data = (UA_Byte*) descriptor->pkey->bytes;
            if (privateKey.data) {
                privateKey.length = descriptor->pkey->length;
            } else {
                privateKey.data = (UA_Byte*) UA_EMPTY_ARRAY_SENTINEL;
            }
        }
        UA_UInt16 port = 4840 + 256 + (UA_UInt16) descriptor->id;

        UA_StatusCode retval = UA_ClientConfig_setDefaultEncryption(
            config, certificate, privateKey, NULL, 0, NULL, 0);
        if (retval) {
            _log(PUFFIN.error, "UA Client config returned %u", retval);
        }
        UA_CertificateGroup_AcceptAll(&config->certificateVerification);

        config->timeout = 100000; // ms = 100s
        const UA_String listenHost = UA_STRING_STATIC("127.0.0.1");
        retval = UA_Client_startListeningForReverseConnect(client, &listenHost, 1, port);
        if (retval != UA_STATUSCODE_GOOD) {
            _log(PUFFIN.error,"Client listen for reverse connect, error: %u", retval);
        };

        AGENT agent = (AGENT) UA_malloc(sizeof(struct AGENT_TYPE));
        agent->id = descriptor->id;
        agent->role = descriptor->role;
        agent->application = (Application*) client;
        UA_PuffinConnectionManager *pcm = take_last_puffin_connection_manager();
        if (pcm) {
            agent->connexion_manager = pcm;
        } else {
            agent->connexion_manager = NULL;
            _log(PUFFIN.error, "Puffin Connection Manager is unavailable!");
        }
        return agent;
    }

    if (descriptor->role == SERVER) {
        UA_Server *server = UA_Server_new();
        UA_ServerConfig *config = UA_Server_getConfig(server);

        /* Exchange the logger */
        UA_LogLevel log_level = UA_LOGLEVEL_TRACE;
        UA_Logger logger = UA_Log_Stdout_withLevel( log_level );
        logger.clear = config->logging->clear;
        *config->logging = logger;

        /* Do not care about timestamps! */
        config->verifyRequestTimestamp = UA_RULEHANDLING_ACCEPT;

        /* no need to UA_malloc, memcopy and then UA_ByteString_clear */
        /* the certificates and private keys are owned by the caller in open62541 */
        UA_ByteString certificate = UA_BYTESTRING_NULL;
        if (descriptor->cert->length > 0) {
            certificate.data = (UA_Byte*) descriptor->cert->bytes;
            if (certificate.data) {
                certificate.length = descriptor->cert->length;
            } else {
                certificate.data = (UA_Byte*) UA_EMPTY_ARRAY_SENTINEL;
            }
        }
        UA_ByteString privateKey = UA_BYTESTRING_NULL;
        if (descriptor->pkey->length > 0) {
            privateKey.data = (UA_Byte*) descriptor->pkey->bytes;
            if (privateKey.data) {
                privateKey.length = descriptor->pkey->length;
            } else {
                privateKey.data = (UA_Byte*) UA_EMPTY_ARRAY_SENTINEL;
            }
        }
        UA_UInt16 port = 4840 + (UA_UInt16) descriptor->id;

        size_t issuerListSize = 0;
        size_t revocationListSize = 0;
        size_t trustListSize = 0;
        UA_ByteString *issuerList = NULL;
        UA_ByteString *revocationList = NULL;
        UA_STACKARRAY(UA_ByteString, trustList, trustListSize+1);

        UA_StatusCode status = UA_ServerConfig_setDefaultWithSecurityPolicies(
            config, port,
            &certificate, &privateKey,
            trustList, trustListSize,
            issuerList, issuerListSize,
            revocationList, revocationListSize);
        if (status) {
            _log(PUFFIN.error, "UA Server config returned %s", UA_StatusCode_name(status));
        }

        status = UA_Server_run_startup(server);
        if (status) {
            _log(PUFFIN.error, "UA Server startup returned %s", UA_StatusCode_name(status));
        }

        AGENT agent = (AGENT) UA_malloc(sizeof(struct AGENT_TYPE));
        agent->id = descriptor->id;
        agent->role = descriptor->role;
        agent->application = (Application*) server;
        UA_PuffinConnectionManager *pcm = take_last_puffin_connection_manager();
        if (pcm) {
            agent->connexion_manager = pcm;
        } else {
            agent->connexion_manager = NULL;
            _log(PUFFIN.error, "Puffin Connection Manager is unavailable!");
        }
        return agent;
    }

    _log(PUFFIN.error,
        "unknown agent role: %u, in application descriptor: %u",
        descriptor->role,
        descriptor->id);
   return NULL;
};

void open62541_destroy(AGENT agent) {
    UA_StatusCode status = UA_STATUSCODE_GOOD;
    if (agent->role == CLIENT) {
        UA_Client *client = (UA_Client*) agent->application;
        UA_Client_disconnect(client);
        if (status) _log(PUFFIN.error, "UA Client disconnect returned %s", UA_StatusCode_name(status));
        UA_Client_delete(client);
    }
    if (agent->role == SERVER) {
        UA_Server *server = (UA_Server*) agent->application;
        //_log(PUFFIN.error,"Server run shutdown ...");
        status = UA_Server_run_shutdown(server);
        if (status) _log(PUFFIN.error, "UA Server shutdown returned %s", UA_StatusCode_name(status));
        //_log(PUFFIN.error,"Server delete ...");
        status = UA_Server_delete(server);
        if (status) _log(PUFFIN.error, "UA Server delete returned %s", UA_StatusCode_name(status));
    }
    UA_free(agent);
}

RESULT open62541_progress(AGENT agent){
    if (agent->role == CLIENT) {
        UA_Client_run_iterate((UA_Client*) agent->application, 1);
        return PUFFIN.make_result(RESULT_OK, "");
    }
    if (agent->role == SERVER) {
        //_log(PUFFIN.error,"Server run ...");
        // UA_Server_run_iterate((UA_Server*) agent->application, false);
        //_log(PUFFIN.error,"Server run RESULT_OK");
        return PUFFIN.make_result(RESULT_OK, "");
    }
    return PUFFIN.make_result(RESULT_ERROR_OTHER, "Client unimplemented!");
}

RESULT open62541_reset(AGENT agent, uint8_t new_name, uint8_t use_clear){
    return PUFFIN.make_result(RESULT_ERROR_OTHER, "Unimplemented!");
};

const char* open62541_describe_state(AGENT agent){
    return "I feel good";
}

bool open62541_is_state_successful(AGENT agent) {
    return true;
};

void open62541_register_claimer(AGENT agent, const CLAIMER_CB *callback) {};


#define RX_BUFFER_MAX_SIZE (2u << 16)

RESULT open62541_add_inbound(AGENT agent, const uint8_t *bytes, size_t length, size_t *written){
    //_log(PUFFIN.error,"Add inbound ...");
    UA_PuffinConnectionManager *pcm = agent->connexion_manager;
    if (!pcm) return PUFFIN.make_result(RESULT_ERROR_OTHER, "Connection Manager unavailable.");

    /* Fills the rxBuffer */
    UA_ByteString buffer = pcm->rxBuffer;
    if (length > RX_BUFFER_MAX_SIZE) {
        return PUFFIN.make_result(RESULT_ERROR_OTHER, "rxBuffer is too small!");
    }

    memcpy(buffer.data, bytes, length);
    buffer.length = length;
    *written = length;

    /* notify application */
    UA_EventLoopPuffin *el = (UA_EventLoopPuffin*)pcm->cm.eventSource.eventLoop;
    UA_LOG_DEBUG(el->eventLoop.logger, UA_LOGCATEGORY_NETWORK,
                 "Harness: Added to connexion %u, a message of size %u", pcm->connectionId, *written);
    pcm->applicationCB(&pcm->cm, (uintptr_t) (pcm->connectionId),
        pcm->application, &pcm->context,
        UA_CONNECTIONSTATE_ESTABLISHED,
        &UA_KEYVALUEMAP_NULL, buffer);

    //_log(PUFFIN.error,"Add inbound OK");
    return PUFFIN.make_result(RESULT_OK, "");
};


RESULT open62541_take_outbound(AGENT agent, uint8_t *bytes, size_t max_length, size_t *readbytes){
    //_log(PUFFIN.error,"Take outbound ...");

    /* read the TxBuffer from the PuffinConnexionManager associated to the agent */
    UA_PuffinConnectionManager *pcm = agent->connexion_manager;

    if (pcm->txBuffer.length > max_length) {
        return PUFFIN.make_result(RESULT_ERROR_OTHER, "Too many bytes to take from the outbound.");
    };
    if (pcm->txBuffer.length > 8) {
        // UATCP messages start with MessageType (3 bytes), IsFinal(1 byte), MessageSize
        UA_UInt32 *message_size = (UA_UInt32*) (pcm->txBuffer.data + 4);
        memcpy(bytes, pcm->txBuffer.data, (size_t) *message_size);
        *readbytes = (size_t) *message_size;
        UA_EventLoopPuffin_freeNetworkBuffer(&pcm->cm, (uintptr_t) pcm->connectionId, &pcm->txBuffer);
    } else {
        *readbytes = 0;
    };
    //_log(PUFFIN.error,"Take outbound OK");
    return PUFFIN.make_result(RESULT_OK, "");
};

const char* open62541_version() {
    return UA_OPEN62541_VERSION;
};
