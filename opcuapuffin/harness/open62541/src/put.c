#include <put.h>
#include <wrapper.h>

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

/* An APPLICATION is either a UA_Client or UA_Server,
   depending on role */
typedef struct Client_or_Server* APPLICATION;

/* private AGENT type */
struct AGENT_TYPE {
    uint8_t id;

    OPCUA_AGENT_ROLE role;
    APPLICATION application;

    void* connexion_manager;

    //const CLAIMER_CB *claimer;
};



AGENT open62541_create(const APPLICATION_DESCRIPTOR *descriptor) {

    if (descriptor->role == CLIENT)
    {
        _log(PUFFIN.error, "Client unimplemented!");
        return NULL;
    }

    if (descriptor->role == SERVER) {
        UA_Server *server = UA_Server_new();
        UA_ServerConfig *config = UA_Server_getConfig(server);
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

        UA_StatusCode retval = UA_ServerConfig_setDefaultWithSecurityPolicies(
            config, port,
            &certificate, &privateKey,
            trustList, trustListSize,
            issuerList, issuerListSize,
            revocationList, revocationListSize);

        /* /!\ TODO: get a puffin connexion manager through id */
        _log(PUFFIN.error, "Connexion Manager is unimplemented!");

        retval = UA_Server_run_startup(server);

        AGENT agent = (AGENT) UA_malloc(sizeof(AGENT));
        agent->id = descriptor->id;
        agent->role = descriptor->role;
        agent->application = (APPLICATION) server;
        agent->connexion_manager = NULL; //!\ TODO!
        return agent;
    }

    _log(PUFFIN.error,
        "unknown agent role: %u, in application descriptor: %u",
        descriptor->role,
        descriptor->id);
   return NULL;
};

void open62541_destroy(AGENT agent) {
    if (agent->role == CLIENT) {
        _log(PUFFIN.error,"Client unimplemented!");
    }
    if (agent->role == SERVER) {
        UA_Server *server = (UA_Server*) agent->application;
        UA_StatusCode status = 0;
        status = UA_Server_run_shutdown(server);
        status = UA_Server_delete(server);
        UA_free(agent);
    }
}

RESULT open62541_progress(AGENT agent){
    if (agent->role == CLIENT) {
        return PUFFIN.make_result(RESULT_ERROR_OTHER, "Client unimplemented!");
    }
    if (agent->role == SERVER) {
        UA_Server_run_iterate((UA_Server*) agent->application, false);
    }
    return PUFFIN.make_result(RESULT_OK, "");
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

RESULT open62541_add_inbound(AGENT agent, const uint8_t *bytes, size_t length, size_t *written){
    return PUFFIN.make_result(RESULT_ERROR_OTHER, "Unimplemented!");
};
RESULT open62541_take_outbound(AGENT agent, uint8_t *bytes, size_t max_length, size_t *readbytes){
    return PUFFIN.make_result(RESULT_ERROR_OTHER, "Unimplemented!");
};

const char* open62541_version() {
    return UA_OPEN62541_VERSION;
};
