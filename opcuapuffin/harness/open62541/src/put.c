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

static const OPCUA_PUT_INTERFACE open62541_vtable = {
    .create = open62541_create,
    .rng_reseed = NULL,
    .supports = NULL,

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

/* private AGENT type */
struct AGENT_TYPE {
    uint8_t id;

    //BIO *in;
    //BIO *out;

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
        /* Do not care about timestamps ! */
        config->verifyRequestTimestamp = UA_RULEHANDLING_ACCEPT;

        UA_ByteString certificate = UA_BYTESTRING_NULL;
        if (descriptor->cert->length > 0) {
            certificate.data = (UA_Byte*) UA_malloc(descriptor->cert->length);
            if (certificate.data) {
                certificate.length = descriptor->cert->length;
                memcpy(certificate.data, descriptor->cert->bytes, certificate.length);
            } else {
                certificate.data = (UA_Byte*) UA_EMPTY_ARRAY_SENTINEL;
            }
        }
        UA_ByteString privateKey = UA_BYTESTRING_NULL;
        if (descriptor->pkey->length > 0) {
            privateKey.data = (UA_Byte*) UA_malloc(descriptor->pkey->length);
            if (privateKey.data) {
                privateKey.length = descriptor->pkey->length;
                memcpy(privateKey.data, descriptor->pkey->bytes, privateKey.length);
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

        UA_ByteString_clear(&certificate);
        UA_ByteString_clear(&privateKey);
        /**/
        _log(PUFFIN.error, "Server unimplemented!");
        return NULL;
    }

    _log(PUFFIN.error,
        "unknown agent role: %u, in application descriptor: %u",
        descriptor->role,
        descriptor->id);
   return NULL;
};

void open62541_destroy(AGENT agent) {
    ;
}

RESULT open62541_progress(AGENT agent){
    return PUFFIN.make_result(RESULT_OK, "Unimplemented!");
};

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

RESULT open62541_start_application(const APPLICATION_DESCRIPTOR *descriptor) {
    return PUFFIN.make_result(RESULT_OK, "Unimplemented!");
};