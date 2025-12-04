#include <put.h>

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

AGENT open62541_create(const APPLICATION_DESCRIPTOR *descriptor) {

    // if (descriptor->role == CLIENT)
    // {
    //     return NULL;
    // }

    // if (descriptor->role == SERVER)
    // {
    //     return NULL;
    // }

    _log(PUFFIN.error,
        "unknown agent role: %u, in application descriptor: %u",
        descriptor->role,
        descriptor->id);
   return NULL;
};
