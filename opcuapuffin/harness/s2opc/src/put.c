#include <put.h>
#include <string.h>

/* OPC UA PUT interface for Open62541 */
AGENT s2opc_create(const APPLICATION_DESCRIPTOR *descriptor);
void s2opc_destroy(AGENT agent);
RESULT s2opc_progress(AGENT agent);
RESULT s2opc_reset(AGENT agent, uint8_t new_name, uint8_t use_clear);
const char* s2opc_describe_state(AGENT agent);
bool s2opc_is_state_successful(AGENT agent);
void s2opc_register_claimer(AGENT agent, const CLAIMER_CB *callback);
RESULT s2opc_add_inbound(AGENT agent, const uint8_t *bytes, size_t length, size_t *written);
RESULT s2opc_take_outbound(AGENT agent, uint8_t *bytes, size_t max_length, size_t *readbytes);
const char* s2opc_version();

static const OPCUA_PUT_INTERFACE s2opc_vtable = {
    .create = s2opc_create,
    .rng_reseed = NULL,
    .supports = NULL,
    .version = s2opc_version,
    .agent_interface = {
        .destroy = s2opc_destroy,
        .progress = s2opc_progress,
        .reset = s2opc_reset,
        .describe_state = s2opc_describe_state,
        .is_state_successful = s2opc_is_state_successful,
        .register_claimer = s2opc_register_claimer,
        .add_inbound = s2opc_add_inbound,
        .take_outbound = s2opc_take_outbound
    }
};

const OPCUA_PUT_INTERFACE s2opc() {
    return s2opc_vtable;
};

/* An APPLICATION is either an UA_Client or an UA_Server,
   depending on its role */
typedef struct Client_or_Server Application;

/* private AGENT type */
struct AGENT_TYPE {
    uint8_t id;

    OPCUA_AGENT_ROLE role;
    Application *application;

    const CLAIMER_CB *claimer;
};

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


void s2opc_register_claimer(AGENT agent, const CLAIMER_CB *callback) {
    if (agent->claimer != NULL)
    {
        agent->claimer->destroy(agent->claimer->context);
    }

    CLAIMER_CB *new_claimer = malloc(sizeof(CLAIMER_CB));
    memcpy(new_claimer, callback, sizeof(CLAIMER_CB));
    agent->claimer = new_claimer;

#ifdef HAS_CLAIMS
    register_claimer(agent->ssl, _inner_claimer, agent);
#endif
};


AGENT s2opc_create(const APPLICATION_DESCRIPTOR *descriptor) {

     _log(PUFFIN.error,
        "unknown agent role: %u, in application descriptor: %u",
        descriptor->role,
        descriptor->id);
   return NULL;
};

void s2opc_destroy(AGENT agent) {
    _log(PUFFIN.error, "s2opc_destroy is unimplemented");
}

RESULT s2opc_progress(AGENT agent){
    return PUFFIN.make_result(RESULT_ERROR_OTHER, "Unimplemented!");
}

RESULT s2opc_reset(AGENT agent, uint8_t new_name, uint8_t use_clear){
    return PUFFIN.make_result(RESULT_ERROR_OTHER, "Unimplemented!");
};

const char* s2opc_describe_state(AGENT agent){
    return "I feel good";
}

bool s2opc_is_state_successful(AGENT agent) {
    return true;
};


RESULT s2opc_add_inbound(AGENT agent, const uint8_t *bytes, size_t length, size_t *written){
    _log(PUFFIN.trace,"Add inbound ...");
    return PUFFIN.make_result(RESULT_ERROR_OTHER, "Unimplemented!");
};


RESULT s2opc_take_outbound(AGENT agent, uint8_t *bytes, size_t max_length, size_t *readbytes){
    _log(PUFFIN.trace,"Take outbound ...");
    return PUFFIN.make_result(RESULT_ERROR_OTHER, "Unimplemented!");
};

const char* s2opc_version() {
    return "???";
};
