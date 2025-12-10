#ifndef PUFFIN_OPCUA_H
#define PUFFIN_OPCUA_H

#include <puffin/puffin.h>

#ifdef __cplusplus
extern "C"
{
#endif

// OPC UA version 1.03, 1.04 and 1.05
typedef enum {
    V1_3,
    V1_4,
    V1_5
} OPCUA_VERSION;

typedef enum {
    CLIENT,
    SERVER
} OPCUA_AGENT_ROLE;

// PEM encoded certs and public keys.
typedef struct {
    const size_t length;
    const uint8_t *const bytes;
} PEM;

// Describes the application to be created by the PUT.
// Owned by the caller (Puffin).
typedef struct {
    uint8_t id;

    OPCUA_AGENT_ROLE role;
    OPCUA_VERSION version;

    const PEM *cert;
    const PEM *pkey;

    const PEM *const *const store;
    const size_t store_length;
} APPLICATION_DESCRIPTOR;


typedef struct OPCUA_PUT_INTERFACE {
    /*
     * An agent is a virtual opc.tcp channel that is used by the fuzzer to communicate
     * with an OPC UA application instantiated in the PUT.
     *
     * Creates a new agent for the application described in the <descriptor>.
     * Returns a pointer to an opaque object representing the created agent or
     * NULL if an error occurred.
     *
     * Note that the caller keeps ownership of the input <descriptor>. The
     * created agent should copy any data it needs in the future and not keep
     * any reference to the <descriptor>'s memory, except its unique id.
     */
    AGENT (*const create)(const APPLICATION_DESCRIPTOR *descriptor);

    /*
     * Reseed PUT RNG
     */
    void (*const rng_reseed)(const uint8_t *buffer, size_t length);

    /*
     * Check for capability support
     */
    bool (*const supports)(const char *capability);

    /*
     * Interface for the fuzzer
     */
    AGENT_INTERFACE agent_interface;

    /*
     * PUT version
    */
    const char* (*const version)();

} OPCUA_PUT_INTERFACE;

#ifdef __cplusplus
}
#endif

#endif // PUFFIN_OPCUA_H