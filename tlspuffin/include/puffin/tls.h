#ifndef PUFFIN_TLS_H
#define PUFFIN_TLS_H

#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>

#include <puffin/puffin.h>

#ifdef __cplusplus
extern "C"
{
#endif
    typedef enum
    {
        V1_3,
        V1_2
    } TLS_VERSION;

    typedef enum
    {
        CLIENT,
        SERVER
    } TLS_AGENT_ROLE;

    typedef struct
    {
        const uint8_t *const bytes;
        const size_t length;
    } PEM;

    typedef struct
    {
        uint8_t name;
        TLS_AGENT_ROLE role;
        TLS_VERSION tls_version;
        bool client_authentication;
        bool server_authentication;
        const char *cipher_string;

        const PEM *cert;
        const PEM *pkey;

        const PEM *const *const store;
        const size_t store_length;
    } TLS_AGENT_DESCRIPTOR;

    typedef struct TLS_PUT_INTERFACE
    {
        /*
         * Creates a new agent following the specification in the <descriptor>.
         *
         * Returns a pointer to an opaque object representing the created agent or
         * NULL if an error occurred.
         *
         * Note that the caller keeps ownership of the input <descriptor>. The
         * created agent should copy any data it needs in the future and not keep
         * any reference to the <descriptor>'s memory.
         */
        AGENT (*const create)(const TLS_AGENT_DESCRIPTOR *descriptor);

        /*
         * Reseed PUT RNG
         */
        void (*const rng_reseed)(const uint8_t *buffer, size_t length);

        /*
         * Check for capability support
         */
        bool (*const supports)(const char *capability);

        AGENT_INTERFACE agent_interface;
    } TLS_PUT_INTERFACE;

#ifdef __cplusplus
}
#endif

#endif // PUFFIN_TLS_H
