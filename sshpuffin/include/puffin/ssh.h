#ifndef PUFFIN_SSH_H
#define PUFFIN_SSH_H

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
        SSH_CLIENT,
        SSH_SERVER
    } SSH_AGENT_ROLE;

    typedef struct
    {
        uint8_t name;
        SSH_AGENT_ROLE role;
    } SSH_AGENT_DESCRIPTOR;

    typedef struct SSH_PUT_INTERFACE
    {
        /*
         * Creates a new agent following the specification in the <descriptor>.
         *
         * Returns a pointer to an opaque object representing the created agent, or
         * NULL on error. The caller retains ownership of <descriptor>.
         */
        AGENT (*const create)(const SSH_AGENT_DESCRIPTOR *descriptor);

        /*
         * Reseed the PUT's deterministic RNG. Called by the fuzzer before each
         * trace execution so that runs are reproducible (required for
         * differential fuzzing). Passing a NULL buffer resets to the default
         * seed.
         */
        void (*const rng_reseed)(const uint8_t *buffer, size_t length);

        AGENT_INTERFACE agent_interface;
    } SSH_PUT_INTERFACE;

#ifdef __cplusplus
}
#endif

#endif // PUFFIN_SSH_H

