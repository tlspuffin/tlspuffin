#ifndef TLSPUFFIN_PUT_H
#define TLSPUFFIN_PUT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <claim-interface.h>

// TODO re-design to remove TLS-specific constructs
//
//     For now, the PUT communication interfaces are TLS-specific, e.g. X509
//     stores, protocol versions, ...
//
//     In order to support different protocols, the TLS-specific definitions
//     need to be either encapsulated in a generic interface or moved to a
//     different file that contains the protocol-specific parts.

// FIXME C/Rust duplication of type definitions
//
//     All the types related to the descriptor are equivalent of the Rust
//     structs and enums. To avoid discrepancy, we could generate a header from
//     Rust using `cbindgen` or use the C definition in Rust using `bindgen`.
//
//     Another solution would be to expose functions to retrieve config
//     informations from Rust. This has the advantage to completely hide the
//     rust structs at the price of a small performance cost each time one of
//     these functions is called.

typedef void *RESULT;

typedef enum
{
    V1_3,
    V1_2
} TLS_VERSION;

typedef enum
{
    CLIENT,
    SERVER
} AGENT_TYPE;

typedef struct
{
    const uint8_t *const bytes;
    const size_t length;
} PEM;

typedef enum
{
    RESULT_OK,
    RESULT_IO_WOULD_BLOCK,
    RESULT_ERROR_OTHER
} RESULT_CODE;

typedef struct
{
    uint8_t name;
    AGENT_TYPE type;
    TLS_VERSION tls_version;
    bool client_authentication;
    bool server_authentication;
    const PEM *cert;
    const PEM *pkey;

    const PEM *const *const store;
    const size_t store_length;
} AGENT_DESCRIPTOR;

typedef struct
{
    /*
     * Any opaque data needed by the callback.
     */
    void *context;

    /*
     * The actual callback function, called on each claim.
     */
    void (*const notify)(void *context, Claim claim);

    /*
     * Perform the necessary cleanup steps to destroy the callback.
     */
    void (*const destroy)(void *context);
} CLAIMER_CB;

typedef struct C_PUT_INTERFACE
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
    void *(*const create)(const AGENT_DESCRIPTOR *descriptor);

    /*
     * Perform cleanup tasks and release memory for an agent previously
     * allocated with ".create()".
     */
    void (*const destroy)(void *agent);

    /*
     * [optional] CAPABILITY: RNG reseed
     */
    void (*const rng_reseed)(const uint8_t *buffer, size_t length);

    RESULT (*const progress)(void *agent);
    RESULT (*const reset)(void *agent, uint8_t agent_name);
    const char *(*const describe_state)(void *agent);
    bool (*const is_state_successful)(void *agent);

    /*
     * Register a claim callback
     */
    void (*const register_claimer)(void *agent, const CLAIMER_CB *callback);

    /*
     * Attempt to write <length> bytes from <bytes> into the <agent> input
     * buffer.
     *
     * It can happen that only <written> bytes (less than <length>) are written.
     * In that case, the caller should re-attempt to call this function on the
     * remaining data at a later time.
     */
    RESULT (*const add_inbound)(void *agent, const uint8_t *bytes, size_t length, size_t *written);

    /*
     * Attempt to read a maximum of <max_length> bytes from the <agent> output
     * buffer into <bytes>.
     *
     * The number of bytes actually placed in <bytes> is given in <readbytes>.
     */
    RESULT (*const take_outbound)(void *agent, uint8_t *bytes, size_t max_length, size_t *readbytes);
} C_PUT_INTERFACE;

typedef struct C_TLSPUFFIN
{
    void (*const error)(const char *message);
    void (*const warn)(const char *message);
    void (*const info)(const char *message);
    void (*const debug)(const char *message);
    void (*const trace)(const char *message);

    RESULT (*const make_result)(RESULT_CODE code, const char *description);
} C_TLSPUFFIN;

/*
 * Add a message into the puffin logs at the log-level of the given <logger>.
 *
 * This is a variadic function that follows the same <format> as the standard
 * "printf" family.
 *
 * Example:
 *     // log a debug message:
 *     _log(TLSPUFFIN.debug, "reached function %s", __func__);
 *
 *     // log an error:
 *     _log(TLSPUFFIN.error, "an error happened at line %d", 42);
 */
void _log(void (*logger)(const char *), const char *format, ...);

extern const C_TLSPUFFIN TLSPUFFIN;

#endif // TLSPUFFIN_PUT_H
