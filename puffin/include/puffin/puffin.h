#ifndef PUFFIN_PUFFIN_H
#define PUFFIN_PUFFIN_H

#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C"
{
#endif
    typedef struct AGENT_TYPE *AGENT;

    struct Claim;
    typedef struct Claim Claim;

    typedef void *RESULT;

    /*
     * Result of an IO operation on an agent.
     */
    typedef enum
    {
        RESULT_OK,
        RESULT_IO_WOULD_BLOCK,
        RESULT_ERROR_OTHER
    } RESULT_CODE;

    typedef struct
    {
        /*
         * Any opaque data needed by the callback.
         */
        void *context;

        /*
         * The actual callback function, called on each claim.
         */
        void (*const notify)(void *context, Claim *claim);

        /*
         * Perform the necessary cleanup steps to destroy the callback.
         */
        void (*const destroy)(void *context);
    } CLAIMER_CB;

    typedef struct AGENT_INTERFACE
    {
        /*
         * Perform cleanup tasks and release memory used by the agent.
         */
        void (*const destroy)(AGENT agent);

        /*
         * Process input buffer, progress internal state and optionally produce output
         * into the output buffer.
         */
        RESULT (*const progress)(AGENT agent);

        /*
         * In-place reset of the agent.
         */
        RESULT (*const reset)(AGENT agent, uint8_t new_name);

        /*
         * Produce a textual description of the current agent's state.
         *
         * Note that this is exposed for debugging/testing purposes only. The
         * actual description string depends on the underlying vendor library
         * used by the agent.
         */
        const char *(*const describe_state)(AGENT agent);

        /*
         * Check whether the agent is in a good state.
         */
        bool (*const is_state_successful)(AGENT agent);

        /*
         * Register a claim callback
         */
        void (*const register_claimer)(AGENT agent, const CLAIMER_CB *callback);

        /*
         * Attempt to write <length> bytes from <bytes> into the <agent> input
         * buffer.
         *
         * It can happen that only <written> bytes (less than <length>) are written.
         * In that case, the caller should re-attempt to call this function on the
         * remaining data at a later time.
         */
        RESULT(*const add_inbound)
        (AGENT agent, const uint8_t *bytes, size_t length, size_t *written);

        /*
         * Attempt to read a maximum of <max_length> bytes from the <agent> output
         * buffer into <bytes>.
         *
         * The number of bytes actually placed in <bytes> is given in <readbytes>.
         */
        RESULT(*const take_outbound)
        (AGENT agent, uint8_t *bytes, size_t max_length, size_t *readbytes);
    } AGENT_INTERFACE;

    /*
     * The <PUFFIN_BINDINGS> struct provides helper functions to the C code,
     * implemented in the Rust part of puffin.
     */
    typedef struct
    {
        void (*const error)(const char *message);
        void (*const warn)(const char *message);
        void (*const info)(const char *message);
        void (*const debug)(const char *message);
        void (*const trace)(const char *message);

        /*
         * Construct a <RESULT> object for an IO operation.
         *
         * The goal of this function is to allocate the structure holding the
         * result code and the description from the Rust part of puffin. It
         * avoids the need for low-level memory management in the Rust code
         * performing IO operations on the agent.
         */
        RESULT (*const make_result)(RESULT_CODE code, const char *description);
    } PUFFIN_BINDINGS;

    /*
     * Add a message into the puffin logs at the log-level of the given <logger>.
     *
     * This is a variadic function that follows the same <format> as the standard
     * "printf" family.
     *
     * Example:
     *     // log a debug message:
     *     _log(PUFFIN.debug, "reached function %s", __func__);
     *
     *     // log an error:
     *     _log(PUFFIN.error, "an error happened at line %d", 42);
     */
    void _log(void (*logger)(const char *), const char *format, ...);

    extern const PUFFIN_BINDINGS PUFFIN;

#ifdef __cplusplus
}
#endif

#endif // PUFFIN_PUFFIN_H
