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
         * TODO: Remove this function? It seems
         *         1. protocol and library specific
         *         2. redundant with the idea of claims
         */
        const char *(*const describe_state)(AGENT agent);

        /*
         * Checks whether the agent is in a good state.
         *
         * TODO: Remove this function? It is unclear what a "good state"
         *       means and should be replaced with some way to query the
         *       internal state of the agent.
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

    typedef struct
    {
        void (*const error)(const char *message);
        void (*const warn)(const char *message);
        void (*const info)(const char *message);
        void (*const debug)(const char *message);
        void (*const trace)(const char *message);

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
