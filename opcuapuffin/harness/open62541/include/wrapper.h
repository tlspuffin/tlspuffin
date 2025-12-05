#include <open62541/types.h>
#include <open62541/client.h>
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/client_highlevel_async.h>
#include <open62541/client_subscriptions.h>
#include <open62541/server.h>
#include <open62541/server_config_default.h>
#include <open62541/plugin/accesscontrol.h>
#include <open62541/plugin/accesscontrol_default.h>
#include <open62541/plugin/log.h>
#include <open62541/plugin/log_stdout.h>
//#include <open62541/plugin/pki.h>
//#include <open62541/plugin/pki_default.h>
#include <open62541/plugin/securitypolicy.h>
#include <open62541/plugin/create_certificate.h>
#include <open62541/plugin/securitypolicy_default.h>

// Include with binding of `vsnprintf()` and `va_list` functions to simplify
// formatting of log messages.
#include <stdarg.h>
#include <stdio.h>

// bindgen does not support non-trivial `#define` used for pointer constant. Use
// statically defined constant as workaround for now.
//
// See https://github.com/rust-lang/rust-bindgen/issues/2426
extern const void *const RS_UA_EMPTY_ARRAY_SENTINEL;

// Wrapper for `vsnprintf()` with normalized behavior across different platforms
// such as Microsoft Windows.
//
// Other than the standard `vsnprintf()`, this implementation copies the
// `va_list` argument before passing it along to allow repeated calls. The
// caller is responsible to invoke `vsnprintf_va_end()` on the `va_list`
// argument eventually.
int RS_vsnprintf_va_copy(
    char *buffer,
    size_t count,
    const char *format,
    va_list args);

// Wrapper for `va_end()` that is supposed to be used with
// `vsnprintf_va_copy()`.
void RS_vsnprintf_va_end(va_list args);
