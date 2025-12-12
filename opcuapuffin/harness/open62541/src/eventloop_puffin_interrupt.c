/* Interrupt events are not supported, but this function is needed by UA_ARCHITECTURE=none */

#include "eventloop_puffin.h"

UA_InterruptManager *
UA_InterruptManager_new_POSIX(const UA_String eventSourceName) {
    return NULL;
}
