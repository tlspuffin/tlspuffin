/* UDP is not supported, but this function is needed by UA_ARCHITECTURE=none */

#include "eventloop_puffin.h"

UA_ConnectionManager *UA_ConnectionManager_new_POSIX_UDP(const UA_String eventSourceName)
{
    return NULL;
}
