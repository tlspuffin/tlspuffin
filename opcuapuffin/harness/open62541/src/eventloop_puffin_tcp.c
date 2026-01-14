/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2021-2022 (c) Fraunhofer IOSB (Author: Julius Pfrommer)
 *    Copyright 2021 (c) Fraunhofer IOSB (Author: Jan Hermes)
 */

#include "open62541/types.h"
#include "eventloop_puffin.h"

/* Configuration parameters */
#define TCP_MANAGERPARAMS 2

static UA_KeyValueRestriction tcpManagerParams[TCP_MANAGERPARAMS] = {
    {{0, UA_STRING_STATIC("recv-bufsize")}, &UA_TYPES[UA_TYPES_UINT32], false, true, false},
    {{0, UA_STRING_STATIC("send-bufsize")}, &UA_TYPES[UA_TYPES_UINT32], false, true, false}
};

#define TCP_PARAMETERSSIZE 5
#define TCP_PARAMINDEX_ADDR 0
#define TCP_PARAMINDEX_PORT 1
#define TCP_PARAMINDEX_LISTEN 2
#define TCP_PARAMINDEX_VALIDATE 3
#define TCP_PARAMINDEX_REUSE 4

static UA_KeyValueRestriction tcpConnectionParams[TCP_PARAMETERSSIZE] = {
    {{0, UA_STRING_STATIC("address")}, &UA_TYPES[UA_TYPES_STRING], false, true, true},
    {{0, UA_STRING_STATIC("port")}, &UA_TYPES[UA_TYPES_UINT16], true, true, false},
    {{0, UA_STRING_STATIC("listen")}, &UA_TYPES[UA_TYPES_BOOLEAN], false, true, false},
    {{0, UA_STRING_STATIC("validate")}, &UA_TYPES[UA_TYPES_BOOLEAN], false, true, false},
    {{0, UA_STRING_STATIC("reuse")}, &UA_TYPES[UA_TYPES_BOOLEAN], false, true, false}
};

typedef struct {
    UA_RegisteredFD rfd;

    UA_ConnectionManager_connectionCallback applicationCB;
    void *application;
    void *context;
} TCP_FD;


/* Test if the ConnectionManager can be stopped */
static void
TCP_checkStopped(UA_PuffinConnectionManager *pcm) {
    if(pcm->fdsSize == 0 &&
       pcm->cm.eventSource.state == UA_EVENTSOURCESTATE_STOPPING) {
        UA_LOG_DEBUG(pcm->cm.eventSource.eventLoop->logger, UA_LOGCATEGORY_NETWORK,
                     "TCP\t| All sockets closed, the EventSource is stopped");
        pcm->cm.eventSource.state = UA_EVENTSOURCESTATE_STOPPED;
    }
}

static void
TCP_delayedClose(void *application, void *context) {
    UA_PuffinConnectionManager *pcm = (UA_PuffinConnectionManager*)application;
    UA_ConnectionManager *cm = &pcm->cm;
    UA_EventLoopPuffin *el = (UA_EventLoopPuffin*)cm->eventSource.eventLoop;
    TCP_FD *conn = (TCP_FD*)context;

    UA_LOG_TRACE(el->eventLoop.logger, UA_LOGCATEGORY_EVENTLOOP,
                 "TCP %u\t| Delayed closing of the connection",
                 (unsigned)conn->rfd.fd);

    /* Deregister internally */
    ZIP_REMOVE(UA_FDTree, &pcm->fds, &conn->rfd);
    UA_assert(pcm->fdsSize > 0);
    pcm->fdsSize--;
    if (pcm->connectionId == (uintptr_t) conn->rfd.fd) {
        pcm->connectionId = (uintptr_t) NULL;
    }

    /* Signal closing to the application */
    conn->applicationCB(cm, (uintptr_t)conn->rfd.fd,
                        conn->application, &conn->context,
                        UA_CONNECTIONSTATE_CLOSING,
                        &UA_KEYVALUEMAP_NULL, UA_BYTESTRING_NULL);

    /* Close the socket */
    UA_LOG_INFO(el->eventLoop.logger, UA_LOGCATEGORY_NETWORK,
                "TCP %u\t| Socket closed", (unsigned)conn->rfd.fd);

    UA_free(conn);

    /* Check if this was the last connection for a closing ConnectionManager */
    TCP_checkStopped(pcm);
}


/* Gets called when a connection socket opens, receives data or closes */
static void
TCP_connectionSocketCallback(UA_ConnectionManager *cm, TCP_FD *conn,
                             short event) {
    UA_EventLoopPuffin *el = (UA_EventLoopPuffin*)cm->eventSource.eventLoop;

    UA_LOG_TRACE(el->eventLoop.logger, UA_LOGCATEGORY_NETWORK,
                 "TCP %u\t| Activity on the socket",
                 (unsigned)conn->rfd.fd);

    /* Error. The connection has closed. */
    if(event == UA_FDEVENT_ERR) {
        UA_LOG_INFO(el->eventLoop.logger, UA_LOGCATEGORY_NETWORK,
                    "TCP %u\t| The connection closes with error",
                     (unsigned)conn->rfd.fd);
        return;
    }

    /* Write-Event, a new connection has opened */
    if(event == UA_FDEVENT_OUT) {

        UA_LOG_DEBUG(el->eventLoop.logger, UA_LOGCATEGORY_NETWORK,
                     "TCP %u\t| Opening a new connection",
                     (unsigned)conn->rfd.fd);

        /* Now we are interested in read-events. */
        conn->rfd.listenEvents = UA_FDEVENT_IN;

        /* A new socket has opened. Signal it to the application. */
        conn->applicationCB(cm, (uintptr_t)conn->rfd.fd,
                            conn->application, &conn->context,
                            UA_CONNECTIONSTATE_ESTABLISHED,
                            &UA_KEYVALUEMAP_NULL, UA_BYTESTRING_NULL);
        return;
    }

    /* Receive */
    /* Use the already allocated receive-buffer */
    UA_PuffinConnectionManager *pcm = (UA_PuffinConnectionManager*)cm;
    UA_ByteString response = pcm->rxBuffer;
    UA_LOG_ERROR(el->eventLoop.logger, UA_LOGCATEGORY_NETWORK,
        "TCP %u\t| Connection socket callback received a message of size %lu",
        (unsigned)conn->rfd.fd, (unsigned)response.length);
}

void
TCP_PuffinConnectionCallback(UA_PuffinConnectionManager *pcm, size_t length) {
    UA_EventLoopPuffin *el = (UA_EventLoopPuffin*)pcm->cm.eventSource.eventLoop;
    UA_LOG_DEBUG(el->eventLoop.logger, UA_LOGCATEGORY_NETWORK,
        "TCP %u\t| Received message of size %u in rxBuffer (%lu bytes at %p)",
        (unsigned)pcm->connectionId, length, pcm->rxBuffer.length, pcm->rxBuffer.data);

    /* Callback to the application layer */
    UA_ByteString response = pcm->rxBuffer;
    response.length = length;
    pcm->applicationCB(&pcm->cm, pcm->connectionId,
                        pcm->application, &pcm->context,
                        UA_CONNECTIONSTATE_ESTABLISHED,
                        &UA_KEYVALUEMAP_NULL, response);
    return;
}

/* Gets called when a new connection opens or if the listenSocket is closed */
static void
TCP_listenSocketCallback(UA_ConnectionManager *cm, TCP_FD *conn, short event) {
    UA_PuffinConnectionManager *pcm = (UA_PuffinConnectionManager*)cm;
    UA_EventLoopPuffin *el = (UA_EventLoopPuffin*)cm->eventSource.eventLoop;

    UA_LOG_TRACE(el->eventLoop.logger, UA_LOGCATEGORY_NETWORK,
                 "TCP %u\t| Callback on server socket",
                 (unsigned)conn->rfd.fd);

    /* Try to accept a new connection */
    UA_FD newsockfd = 2;
    pcm->connectionId = (uintptr_t) newsockfd;

    /* Log the name of the remote host */
    char hoststr[] = "puffin";
    UA_LOG_INFO(cm->eventSource.eventLoop->logger, UA_LOGCATEGORY_NETWORK,
                "TCP %u\t| Connection opened from \"%s\" via the server socket %u",
                (unsigned)newsockfd, hoststr, (unsigned)conn->rfd.fd);

    /* Configure the new socket */
    UA_StatusCode res = UA_STATUSCODE_GOOD;

    /* Allocate the UA_RegisteredFD */
    TCP_FD *newConn = (TCP_FD*)UA_calloc(1, sizeof(TCP_FD));
    if(!newConn) {
        UA_LOG_WARNING(el->eventLoop.logger, UA_LOGCATEGORY_NETWORK,
                       "TCP %u\t| Error allocating memory for the socket",
                       (unsigned)newsockfd);
        return;
    }

    newConn->rfd.fd = newsockfd;
    newConn->rfd.listenEvents = UA_FDEVENT_IN;
    newConn->rfd.es = &cm->eventSource;
    newConn->rfd.eventSourceCB = (UA_FDCallback)TCP_connectionSocketCallback;
    newConn->applicationCB = conn->applicationCB;
    newConn->application = conn->application;
    newConn->context = conn->context;

    /* Register in the EventLoop. Signal to the user if registering failed. */

    /* Register internally in the EventSource */
    ZIP_INSERT(UA_FDTree, &pcm->fds, &newConn->rfd);
    pcm->fdsSize++;

    /* Forward the remote hostname to the application */
    UA_KeyValuePair kvp;
    kvp.key = UA_QUALIFIEDNAME(0, "remote-address");
    UA_String hostName = UA_STRING(hoststr);
    UA_Variant_setScalar(&kvp.value, &hostName, &UA_TYPES[UA_TYPES_STRING]);

    UA_KeyValueMap kvm;
    kvm.mapSize = 1;
    kvm.map = &kvp;

    /* The socket has opened. Signal it to the application. */
    newConn->applicationCB(cm, (uintptr_t)newsockfd,
                           newConn->application, &newConn->context,
                           UA_CONNECTIONSTATE_ESTABLISHED,
                           &kvm, UA_BYTESTRING_NULL);
    /* connection context is updated by the callback! */
    pcm->context = newConn->context;
}

static UA_StatusCode
TCP_registerListenSocket(UA_PuffinConnectionManager *pcm,
                         const char *hostname, UA_UInt16 port,
                         void *application, void *context,
                         UA_ConnectionManager_connectionCallback connectionCallback,
                         UA_Boolean validate) {
    UA_EventLoopPuffin *el = (UA_EventLoopPuffin*)pcm->cm.eventSource.eventLoop;


    /* Create the server socket */
    UA_FD listenSocket = 1;

    UA_LOG_INFO(el->eventLoop.logger, UA_LOGCATEGORY_NETWORK,
                    "TCP %u\t| Creating listen socket for \"%s\" on port %u",
                    (unsigned)listenSocket, hostname, port);

    /* Only validate, don't actually start listening */
    if(validate) {
        return UA_STATUSCODE_GOOD;
    }

    /* Allocate the connection */
    TCP_FD *newConn = (TCP_FD*)UA_calloc(1, sizeof(TCP_FD));
    if(!newConn) {
        UA_LOG_WARNING(el->eventLoop.logger, UA_LOGCATEGORY_NETWORK,
                       "TCP %u\t| Error allocating memory for the socket",
                       (unsigned)listenSocket);
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    newConn->rfd.fd = listenSocket;
    newConn->rfd.listenEvents = UA_FDEVENT_IN;
    newConn->rfd.es = &pcm->cm.eventSource;
    newConn->rfd.eventSourceCB = (UA_FDCallback)TCP_listenSocketCallback;
    newConn->applicationCB = connectionCallback;
    newConn->application = application;
    newConn->context = context;

    /* Register internally */
    ZIP_INSERT(UA_FDTree, &pcm->fds, &newConn->rfd);
    pcm->fdsSize++;

    /* Set up the callback parameters */
    UA_String listenAddress = UA_STRING((char*)(uintptr_t)hostname);
    UA_KeyValuePair params[2];
    params[0].key = UA_QUALIFIEDNAME(0, "listen-address");
    UA_Variant_setScalar(&params[0].value, &listenAddress, &UA_TYPES[UA_TYPES_STRING]);
    params[1].key = UA_QUALIFIEDNAME(0, "listen-port");
    UA_Variant_setScalar(&params[1].value, &port, &UA_TYPES[UA_TYPES_UINT16]);
    UA_KeyValueMap paramMap = {2, params};

    if(el->maxSocketsLimitReached) {
        /* Announce the reopening of the listen-socket in the application */
        connectionCallback(&pcm->cm, (uintptr_t)listenSocket,
                           application, &newConn->context,
                           UA_CONNECTIONSTATE_REOPENING,
                           &paramMap, UA_BYTESTRING_NULL);
        return UA_STATUSCODE_GOOD;
    }

    /* Announce the listen-socket in the application */
    connectionCallback(&pcm->cm, (uintptr_t)listenSocket,
                       application, &newConn->context,
                       UA_CONNECTIONSTATE_ESTABLISHED,
                       &paramMap, UA_BYTESTRING_NULL);

    /* -- Direct call of the TCP_listenSocketCallback -- */
    TCP_listenSocketCallback(&pcm->cm, newConn, UA_FDEVENT_IN);

    return UA_STATUSCODE_GOOD;
}

static void
TCP_shutdown(UA_ConnectionManager *cm, TCP_FD *conn) {
    /* Already closing - nothing to do */
    UA_EventLoopPuffin *el = (UA_EventLoopPuffin*)cm->eventSource.eventLoop;

    if(conn->rfd.dc.callback) {
        UA_LOG_TRACE(el->eventLoop.logger, UA_LOGCATEGORY_NETWORK,
                     "TCP %u\t| Cannot close - already closing",
                     (unsigned)conn->rfd.fd);
        return;
    }

    UA_LOG_DEBUG(el->eventLoop.logger, UA_LOGCATEGORY_NETWORK,
                 "TCP %u\t| Shutdown triggered",
                 (unsigned)conn->rfd.fd);

    /* Add to the delayed callback list. Will be cleaned up in the next
     * iteration. */
    UA_DelayedCallback *dc = &conn->rfd.dc;
    dc->callback = TCP_delayedClose;
    dc->application = cm;
    dc->context = conn;

    /* Adding a delayed callback does not take a lock */
    UA_EventLoopPuffin_addDelayedCallback((UA_EventLoop*)el, dc);
}

static UA_StatusCode
TCP_shutdownConnection(UA_ConnectionManager *cm, uintptr_t connectionId) {
    UA_PuffinConnectionManager *pcm = (UA_PuffinConnectionManager*)cm;
    UA_EventLoopPuffin *el = (UA_EventLoopPuffin *)cm->eventSource.eventLoop;

    UA_FD fd = (UA_FD)connectionId;
    TCP_FD *conn = (TCP_FD*)ZIP_FIND(UA_FDTree, &pcm->fds, &fd);
    if(!conn) {
        UA_LOG_WARNING(el->eventLoop.logger, UA_LOGCATEGORY_NETWORK,
                       "TCP\t| Cannot close TCP connection %u - not found",
                       (unsigned)connectionId);
        return UA_STATUSCODE_BADNOTFOUND;
    }

    TCP_shutdown(cm, conn);

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
Puffin_sendWithConnection(UA_ConnectionManager *cm, uintptr_t connectionId,
                       const UA_KeyValueMap *params, UA_ByteString *buf) {

    UA_PuffinConnectionManager *pcm = (UA_PuffinConnectionManager*) cm;
    UA_EventLoopPuffin *el = (UA_EventLoopPuffin*)pcm->cm.eventSource.eventLoop;

     /* Send the full buffer in txBuffer */
    if(buf->length > 0 && buf->data) {
        if (pcm->txBuffer.data != buf->data) {
            memcpy(pcm->txBuffer.data + pcm->txBuffer_index, buf->data, buf->length);
            pcm->txBuffer_index += buf->length;
            UA_EventLoopPuffin_freeNetworkBuffer(&pcm->cm, connectionId, buf);
        } else {
            pcm->txBuffer_index = buf->length;
        };
    };
    UA_LOG_TRACE(el->eventLoop.logger, UA_LOGCATEGORY_NETWORK,
        "TCP %u\t| Send messages in txBuffer (%lu bytes at %p)",
        (unsigned)connectionId, pcm->txBuffer_index, pcm->txBuffer.data);

    /* Clean up of txBuffer will be performed by open62541_take_outbound,
       by calling UA_EventLoopPuffin_freeNetworkBuffer */
    return UA_STATUSCODE_GOOD;
}

/* Create a listen-socket that waits for incoming connections */
static UA_StatusCode
TCP_openPassiveConnection(UA_PuffinConnectionManager *pcm, const UA_KeyValueMap *params,
                          void *application, void *context,
                          UA_ConnectionManager_connectionCallback connectionCallback,
                          UA_Boolean validate) {
    UA_EventLoopPuffin *el = (UA_EventLoopPuffin*)pcm->cm.eventSource.eventLoop;

    /* Get the port parameter */
    const UA_UInt16 *port = (const UA_UInt16*)
        UA_KeyValueMap_getScalar(params, tcpConnectionParams[TCP_PARAMINDEX_PORT].name,
                                 &UA_TYPES[UA_TYPES_UINT16]);
    UA_assert(port); /* existence is checked before */

    /* Get the address parameter */
    const UA_Variant *addrs =
        UA_KeyValueMap_get(params, tcpConnectionParams[TCP_PARAMINDEX_ADDR].name);
    size_t addrsSize = 0;
    if(addrs) {
        UA_assert(addrs->type == &UA_TYPES[UA_TYPES_STRING]);
        if(UA_Variant_isScalar(addrs))
            addrsSize = 1;
        else
            addrsSize = addrs->arrayLength;
    }

    /* Initialize the Puffin connexion manager,
     * that manages the single connection with the fuzzer */
    pcm->port = *port;
    pcm->connectionId = (uintptr_t) NULL;
    pcm->application = application;
    pcm->context = context;
    pcm->applicationCB = connectionCallback;

    /* Undefined or empty addresses array -> listen on localhost */
    UA_StatusCode retval = UA_STATUSCODE_BADINTERNALERROR;
    char hostname[512];
    if(addrsSize == 0) {
        strcpy(hostname, "localhost");
        retval = UA_STATUSCODE_GOOD;
    };
    /* Iterate over the configured hostnames */
    for(size_t i = 0; i < addrsSize; i++) {
        UA_String *hostStrings = (UA_String*)addrs->data;
        if(hostStrings[i].length >= sizeof(hostname))
            continue;
        memcpy(hostname, hostStrings[i].data, hostStrings->length);
        hostname[hostStrings->length] = '\0';
        retval = UA_STATUSCODE_GOOD;
        break;
    };
    if (retval != UA_STATUSCODE_GOOD) {
        return retval;
    }
    if(TCP_registerListenSocket(pcm, hostname, *port, application,
        context, connectionCallback, validate) == UA_STATUSCODE_GOOD) {
        retval = UA_STATUSCODE_GOOD;
    };

    return retval;
}

/* Open a TCP connection to a remote host */
static UA_StatusCode
TCP_openActiveConnection(UA_PuffinConnectionManager *pcm, const UA_KeyValueMap *params,
                         void *application, void *context,
                         UA_ConnectionManager_connectionCallback connectionCallback,
                         UA_Boolean validate) {
    UA_EventLoopPuffin *el = (UA_EventLoopPuffin*)pcm->cm.eventSource.eventLoop;

    /* Get the connection parameters */
    char hostname[UA_MAXHOSTNAME_LENGTH];
    char portStr[UA_MAXPORTSTR_LENGTH];

    /* Prepare the port parameter */
    const UA_UInt16 *port = (const UA_UInt16*)
        UA_KeyValueMap_getScalar(params, tcpConnectionParams[TCP_PARAMINDEX_PORT].name,
                                 &UA_TYPES[UA_TYPES_UINT16]);
    UA_assert(port); /* existence is checked before */

    /* Prepare the hostname string */
    const UA_String *addr = (const UA_String*)
        UA_KeyValueMap_getScalar(params, tcpConnectionParams[TCP_PARAMINDEX_ADDR].name,
                                 &UA_TYPES[UA_TYPES_STRING]);
    if(!addr) {
        UA_LOG_ERROR(el->eventLoop.logger, UA_LOGCATEGORY_NETWORK,
                     "TCP\t| Open TCP Connection: No hostname defined, aborting");
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    if(addr->length >= UA_MAXHOSTNAME_LENGTH) {
        UA_LOG_ERROR(el->eventLoop.logger, UA_LOGCATEGORY_EVENTLOOP,
                     "TCP\t| Open TCP Connection: Hostname too long, aborting");
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    strncpy(hostname, (const char*)addr->data, addr->length);
    hostname[addr->length] = 0;

    UA_LOG_DEBUG(el->eventLoop.logger, UA_LOGCATEGORY_NETWORK,
                 "TCP\t| Open a connection to \"%s\" on port %u", hostname, *port);

    /* Only validate, don't actually open the connection */
    if(validate) {
        return UA_STATUSCODE_GOOD;
    }

    /* Initialize the Puffin connexion manager,
     * that manages the single connection with the fuzzer */
    pcm->port = *port;
    pcm->connectionId = (uintptr_t) (*port - 53530);
    pcm->application = application;
    pcm->applicationCB = connectionCallback;

    UA_LOG_INFO(el->eventLoop.logger, UA_LOGCATEGORY_NETWORK,
                "TCP %u\t| Opening a connection to \"%s\" on port %u",
                (unsigned)pcm->connectionId, hostname, *port);

    /* Signal the new connection to the application as asynchronously opening */
    connectionCallback(&pcm->cm, (uintptr_t)pcm->connectionId,
                       application, &pcm->context,
                       UA_CONNECTIONSTATE_OPENING, &UA_KEYVALUEMAP_NULL,
                       UA_BYTESTRING_NULL);

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
TCP_openConnection(UA_ConnectionManager *cm, const UA_KeyValueMap *params,
                   void *application, void *context,
                   UA_ConnectionManager_connectionCallback connectionCallback) {
    UA_PuffinConnectionManager *pcm = (UA_PuffinConnectionManager*)cm;
    UA_EventLoopPuffin *el = (UA_EventLoopPuffin*)cm->eventSource.eventLoop;

    if(cm->eventSource.state != UA_EVENTSOURCESTATE_STARTED) {
        UA_LOG_ERROR(el->eventLoop.logger, UA_LOGCATEGORY_NETWORK,
                     "TCP\t| Cannot open a connection for a "
                     "ConnectionManager that is not started");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    /* Check the parameters */
    UA_StatusCode res =
        UA_KeyValueRestriction_validate(el->eventLoop.logger, "TCP",
                                        tcpConnectionParams,
                                        TCP_PARAMETERSSIZE, params);
    if(res != UA_STATUSCODE_GOOD) {
        return res;
    }

    /* Only validate the parameters? */
    UA_Boolean validate = false;
    const UA_Boolean *validateParam = (const UA_Boolean*)
        UA_KeyValueMap_getScalar(params,
                                 tcpConnectionParams[TCP_PARAMINDEX_VALIDATE].name,
                                 &UA_TYPES[UA_TYPES_BOOLEAN]);
    if(validateParam)
        validate = *validateParam;

    /* Listen or active connection? */
    UA_Boolean listen = false;
    const UA_Boolean *listenParam = (const UA_Boolean*)
        UA_KeyValueMap_getScalar(params,
                                 tcpConnectionParams[TCP_PARAMINDEX_LISTEN].name,
                                 &UA_TYPES[UA_TYPES_BOOLEAN]);
    if(listenParam)
        listen = *listenParam;

    if(listen) {
        res = TCP_openPassiveConnection(pcm, params, application, context,
                                        connectionCallback, validate);
    } else {
        res = TCP_openActiveConnection(pcm, params, application, context,
                                       connectionCallback, validate);
    }

    return res;
}

static UA_StatusCode
TCP_eventSourceStart(UA_ConnectionManager *cm) {
    UA_PuffinConnectionManager *pcm = (UA_PuffinConnectionManager*)cm;
    UA_EventLoopPuffin *el = (UA_EventLoopPuffin*)cm->eventSource.eventLoop;
    if(!el)
        return UA_STATUSCODE_BADINTERNALERROR;

    /* Check the state */
    if(cm->eventSource.state != UA_EVENTSOURCESTATE_STOPPED) {
        UA_LOG_ERROR(el->eventLoop.logger, UA_LOGCATEGORY_NETWORK,
                     "TCP\t| To start the ConnectionManager, it has to be "
                     "registered in an EventLoop and not started yet");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    /* Check the parameters */
    UA_StatusCode res =
        UA_KeyValueRestriction_validate(el->eventLoop.logger, "TCP",
                                        tcpManagerParams, TCP_MANAGERPARAMS,
                                        &cm->eventSource.params);
    if(res != UA_STATUSCODE_GOOD)
        goto finish;

    /* Allocate the rx buffer */
    res = UA_EventLoopPuffin_allocateStaticBuffers(pcm);
    if(res != UA_STATUSCODE_GOOD)
        goto finish;

    /* Set the EventSource to the started state */
    cm->eventSource.state = UA_EVENTSOURCESTATE_STARTED;

    UA_LOG_TRACE(el->eventLoop.logger, UA_LOGCATEGORY_NETWORK,
        "TCP\t| EventSource is started and rxBuffer allocated (at: %p, of size: %u).",
        (void*) pcm, (void*) pcm->rxBuffer.data, pcm->rxBuffer.length);

 finish:
    return res;
}

static void *
TCP_shutdownCB(void *application, UA_RegisteredFD *rfd) {
    return NULL;
}

static void
TCP_eventSourceStop(UA_ConnectionManager *cm) {
    UA_PuffinConnectionManager *pcm = (UA_PuffinConnectionManager*)cm;
    UA_EventLoopPuffin *el = (UA_EventLoopPuffin*)cm->eventSource.eventLoop;

    UA_LOG_DEBUG(cm->eventSource.eventLoop->logger, UA_LOGCATEGORY_NETWORK,
                 "TCP\t| Shutting down the ConnectionManager");

    /* Prevent new connections to open */
    cm->eventSource.state = UA_EVENTSOURCESTATE_STOPPING;

    /* Shutdown all existing connection */
    ZIP_ITER(UA_FDTree, &pcm->fds, TCP_shutdownCB, cm);

    /* All sockets closed? Otherwise iterate some more. */
    TCP_checkStopped(pcm);
}

static UA_StatusCode
TCP_eventSourceDelete(UA_ConnectionManager *cm) {
    UA_PuffinConnectionManager *pcm = (UA_PuffinConnectionManager*)cm;
    if(cm->eventSource.state >= UA_EVENTSOURCESTATE_STARTING) {
        UA_LOG_ERROR(cm->eventSource.eventLoop->logger, UA_LOGCATEGORY_EVENTLOOP,
                     "TCP\t| The EventSource must be stopped before it can be deleted");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_ByteString_clear(&pcm->rxBuffer);
    UA_ByteString_clear(&pcm->txBuffer);
    UA_KeyValueMap_clear(&cm->eventSource.params);
    UA_String_clear(&cm->eventSource.name);
    UA_free(cm);

    return UA_STATUSCODE_GOOD;
}

static const char *tcpName = "tcp";

UA_PuffinConnectionManager *LAST_PUFFIN_CONNECTION_MANAGER = NULL;

UA_ConnectionManager *
UA_ConnectionManager_new_POSIX_TCP(const UA_String eventSourceName) {
    UA_PuffinConnectionManager *pcm = (UA_PuffinConnectionManager*)
        UA_calloc(1, sizeof(UA_PuffinConnectionManager));
    if(!pcm)
        return NULL;

    pcm->cm.eventSource.eventSourceType = UA_EVENTSOURCETYPE_CONNECTIONMANAGER;
    UA_String_copy(&eventSourceName, &pcm->cm.eventSource.name);
    pcm->cm.eventSource.start = (UA_StatusCode (*)(UA_EventSource *))TCP_eventSourceStart;
    pcm->cm.eventSource.stop = (void (*)(UA_EventSource *))TCP_eventSourceStop;
    pcm->cm.eventSource.free = (UA_StatusCode (*)(UA_EventSource *))TCP_eventSourceDelete;
    pcm->cm.protocol = UA_STRING((char*)(uintptr_t)tcpName);
    pcm->cm.openConnection = TCP_openConnection;
    pcm->cm.allocNetworkBuffer = UA_EventLoopPuffin_allocNetworkBuffer;
    pcm->cm.freeNetworkBuffer = UA_EventLoopPuffin_freeNetworkBuffer;
    pcm->cm.sendWithConnection = Puffin_sendWithConnection;
    pcm->cm.closeConnection = TCP_shutdownConnection;

    /* Addition for the Puffin agent */
    LAST_PUFFIN_CONNECTION_MANAGER = pcm;

    return &pcm->cm;
}

UA_PuffinConnectionManager *take_last_puffin_connection_manager(void) {
    UA_PuffinConnectionManager *result = LAST_PUFFIN_CONNECTION_MANAGER;
    LAST_PUFFIN_CONNECTION_MANAGER = NULL;
    return result;
};