/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2017 (c) Stefan Profanter, fortiss GmbH
 *    Copyright 2021 (c) Christian von Arnim, ISW University of Stuttgart (for VDW and umati)
 *    Copyright 2021 (c) Fraunhofer IOSB (Author: Julius Pfrommer)
 *    Copyright 2021 (c) Fraunhofer IOSB (Author: Jan Hermes)
 */

#ifndef UA_EVENTLOOP_PUFFIN_H_
#define UA_EVENTLOOP_PUFFIN_H_

#include <open62541/config.h>
#include <open62541/plugin/eventloop.h>

#include "timer.h"
#include "eventloop_common.h"
#include "open62541_queue.h"

_UA_BEGIN_DECLS

/*********************/
/* POSIX Definitions */
/*********************/

#include <time.h>

/*---------------------*/
/* Network Definitions */
/*---------------------*/

#define UA_SOCKET int
#define UA_INVALID_SOCKET -1

/***********************/
/* General Definitions */
/***********************/

#define UA_MAXHOSTNAME_LENGTH 256
#define UA_MAXPORTSTR_LENGTH 6

/* POSIX events are based on sockets / file descriptors. The EventSources can
 * register their fd in the EventLoop so that they are considered by the
 * EventLoop dropping into "poll" to wait for events. */

/* TODO: Move the macro-forest from /arch/<arch>/ua_architecture.h */

#define UA_FD UA_SOCKET
#define UA_INVALID_FD UA_INVALID_SOCKET

struct UA_RegisteredFD;
typedef struct UA_RegisteredFD UA_RegisteredFD;

/* Bitmask to be used for the UA_FDCallback event argument */
#define UA_FDEVENT_IN 1
#define UA_FDEVENT_OUT 2
#define UA_FDEVENT_ERR 4

typedef void (*UA_FDCallback)(UA_EventSource *es, UA_RegisteredFD *rfd, short event);

struct UA_RegisteredFD {
    UA_DelayedCallback dc; /* Used for async closing. Must be the first member
                            * because the rfd is freed by the delayed callback
                            * mechanism. */

    ZIP_ENTRY(UA_RegisteredFD) zipPointers; /* Register FD in the EventSource */
    UA_FD fd;
    short listenEvents; /* UA_FDEVENT_IN | UA_FDEVENT_OUT*/

    /* Information to reopen listen socket */
    UA_String hostname;
    UA_UInt16 port;
    UA_Boolean reuseaddr;

    UA_EventSource *es; /* Backpointer to the EventSource */
    UA_FDCallback eventSourceCB;
};

enum ZIP_CMP cmpFD(const UA_FD *a, const UA_FD *b);
typedef ZIP_HEAD(UA_FDTree, UA_RegisteredFD) UA_FDTree;
ZIP_FUNCTIONS(UA_FDTree, UA_RegisteredFD, zipPointers, UA_FD, fd, cmpFD)

typedef struct UA_DeregisteredListenFD {
    LIST_ENTRY(UA_DeregisteredListenFD) pointers;
    UA_RegisteredFD *listenFd;
} UA_DeregisteredListenFD;

typedef LIST_HEAD(UA_DeregisteredListenFDList, UA_DeregisteredListenFD) UA_DeregisteredListenFDList;

/* Puffin connection manager, similar to POSIX connection manager but */
/* the rx and tx buffers are directly used by the puffin agent */
typedef struct {
    UA_ConnectionManager cm;

    UA_ByteString rxBuffer; /* statically allocated */
    UA_ByteString txBuffer; /* allocated by the caller? */

    UA_UInt16 port;
    uintptr_t connectionId;

    UA_ConnectionManager_connectionCallback applicationCB;
    void *application;
    void *context;

    /* Sorted tree of the FDs */
    size_t fdsSize;
    UA_FDTree fds;

} UA_PuffinConnectionManager;

/* A static variable is set by UA_ConnectionManager_new_POSIX_TCP,
   and contains the last connection manager created. It is only read
   when a new puffin agent is created, and reading resets the variable. */
UA_PuffinConnectionManager *take_last_puffin_connection_manager(void);

typedef struct {
    UA_EventLoop eventLoop;

    /* Timer */
    UA_Timer timer;

    /* Singly-linked FIFO queue (lock-free multi-producer single-consumer) of
     * delayed callbacks. Insertion happens by chasing the tail-pointer. We
     * "check out" the current queue and reset by switching the tail to the
     * alternative head-pointer.
     *
     * This could be a simple singly-linked list. But we want to do in-order
     * processing so we can wait until the worker jobs already in the queue get
     * finished before.
     *
     * The currently unused head gets marked with the 0x01 sentinel. */
    UA_DelayedCallback *delayedHead1;
    UA_DelayedCallback *delayedHead2;
    UA_DelayedCallback **delayedTail;

    /* Flag determining whether the eventloop is currently within the
     * "run" method */
    volatile UA_Boolean executing;

    /* Indicates that the maximum number of sockets has been reached.
     * All listening sockets will be closed. */
    UA_Boolean maxSocketsLimitReached;

    /* Clocks for the eventloop's time domain */
    UA_Int32 clockSource;
    UA_Int32 clockSourceMonotonic;

    UA_RegisteredFD **fds;
    size_t fdsSize;

    /* Self-pipe to cancel blocking wait */
    UA_FD selfpipe[2]; /* 0: read, 1: write */

#if UA_MULTITHREADING >= 100
    UA_Lock elMutex;
#endif
} UA_EventLoopPuffin;

/* The following functions differ between epoll and normal select */

/* Register to start receiving events */
UA_StatusCode
UA_EventLoopPuffin_registerFD(UA_EventLoopPuffin *el, UA_RegisteredFD *rfd);

/* Modify the events that the fd listens on */
UA_StatusCode
UA_EventLoopPuffin_modifyFD(UA_EventLoopPuffin *el, UA_RegisteredFD *rfd);

/* Deregister but do not close the fd. No further events are received. */
void
UA_EventLoopPuffin_deregisterFD(UA_EventLoopPuffin *el, UA_RegisteredFD *rfd);

UA_StatusCode
UA_EventLoopPuffin_pollFDs(UA_EventLoopPuffin *el, UA_DateTime listenTimeout);

/* Helper functions across EventSources */

UA_StatusCode
UA_EventLoopPuffin_allocateStaticBuffers(UA_PuffinConnectionManager *pcm);

UA_StatusCode
UA_EventLoopPuffin_allocNetworkBuffer(UA_ConnectionManager *cm,
                                     uintptr_t connectionId,
                                     UA_ByteString *buf,
                                     size_t bufSize);

void
UA_EventLoopPuffin_freeNetworkBuffer(UA_ConnectionManager *cm,
                                    uintptr_t connectionId,
                                    UA_ByteString *buf);

/* Set the socket non-blocking. If the listen-socket is nonblocking, incoming
 * connections inherit this state. */
UA_StatusCode
UA_EventLoopPuffin_setNonBlocking(UA_FD sockfd);

/* Don't have the socket create interrupt signals */
UA_StatusCode
UA_EventLoopPuffin_setNoSigPipe(UA_FD sockfd);

/* Enables sharing of the same listening address on different sockets */
UA_StatusCode
UA_EventLoopPuffin_setReusable(UA_FD sockfd);

/* Windows has no pipes. Use a local TCP connection for the self-pipe trick.
 * https://stackoverflow.com/a/3333565 */
// #if defined(__APPLE__)
// int UA_EventLoopPuffin_pipe(SOCKET fds[2]);
// #else
// # define UA_EventLoopPuffin_pipe(fds) pipe2(fds, O_NONBLOCK)
// #endif

/* Cancel the current _run by sending to the self-pipe */
void
UA_EventLoopPuffin_cancel(UA_EventLoopPuffin *el);

void
UA_EventLoopPuffin_addDelayedCallback(UA_EventLoop *public_el,
                                     UA_DelayedCallback *dc);

_UA_END_DECLS

#endif /* UA_EVENTLOOP_PUFFIN_H_ */
