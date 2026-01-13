/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2021 (c) Fraunhofer IOSB (Author: Julius Pfrommer)
 *    Copyright 2021 (c) Fraunhofer IOSB (Author: Jan Hermes)
 */

#include "eventloop_puffin.h"
#include "open62541/plugin/eventloop.h"
#include <stdio.h>

/*********/
/* Timer */
/*********/

static UA_DateTime
UA_EventLoopPuffin_nextTimer(UA_EventLoop *public_el) {
    UA_EventLoopPuffin *el = (UA_EventLoopPuffin*)public_el;
    if(el->delayedHead1 > (UA_DelayedCallback *)0x01 ||
       el->delayedHead2 > (UA_DelayedCallback *)0x01)
        return el->eventLoop.dateTime_nowMonotonic(&el->eventLoop);
    return UA_Timer_next(&el->timer);
}

static UA_StatusCode
UA_EventLoopPuffin_addTimer(UA_EventLoop *public_el, UA_Callback cb,
                           void *application, void *data, UA_Double interval_ms,
                           UA_DateTime *baseTime, UA_TimerPolicy timerPolicy,
                           UA_UInt64 *callbackId) {
    UA_EventLoopPuffin *el = (UA_EventLoopPuffin*)public_el;
    return UA_Timer_add(&el->timer, cb, application, data, interval_ms,
                        public_el->dateTime_nowMonotonic(public_el),
                        baseTime, timerPolicy, callbackId);
}

static UA_StatusCode
UA_EventLoopPuffin_modifyTimer(UA_EventLoop *public_el,
                              UA_UInt64 callbackId,
                              UA_Double interval_ms,
                              UA_DateTime *baseTime,
                              UA_TimerPolicy timerPolicy) {
    UA_EventLoopPuffin *el = (UA_EventLoopPuffin*)public_el;
    return UA_Timer_modify(&el->timer, callbackId, interval_ms,
                           public_el->dateTime_nowMonotonic(public_el),
                           baseTime, timerPolicy);
}

static void
UA_EventLoopPuffin_removeTimer(UA_EventLoop *public_el,
                              UA_UInt64 callbackId) {
    UA_EventLoopPuffin *el = (UA_EventLoopPuffin*)public_el;
    UA_Timer_remove(&el->timer, callbackId);
}

void
UA_EventLoopPuffin_addDelayedCallback(UA_EventLoop *public_el,
                                     UA_DelayedCallback *dc) {
    UA_EventLoopPuffin *el = (UA_EventLoopPuffin*)public_el;
    dc->next = NULL;

    /* el->delayedTail points either to prev->next or to the head.
     * We need to update two locations:
     * 1: el->delayedTail = &dc->next;
     * 2: *oldtail = dc; (equal to &dc->next)
     *
     * Once we have (1), we "own" the previous-to-last entry. No need to worry
     * about (2), we can adjust it with a delay. This makes the queue
     * "eventually consistent". */
    UA_DelayedCallback **oldtail = (UA_DelayedCallback**)
        UA_atomic_xchg((void**)&el->delayedTail, &dc->next);
    UA_atomic_xchg((void**)oldtail, &dc->next);
}

/* Resets the delayed queue and returns the previous head and tail */
static void
resetDelayedQueue(UA_EventLoopPuffin *el, UA_DelayedCallback **oldHead,
                  UA_DelayedCallback **oldTail) {

    UA_LOG_TRACE(el->eventLoop.logger, UA_LOGCATEGORY_EVENTLOOP,
        "Reset delayed Queue");
    if(el->delayedHead1 <= (UA_DelayedCallback *)0x01 &&
       el->delayedHead2 <= (UA_DelayedCallback *)0x01)
        return; /* The queue is empty */

    UA_Boolean active1 = (el->delayedHead1 != (UA_DelayedCallback*)0x01);
    UA_DelayedCallback **activeHead = (active1) ? &el->delayedHead1 : &el->delayedHead2;
    UA_DelayedCallback **inactiveHead = (active1) ? &el->delayedHead2 : &el->delayedHead1;

    /* Switch active/inactive by resetting the sentinel values. The (old) active
     * head points to an element which we return. Parallel threads continue to
     * add elements to the queue "below" the first element. */
    UA_atomic_xchg((void**)inactiveHead, NULL);
    *oldHead = (UA_DelayedCallback *)
        UA_atomic_xchg((void**)activeHead, (void*)0x01);

    /* Make the tail point to the (new) active head. Return the value of last
     * tail. When iterating over the queue elements, we need to find this tail
     * as the last element. If we find a NULL next-pointer before hitting the
     * tail spinlock until the pointer updates (eventually consistent). */
    *oldTail = (UA_DelayedCallback*)
        UA_atomic_xchg((void**)&el->delayedTail, inactiveHead);
}

static void
UA_EventLoopPuffin_removeDelayedCallback(UA_EventLoop *public_el,
                                        UA_DelayedCallback *dc) {
    UA_EventLoopPuffin *el = (UA_EventLoopPuffin*)public_el;
    UA_LOG_TRACE(el->eventLoop.logger, UA_LOGCATEGORY_EVENTLOOP,
        "Removed delayed Callback");

    /* Reset and get the old head and tail */
    UA_DelayedCallback *cur = NULL, *tail = NULL;
    resetDelayedQueue(el, &cur, &tail);

    /* Loop until we reach the tail (or head and tail are both NULL) */
    UA_DelayedCallback *next;
    for(; cur; cur = next) {
        /* Spin-loop until the next-pointer of cur is updated.
         * The element pointed to by tail must appear eventually. */
        next = cur->next;
        while(!next && cur != tail)
            next = (UA_DelayedCallback *)UA_atomic_load((void**)&cur->next);
        if(cur == dc)
            continue;
        UA_EventLoopPuffin_addDelayedCallback(public_el, cur);
    }
}

static void
processDelayed(UA_EventLoopPuffin *el) {
    UA_LOG_TRACE(el->eventLoop.logger, UA_LOGCATEGORY_EVENTLOOP,
                 "Process delayed callbacks");

    /* Reset and get the old head and tail */
    UA_DelayedCallback *dc = NULL, *tail = NULL;
    resetDelayedQueue(el, &dc, &tail);

    /* Loop until we reach the tail (or head and tail are both NULL) */
    UA_DelayedCallback *next;
    for(; dc; dc = next) {
        next = dc->next;
        while(!next && dc != tail)
            next = (UA_DelayedCallback *)UA_atomic_load((void**)&dc->next);
        if(!dc->callback)
            continue;
        dc->callback(dc->application, dc->context);
    }
}

/***********************/
/* EventLoop Lifecycle */
/***********************/

static UA_StatusCode
UA_EventLoopPuffin_start(UA_EventLoopPuffin *el) {

    if(el->eventLoop.state != UA_EVENTLOOPSTATE_FRESH &&
       el->eventLoop.state != UA_EVENTLOOPSTATE_STOPPED) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_LOG_DEBUG(el->eventLoop.logger, UA_LOGCATEGORY_EVENTLOOP,
                 "Starting the EventLoop");

    /* Setting custom clock source */
    const UA_Int32 *cs = (const UA_Int32*)
        UA_KeyValueMap_getScalar(&el->eventLoop.params,
                                 UA_QUALIFIEDNAME(0, "clock-source"),
                                 &UA_TYPES[UA_TYPES_INT32]);
    if(cs)
        el->clockSource = *cs;

    const UA_Int32 *csm = (const UA_Int32*)
        UA_KeyValueMap_getScalar(&el->eventLoop.params,
                                 UA_QUALIFIEDNAME(0, "clock-source-monotonic"),
                                 &UA_TYPES[UA_TYPES_INT32]);
    if(csm) {
        if(el->clockSourceMonotonic != *csm && el->timer.idTree.root) {
            UA_LOG_WARNING(el->eventLoop.logger, UA_LOGCATEGORY_EVENTLOOP,
                           "Eventloop\t| Setting a different monotonic clock, ",
                           "but existing timers have been registered with a "
                           "different clock source");
        }
        el->clockSourceMonotonic = *csm;
    }

    /* Start the EventSources */
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    UA_EventSource *es = el->eventLoop.eventSources;
    while(es) {
        res |= es->start(es);
        es = es->next;
    }

    /* Dirty-write the state that is const "from the outside" */
    *(UA_EventLoopState*)(uintptr_t)&el->eventLoop.state =
        UA_EVENTLOOPSTATE_STARTED;

    return res;
}

static void
checkClosed(UA_EventLoopPuffin *el) {

    UA_LOG_DEBUG(el->eventLoop.logger, UA_LOGCATEGORY_EVENTLOOP,
        "Check if EventLoop can be stopped");

    UA_EventSource *es = el->eventLoop.eventSources;
    while(es) {
        if(es->state != UA_EVENTSOURCESTATE_STOPPED) {
            UA_LOG_DEBUG(el->eventLoop.logger, UA_LOGCATEGORY_EVENTLOOP,
                "Cannot stop the EventLoop due to an unstopped event source");
            return;
        }
        es = es->next;
    }

    /* Not closed until all delayed callbacks are processed */
    if(el->delayedHead1 != NULL && el->delayedHead2 != NULL)
       return;

    /* Dirty-write the state that is const "from the outside" */
    *(UA_EventLoopState*)(uintptr_t)&el->eventLoop.state =
        UA_EVENTLOOPSTATE_STOPPED;

    UA_LOG_DEBUG(el->eventLoop.logger, UA_LOGCATEGORY_EVENTLOOP,
                 "The EventLoop has stopped");
}

static void
UA_EventLoopPuffin_stop(UA_EventLoopPuffin *el) {
    if(el->eventLoop.state != UA_EVENTLOOPSTATE_STARTED) {
        UA_LOG_WARNING(el->eventLoop.logger, UA_LOGCATEGORY_EVENTLOOP,
                       "The EventLoop is not running, cannot be stopped");
        return;
    }

    UA_LOG_DEBUG(el->eventLoop.logger, UA_LOGCATEGORY_EVENTLOOP,
                 "Stopping the EventLoop");

    /* Set to STOPPING to prevent "normal use" */
    *(UA_EventLoopState*)(uintptr_t)&el->eventLoop.state =
        UA_EVENTLOOPSTATE_STOPPING;

    /* Stop all event sources (asynchronous) */
    UA_EventSource *es = el->eventLoop.eventSources;
    for(; es; es = es->next) {
        if(es->state == UA_EVENTSOURCESTATE_STARTING ||
           es->state == UA_EVENTSOURCESTATE_STARTED) {
            es->stop(es);
        }
    }

    /* Set to STOPPED if all EventSources are STOPPED */
    checkClosed(el);
}

static UA_StatusCode
UA_EventLoopPuffin_run(UA_EventLoopPuffin *el, UA_UInt32 timeout) {
    if(el->executing) {
        UA_LOG_ERROR(el->eventLoop.logger,
                     UA_LOGCATEGORY_EVENTLOOP,
                     "Cannot run EventLoop from the run method itself");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    el->executing = true;

    if(el->eventLoop.state == UA_EVENTLOOPSTATE_FRESH ||
       el->eventLoop.state == UA_EVENTLOOPSTATE_STOPPED) {
        UA_LOG_WARNING(el->eventLoop.logger, UA_LOGCATEGORY_EVENTLOOP,
                       "Cannot run a stopped EventLoop");
        el->executing = false;
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_LOG_TRACE(el->eventLoop.logger, UA_LOGCATEGORY_EVENTLOOP,
                 "Iterate the Puffin EventLoop");

    /* Process cyclic callbacks */
    UA_DateTime dateBefore =
        el->eventLoop.dateTime_nowMonotonic(&el->eventLoop);

    UA_DateTime dateNext = UA_Timer_process(&el->timer, dateBefore);

    /* Process delayed callbacks here:
     * - Removes closed sockets already here instead of polling them again.
     * - The timeout for polling is selected to be ready in time for the next
     *   cyclic callback. So we want to do little work between the timeout
     *   running out and executing the due cyclic callbacks. */
    processDelayed(el);
    UA_LOG_TRACE(el->eventLoop.logger, UA_LOGCATEGORY_EVENTLOOP,
        "Delayed callbacks are processed");

    /* Check if the last EventSource was successfully stopped */
    if(el->eventLoop.state == UA_EVENTLOOPSTATE_STOPPING)
        checkClosed(el);

    el->executing = false;
    return UA_STATUSCODE_GOOD;
}

/*****************************/
/* Registering Event Sources */
/*****************************/

static UA_StatusCode
UA_EventLoopPuffin_registerEventSource(UA_EventLoopPuffin *el,
                                      UA_EventSource *es) {
    if(!es) {
        UA_LOG_ERROR(el->eventLoop.logger, UA_LOGCATEGORY_NETWORK,
                        "Cannot register a null EventSource!");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    /* Already registered? */
    if(es->state != UA_EVENTSOURCESTATE_FRESH) {
        UA_LOG_ERROR(el->eventLoop.logger, UA_LOGCATEGORY_NETWORK,
                     "Cannot register the EventSource \"%.*s\": "
                     "already registered",
                     (int)es->name.length, (char*)es->name.data);
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    /* Add to linked list */
    es->next = el->eventLoop.eventSources;
    el->eventLoop.eventSources = es;

    es->eventLoop = &el->eventLoop;
    es->state = UA_EVENTSOURCESTATE_STOPPED;

    /* Start if the entire EventLoop is started */
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    if(el->eventLoop.state == UA_EVENTLOOPSTATE_STARTED)
        res = es->start(es);

    return res;
}

static UA_StatusCode
UA_EventLoopPuffin_deregisterEventSource(UA_EventLoopPuffin *el,
                                        UA_EventSource *es) {
    if(es->state != UA_EVENTSOURCESTATE_STOPPED) {
        UA_LOG_WARNING(el->eventLoop.logger, UA_LOGCATEGORY_EVENTLOOP,
                       "Cannot deregister the EventSource %.*s: "
                       "Has to be stopped first",
                       (int)es->name.length, es->name.data);
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    /* Remove from the linked list */
    UA_EventSource **s = &el->eventLoop.eventSources;
    while(*s) {
        if(*s == es) {
            *s = es->next;
            break;
        }
        s = &(*s)->next;
    }

    /* Set the state to non-registered */
    es->state = UA_EVENTSOURCESTATE_FRESH;
    return UA_STATUSCODE_GOOD;
}

/***************/
/* Time Domain */
/***************/

static UA_DateTime
UA_EventLoopPuffin_DateTime_now(UA_EventLoop *el) {
    UA_EventLoopPuffin *pel = (UA_EventLoopPuffin*)el;
    struct timespec ts;
    int res = clock_gettime(pel->clockSource, &ts);
    if(UA_UNLIKELY(res != 0))
        return 0;
    return (ts.tv_sec * UA_DATETIME_SEC) + (ts.tv_nsec / 100) + UA_DATETIME_UNIX_EPOCH;
}

static UA_DateTime
UA_EventLoopPuffin_DateTime_nowMonotonic(UA_EventLoop *el) {
    UA_EventLoopPuffin *pel = (UA_EventLoopPuffin*)el;
    struct timespec ts;
    int res = clock_gettime(pel->clockSourceMonotonic, &ts);
    if(UA_UNLIKELY(res != 0))
        return 0;
    /* Also add the unix epoch for the monotonic clock. So we get a "normal"
     * output when a "normal" source is configured. */
    return (ts.tv_sec * UA_DATETIME_SEC) + (ts.tv_nsec / 100) + UA_DATETIME_UNIX_EPOCH;
}

static UA_Int64
UA_EventLoopPuffin_DateTime_localTimeUtcOffset(UA_EventLoop *el) {
    /* TODO: Fix for custom clock sources */
    return UA_DateTime_localTimeUtcOffset();
}

/*************************/
/* Initialize and Delete */
/*************************/

static UA_StatusCode
UA_EventLoopPuffin_free(UA_EventLoopPuffin *el) {
    /* Check if the EventLoop can be deleted */
    if(el->eventLoop.state != UA_EVENTLOOPSTATE_STOPPED &&
       el->eventLoop.state != UA_EVENTLOOPSTATE_FRESH) {
        UA_LOG_WARNING(el->eventLoop.logger, UA_LOGCATEGORY_EVENTLOOP,
                       "Cannot delete a running EventLoop");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    /* Deregister and delete all the EventSources */
    while(el->eventLoop.eventSources) {
        UA_EventSource *es = el->eventLoop.eventSources;
        UA_EventLoopPuffin_deregisterEventSource(el, es);
        es->free(es);
    }

    /* Remove the repeated timed callbacks */
    UA_Timer_clear(&el->timer);

    /* Process remaining delayed callbacks */
    processDelayed(el);

    UA_KeyValueMap_clear(&el->eventLoop.params);

    /* Clean up */
    UA_free(el);
    return UA_STATUSCODE_GOOD;
}

static void
UA_EventLoopPuffin_lock(UA_EventLoop *public_el) {}

static void
UA_EventLoopPuffin_unlock(UA_EventLoop *public_el) {}

UA_EventLoop *
UA_EventLoop_new_POSIX(const UA_Logger *logger) {
    UA_EventLoopPuffin *el = (UA_EventLoopPuffin*)
        UA_calloc(1, sizeof(UA_EventLoopPuffin));
    if(!el)
        return NULL;

    UA_Timer_init(&el->timer);

    /* Initialize the queue */
    el->delayedTail = &el->delayedHead1;
    el->delayedHead2 = (UA_DelayedCallback*)0x01; /* sentinel value */

    /* Set the public EventLoop content */
    el->eventLoop.logger = logger;

    /* Initialize the clock source to the default */
    el->clockSource = CLOCK_REALTIME;
# ifdef CLOCK_MONOTONIC_RAW
    el->clockSourceMonotonic = CLOCK_MONOTONIC_RAW;
# else
    el->clockSourceMonotonic = CLOCK_MONOTONIC;
# endif

    /* Set the method pointers for the interface */
    el->eventLoop.start = (UA_StatusCode (*)(UA_EventLoop*))UA_EventLoopPuffin_start;
    el->eventLoop.stop = (void (*)(UA_EventLoop*))UA_EventLoopPuffin_stop;
    el->eventLoop.free = (UA_StatusCode (*)(UA_EventLoop*))UA_EventLoopPuffin_free;
    el->eventLoop.run = (UA_StatusCode (*)(UA_EventLoop*, UA_UInt32))UA_EventLoopPuffin_run;
    el->eventLoop.cancel = (void (*)(UA_EventLoop*))UA_EventLoopPuffin_cancel;

    el->eventLoop.dateTime_now = UA_EventLoopPuffin_DateTime_now;
    el->eventLoop.dateTime_nowMonotonic =
        UA_EventLoopPuffin_DateTime_nowMonotonic;
    el->eventLoop.dateTime_localTimeUtcOffset =
        UA_EventLoopPuffin_DateTime_localTimeUtcOffset;

    el->eventLoop.nextTimer = UA_EventLoopPuffin_nextTimer;
    el->eventLoop.addTimer = UA_EventLoopPuffin_addTimer;
    el->eventLoop.modifyTimer = UA_EventLoopPuffin_modifyTimer;
    el->eventLoop.removeTimer = UA_EventLoopPuffin_removeTimer;
    el->eventLoop.addDelayedCallback = UA_EventLoopPuffin_addDelayedCallback;
    el->eventLoop.removeDelayedCallback = UA_EventLoopPuffin_removeDelayedCallback;

    el->eventLoop.registerEventSource =
        (UA_StatusCode (*)(UA_EventLoop*, UA_EventSource*))
        UA_EventLoopPuffin_registerEventSource;
    el->eventLoop.deregisterEventSource =
        (UA_StatusCode (*)(UA_EventLoop*, UA_EventSource*))
        UA_EventLoopPuffin_deregisterEventSource;

    el->eventLoop.lock = UA_EventLoopPuffin_lock;
    el->eventLoop.unlock = UA_EventLoopPuffin_unlock;

    return &el->eventLoop;
}

/***************************/
/* Network Buffer Handling */
/***************************/

UA_StatusCode
UA_EventLoopPuffin_allocNetworkBuffer(UA_ConnectionManager *cm,
                                     uintptr_t connectionId,
                                     UA_ByteString *buf,
                                     size_t bufSize) {
    UA_PuffinConnectionManager *pcm = (UA_PuffinConnectionManager*)cm;
    if(pcm->txBuffer.length == 0) {
        UA_StatusCode status = UA_ByteString_allocBuffer(buf, bufSize);
        if (status) return status;
        if(buf->length < bufSize) return UA_STATUSCODE_BADOUTOFMEMORY;
        pcm->txBuffer = *buf;
        UA_LOG_DEBUG(pcm->cm.eventSource.eventLoop->logger, UA_LOGCATEGORY_NETWORK,
            "TCP %u\t| Allocated txBuffer of size %lu at %p",
            (unsigned)connectionId, pcm->txBuffer.length, pcm->txBuffer.data);
    }
    return UA_STATUSCODE_GOOD;
}

void
UA_EventLoopPuffin_freeNetworkBuffer(UA_ConnectionManager *cm,
                                    uintptr_t connectionId,
                                    UA_ByteString *buf) {
    UA_PuffinConnectionManager *pcm = (UA_PuffinConnectionManager*)cm;
    UA_LOG_DEBUG(pcm->cm.eventSource.eventLoop->logger, UA_LOGCATEGORY_NETWORK,
        "TCP\t| Free txBuffer (clear) of size %lu, at %p",
        buf->length, buf->data);
    UA_ByteString_clear(buf);
}

UA_StatusCode
UA_EventLoopPuffin_allocateStaticBuffers(UA_PuffinConnectionManager *pcm) {
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    UA_UInt32 rxBufSize = 2u << 16; /* The default is 64kb */
    const UA_UInt32 *configRxBufSize = (const UA_UInt32 *)
        UA_KeyValueMap_getScalar(&pcm->cm.eventSource.params,
                                 UA_QUALIFIEDNAME(0, "recv-bufsize"),
                                 &UA_TYPES[UA_TYPES_UINT32]);
    if(configRxBufSize)
        rxBufSize = *configRxBufSize;
    if(pcm->rxBuffer.length != rxBufSize) {
        UA_ByteString_clear(&pcm->rxBuffer);
        res = UA_ByteString_allocBuffer(&pcm->rxBuffer, rxBufSize);
    }
    printf("Allocated static buffer of size %u at %p\n",
        pcm->rxBuffer.length, pcm->rxBuffer.data);

    const UA_UInt32 *txBufSize = (const UA_UInt32 *)
        UA_KeyValueMap_getScalar(&pcm->cm.eventSource.params,
                                 UA_QUALIFIEDNAME(0, "send-bufsize"),
                                 &UA_TYPES[UA_TYPES_UINT32]);
    if(txBufSize && pcm->txBuffer.length != *txBufSize) {
        UA_ByteString_clear(&pcm->txBuffer);
        res |= UA_ByteString_allocBuffer(&pcm->txBuffer, *txBufSize);
    }
    return res;
}

enum ZIP_CMP
cmpFD(const UA_FD *a, const UA_FD *b) {
    if(*a == *b)
        return ZIP_CMP_EQ;
    return (*a < *b) ? ZIP_CMP_LESS : ZIP_CMP_MORE;
}

void
UA_EventLoopPuffin_cancel(UA_EventLoopPuffin *el) {}

