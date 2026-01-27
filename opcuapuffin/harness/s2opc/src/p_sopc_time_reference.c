/*
 * Licensed to Systerel under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Systerel licenses this file to you under the Apache
 * License, Version 2.0 (the "License"); you may not use this
 * file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#include <errno.h>
#include <string.h>
#include <time.h>

#include <s2opc/common/sopc_assert.h>
#include <s2opc/common/sopc_date_time.h>
#include <s2opc/common/sopc_logger.h>
#include <s2opc/common/sopc_mem_alloc.h>
#include <s2opc/common/sopc_time_reference.h>

#define SOPC_SECOND_TO_NANOSECONDS 1000000000
#define SOPC_MILLISECOND_TO_NANOSECONDS 1000000
#define SOPC_SECONDS_TO_MICROSECONDS 1000000
#define SOPC_MICROSECOND_TO_NANOSECONDS 1000

struct SOPC_HighRes_TimeReference
{
    struct timespec tp;
};

SOPC_TimeReference SOPC_TimeReference_GetCurrent(void)
{
    /* Extract of clock_gettime documentation:
     *
     *   CLOCK_REALTIME
     *          System-wide  clock  that measures real (i.e., wall-clock) time.  Setting this clock requires appropriate
     * privileges.  This clock is affected by discontinuous jumps in the system time (e.g., if the system administrator
     * manually changes the clock), and by the incremental adjustments performed by adjtime(3) and NTP.
     *
     *   CLOCK_MONOTONIC
     *          Clock that cannot be set and represents monotonic time since some unspecified starting point.  This
     * clock is not affected by discontinuous jumps in the system time (e.g., if the  system administrator manually
     * changes the clock), but is affected by the incremental adjustments performed by adjtime(3) and NTP.
     *
     *   CLOCK_MONOTONIC_RAW (since Linux 2.6.28; Linux-specific)
     *          Similar to CLOCK_MONOTONIC, but provides access to a raw hardware-based time that is not subject to NTP
     * adjustments or the incremental adjustments performed by adjtime(3).
     */

    int gettimeResult;
    struct timespec currentTime;
    SOPC_TimeReference result = 0;
    uint64_t nanosecs = 0;

    gettimeResult = clock_gettime(CLOCK_MONOTONIC, &currentTime);
    if (gettimeResult != 0)
    {
        /* If the system does not support monotonic clock,
         * it is necessary to set SOPC_MONOTONIC_CLOCK to false.
         * In this latter case the real time is used which is not monotonic
         * and there is no guarantee on elapsed duration computation.
         * */
        SOPC_ASSERT(false == SOPC_MONOTONIC_CLOCK);
        gettimeResult = clock_gettime(CLOCK_REALTIME, &currentTime);
    }
    // At least realtime clock shall always be available
    SOPC_ASSERT(0 == gettimeResult);

    if (currentTime.tv_sec > 0 && UINT64_MAX / 1000 > (uint64_t) currentTime.tv_sec)
    {
        result = (uint64_t) currentTime.tv_sec * 1000; // Add seconds to results

        if (currentTime.tv_nsec > 0 && (uint64_t) currentTime.tv_nsec < SOPC_SECOND_TO_NANOSECONDS)
        {
            nanosecs = (uint64_t) currentTime.tv_nsec;
        }
        else
        {
            nanosecs = SOPC_SECOND_TO_NANOSECONDS - 1; // Use maximum nanoseconds representable (< 1 second)
        }
        // Since nanosecs < 1 second no overflow possible
        result = result + nanosecs / SOPC_MILLISECOND_TO_NANOSECONDS; // Add milliseconds to result
    }
    else
    {
        result = UINT64_MAX; // Use maximum representable value
    }

    return result;
}

SOPC_HighRes_TimeReference* SOPC_HighRes_TimeReference_Create(void)
{
    SOPC_HighRes_TimeReference* ret = SOPC_Calloc(1, sizeof(SOPC_HighRes_TimeReference));
    SOPC_HighRes_TimeReference_GetTime(ret);

    return ret;
}

void SOPC_HighRes_TimeReference_Delete(SOPC_HighRes_TimeReference** t)
{
    if (NULL == t)
    {
        return;
    }
    SOPC_Free(*t);
    *t = NULL;
}

void SOPC_HighRes_TimeReference_Copy(SOPC_HighRes_TimeReference* to, const SOPC_HighRes_TimeReference* from)
{
    if (NULL != from && NULL != to)
    {
        *to = *from;
    }
}

void SOPC_HighRes_TimeReference_GetTime(SOPC_HighRes_TimeReference* t)
{
    if (NULL != t)
    {
        int res = clock_gettime(CLOCK_MONOTONIC, &t->tp);
        SOPC_ASSERT(-1 != res);
    }
}

static void SOPC_HighRes_TimeReference_AddDuration(SOPC_HighRes_TimeReference* t, uint64_t duration_us)
{
    SOPC_ASSERT(NULL != t);

    /* TODO: check that tv_sec += duration_ms / 1000 will not make it wrap */
    t->tp.tv_sec += (time_t)(duration_us / SOPC_SECONDS_TO_MICROSECONDS);
    /* This may add a negative or positive number */
    t->tp.tv_nsec += (long) ((duration_us % SOPC_SECONDS_TO_MICROSECONDS) * SOPC_MICROSECOND_TO_NANOSECONDS);

    /* Normalize */
    if (t->tp.tv_nsec < 0)
    {
        /* This case is technically impossible but makes code robust to invalid inputs */
        t->tp.tv_sec -= 1;
        t->tp.tv_nsec += SOPC_SECOND_TO_NANOSECONDS;
    }
    else if (t->tp.tv_nsec >= SOPC_SECOND_TO_NANOSECONDS)
    {
        t->tp.tv_sec += 1;
        t->tp.tv_nsec -= SOPC_SECOND_TO_NANOSECONDS;
    }
}

void SOPC_HighRes_TimeReference_AddSynchedDuration(SOPC_HighRes_TimeReference* t,
                                                   uint64_t duration_us,
                                                   int32_t offset_us)
{
    SOPC_ASSERT(NULL != t);
    uint64_t increment_us = duration_us;

    if (offset_us >= 0)
    {
        /**
         * Window offset principle.
         * - Find out current position in window [0 .. duration_us -1]
         * - Add the missing time up to next position "offset_us" in that window
         * - In the case the current position is close BEFORE "offset_us", then add a full cycle to
         *      wait time. This case means that this function was called a little too early due to
         *      clock discrepancies:
         *       - position in window is given by system DateTime clock (which is continuously
         *           corrected by PTP/NTP)
         *       - actual wait times are provided by monotonic realtime clock
         */

        SOPC_ASSERT(duration_us > 0);
        // Current remainder of clock within window given by duration_us
        uint64_t currentRem_us = (uint64_t)(SOPC_Time_GetCurrentTimeUTC() / 10);
        currentRem_us %= duration_us;
        // consider the remainder relatively to a window starting at offset_us rather than 0
        // windowOffset_us is 0 if current time matches offset_us
        // windowOffset_us is small positive if current time is past offset_us
        // windowOffset_us is large positive (from duration_us -1) if current time is right before offset_us
        const uint64_t windowOffset_us = (duration_us + currentRem_us - (uint32_t) offset_us) % duration_us;

        // remove the part of the cycle that already elapsed
        increment_us -= windowOffset_us;

        const uint64_t minIncrement = duration_us / 5;
        // Consider that event is in the "past" if windowOffset_us is close to next event (>80% of cycle)
        if (increment_us < minIncrement)
        {
            increment_us += duration_us;
        }
    }
    SOPC_HighRes_TimeReference_AddDuration(t, increment_us);
}

bool SOPC_HighRes_TimeReference_IsExpired(const SOPC_HighRes_TimeReference* t, const SOPC_HighRes_TimeReference* now)
{
    SOPC_ASSERT(NULL != t);
    SOPC_HighRes_TimeReference t1 = {0};

    if (NULL == now)
    {
        SOPC_HighRes_TimeReference_GetTime(&t1);
    }
    else
    {
        t1 = *now;
    }

    /* t <= t1 */
    return (t->tp.tv_sec < t1.tp.tv_sec || (t->tp.tv_sec == t1.tp.tv_sec && t->tp.tv_nsec <= t1.tp.tv_nsec));
}

int64_t SOPC_HighRes_TimeReference_DeltaUs(const SOPC_HighRes_TimeReference* tRef, const SOPC_HighRes_TimeReference* t)
{
    SOPC_HighRes_TimeReference t1 = {0};

    if (NULL == t)
    {
        SOPC_HighRes_TimeReference_GetTime(&t1);
    }
    else
    {
        t1 = *t;
    }
    int64_t delta_sec = (int64_t) t1.tp.tv_sec - (int64_t) tRef->tp.tv_sec;
    int64_t delta_nsec = (int64_t) t1.tp.tv_nsec - (int64_t) tRef->tp.tv_nsec;

    return delta_sec * SOPC_SECONDS_TO_MICROSECONDS + delta_nsec / SOPC_MICROSECOND_TO_NANOSECONDS;
}

void SOPC_HighRes_TimeReference_SleepUntil(const SOPC_HighRes_TimeReference* date)
{
    SOPC_ASSERT(NULL != date);
    static bool warned = false;

    int res;
    do
    {
        res = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &date->tp, NULL);
    } while (res == EINTR);

    if (0 != res && !warned)
    {
        /* TODO: strerror is not thread safe: is it possible to find a thread safe work-around? */
        SOPC_Logger_TraceError(SOPC_LOG_MODULE_COMMON, "clock_nanosleep failed (warn once): %d (%s)", errno,
                               strerror(errno));
        SOPC_ASSERT(false);
    }
}
