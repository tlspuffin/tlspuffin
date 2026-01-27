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

#include <s2opc/common/sopc_date_time.h>

SOPC_DateTime SOPC_Time_GetCurrentTimeUTC(void)
{
    struct timespec currentTime;
    int64_t dt = 0;

    /*
     * Extract from clock_gettime documentation:
     * All implementations support the system-wide real-time clock, which is identified by CLOCK_REALTIME.  Its time
     * represents seconds and nanoseconds since the Epoch.  When its time is changed, timers for a relative interval are
     * unaffected, but timers for an absolute point in time are affected.
     * */
    if (clock_gettime(CLOCK_REALTIME, &currentTime) != 0)
    {
        return 0;
    }

    int64_t ns100 = currentTime.tv_nsec / 100;

    if ((SOPC_Time_FromUnixTime(currentTime.tv_sec, &dt) != SOPC_STATUS_OK) || (INT64_MAX - ns100 < dt))
    {
        // Time overflow...
        return INT64_MAX;
    }

    dt += ns100;

    return dt;
}

SOPC_ReturnStatus SOPC_Time_Breakdown_Local(SOPC_Unix_Time t, struct tm* tm)
{
    return (localtime_r(&t, tm) == NULL) ? SOPC_STATUS_NOK : SOPC_STATUS_OK;
}

SOPC_ReturnStatus SOPC_Time_Breakdown_UTC(SOPC_Unix_Time t, struct tm* tm)
{
    return (gmtime_r(&t, tm) == NULL) ? SOPC_STATUS_NOK : SOPC_STATUS_OK;
}
