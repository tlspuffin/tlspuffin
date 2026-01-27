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
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <p_sopc_threads.h>

#include <s2opc/common/sopc_assert.h>
#include <s2opc/common/sopc_date_time.h>
#include <s2opc/common/sopc_mem_alloc.h>
#include <s2opc/common/sopc_mutexes.h>
#include <s2opc/common/sopc_threads.h>

// 10^9
#define SOPC_SECOND_TO_NANOSECONDS 1000000000
// 10^6
#define SOPC_MILLISECOND_TO_NANOSECONDS 1000000

SOPC_ReturnStatus SOPC_Condition_Init(SOPC_Condition* cond)
{
    SOPC_ReturnStatus status = SOPC_STATUS_INVALID_PARAMETERS;
    if (NULL != cond)
    {
        int retCode = 0;
        struct SOPC_Condition_Impl* condI = SOPC_Calloc(1, sizeof(*condI));

        if (SOPC_INVALID_COND == condI)
        {
            status = SOPC_STATUS_OUT_OF_MEMORY;
        }
        else
        {
            retCode = pthread_cond_init(&condI->cond, NULL);
            // unrecoverable issue if CONDVAR cannot be created
            SOPC_ASSERT(retCode == 0);
            status = SOPC_STATUS_OK;
        }
        *cond = condI;
    }
    return status;
}

SOPC_ReturnStatus SOPC_Condition_Clear(SOPC_Condition* cond)
{
    SOPC_ReturnStatus status = SOPC_STATUS_INVALID_PARAMETERS;
    if (cond != NULL)
    {
        struct SOPC_Condition_Impl* condI = (SOPC_Condition_Impl*) (*cond);
        SOPC_ASSERT(SOPC_INVALID_COND != condI); // see SOPC_Condition_Init

        int retCode = pthread_cond_destroy(&condI->cond);
        // unrecoverable issue if CONDVAR cannot be deleted.
        // Note that if EBUSY is returned, this imply a software design issue.
        SOPC_ASSERT(retCode == 0);

        status = SOPC_STATUS_OK;
        SOPC_Free(condI);
        *cond = SOPC_INVALID_COND;
    }
    return status;
}

SOPC_ReturnStatus SOPC_Condition_SignalAll(SOPC_Condition* cond)
{
    SOPC_ReturnStatus status = SOPC_STATUS_INVALID_PARAMETERS;
    int retCode = 0;
    if (cond != NULL)
    {
        struct SOPC_Condition_Impl* condI = (SOPC_Condition_Impl*) (*cond);
        SOPC_ASSERT(SOPC_INVALID_COND != condI); // see SOPC_Condition_Init

        retCode = pthread_cond_broadcast(&condI->cond);
        status = (retCode == 0 ? SOPC_STATUS_OK : SOPC_STATUS_NOK);
    }
    return status;
}

SOPC_ReturnStatus SOPC_Mutex_Initialization(SOPC_Mutex* mut)
{
    SOPC_ASSERT(NULL != mut);

    SOPC_ReturnStatus status = SOPC_STATUS_OK;
    pthread_mutexattr_t attr;

    *mut = SOPC_INVALID_MUTEX;

    if (pthread_mutexattr_init(&attr) != 0)
    {
        return SOPC_STATUS_OUT_OF_MEMORY;
    }

    if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE) != 0)
    {
        status = SOPC_STATUS_NOK;
    }
    if (SOPC_STATUS_OK == status)
    {
        struct SOPC_Mutex_Impl* mutI = SOPC_Calloc(1, sizeof(*mutI));
        if (NULL == mutI)
        {
            status = SOPC_STATUS_OUT_OF_MEMORY;
        }
        else if (pthread_mutex_init(&mutI->mutex, &attr) != 0)
        {
            SOPC_Free(mutI);
            mutI = SOPC_INVALID_MUTEX;
            status = SOPC_STATUS_NOK;
        }
        *mut = mutI;
    }

    pthread_mutexattr_destroy(&attr);

    return status;
}

SOPC_ReturnStatus SOPC_Mutex_Clear(SOPC_Mutex* mut)
{
    SOPC_ReturnStatus status = SOPC_STATUS_INVALID_PARAMETERS;
    int retCode = 0;
    if (mut != NULL)
    {
        struct SOPC_Mutex_Impl* mutI = (SOPC_Mutex_Impl*) (*mut);
        SOPC_ASSERT(SOPC_INVALID_MUTEX != mutI); // See SOPC_Mutex_Initialization
        retCode = pthread_mutex_destroy(&mutI->mutex);
        // unrecoverable issue if MUTEX cannot be deleted.
        // Note that if EBUSY is returned, this imply a software design issue.
        SOPC_ASSERT(retCode == 0);
        SOPC_Free(mutI);
        *mut = SOPC_INVALID_MUTEX;
        status = SOPC_STATUS_OK;
    }
    return status;
}

SOPC_ReturnStatus SOPC_Mutex_Lock(SOPC_Mutex* mut)
{
    SOPC_ReturnStatus status = SOPC_STATUS_INVALID_PARAMETERS;
    int retCode = 0;
    if (mut != NULL)
    {
        struct SOPC_Mutex_Impl* mutI = (SOPC_Mutex_Impl*) (*mut);
        SOPC_ASSERT(SOPC_INVALID_MUTEX != mutI); // See SOPC_Mutex_Initialization

        retCode = pthread_mutex_lock(&mutI->mutex);
        if (retCode == 0)
        {
            status = SOPC_STATUS_OK;
        }
        else
        {
            status = SOPC_STATUS_NOK;
        }
    }
    return status;
}

SOPC_ReturnStatus SOPC_Mutex_Unlock(SOPC_Mutex* mut)
{
    SOPC_ReturnStatus status = SOPC_STATUS_INVALID_PARAMETERS;
    int retCode = 0;
    if (mut != NULL)
    {
        struct SOPC_Mutex_Impl* mutI = (SOPC_Mutex_Impl*) (*mut);
        SOPC_ASSERT(SOPC_INVALID_MUTEX != mutI); // See SOPC_Mutex_Initialization
        retCode = pthread_mutex_unlock(&mutI->mutex);
        if (retCode == 0)
        {
            status = SOPC_STATUS_OK;
        }
        else
        {
            status = SOPC_STATUS_NOK;
        }
    }
    return status;
}

SOPC_ReturnStatus SOPC_Mutex_UnlockAndWaitCond(SOPC_Condition* cond, SOPC_Mutex* mut)
{
    SOPC_ReturnStatus status = SOPC_STATUS_INVALID_PARAMETERS;
    int retCode = 0;
    if (NULL != cond && NULL != mut)
    {
        struct SOPC_Mutex_Impl* mutI = (SOPC_Mutex_Impl*) (*mut);
        struct SOPC_Condition_Impl* condI = (SOPC_Condition_Impl*) (*cond);
        SOPC_ASSERT(SOPC_INVALID_COND != condI && SOPC_INVALID_MUTEX != mutI);

        retCode = pthread_cond_wait(&condI->cond, &mutI->mutex);
        if (retCode == 0)
        {
            status = SOPC_STATUS_OK;
        }
        else
        {
            status = SOPC_STATUS_NOK;
        }
    }
    return status;
}

SOPC_ReturnStatus SOPC_Mutex_UnlockAndTimedWaitCond(SOPC_Condition* cond, SOPC_Mutex* mut, uint32_t milliSecs)
{
    SOPC_ReturnStatus status = SOPC_STATUS_INVALID_PARAMETERS;
    struct timespec absoluteTimeout;

    int retCode = 0;
    if (NULL != cond && NULL != mut && milliSecs > 0)
    {
        // Retrieve current time
        clock_gettime(CLOCK_REALTIME, &absoluteTimeout);

        absoluteTimeout.tv_sec = absoluteTimeout.tv_sec + (time_t)(milliSecs / 1000);
        uint64_t nanoseconds = (milliSecs % 1000) * SOPC_MILLISECOND_TO_NANOSECONDS;

        SOPC_ASSERT(absoluteTimeout.tv_nsec < SOPC_SECOND_TO_NANOSECONDS);
        if (SOPC_SECOND_TO_NANOSECONDS - (uint64_t) absoluteTimeout.tv_nsec < nanoseconds)
        {
            // Additional second
            absoluteTimeout.tv_sec += 1;
            absoluteTimeout.tv_nsec = (long) nanoseconds - (SOPC_SECOND_TO_NANOSECONDS - absoluteTimeout.tv_nsec);
        }
        else
        {
            absoluteTimeout.tv_nsec = absoluteTimeout.tv_nsec + (long) nanoseconds;
        }

        struct SOPC_Mutex_Impl* mutI = (SOPC_Mutex_Impl*) (*mut);
        struct SOPC_Condition_Impl* condI = (SOPC_Condition_Impl*) (*cond);
        SOPC_ASSERT(SOPC_INVALID_COND != condI && SOPC_INVALID_MUTEX != mutI);

        retCode = pthread_cond_timedwait(&condI->cond, &mutI->mutex, &absoluteTimeout);
        if (retCode == 0)
        {
            status = SOPC_STATUS_OK;
        }
        else if (ETIMEDOUT == retCode)
        {
            status = SOPC_STATUS_TIMEOUT;
        }
        else
        {
            status = SOPC_STATUS_NOK;
        }
    }
    return status;
}

static inline SOPC_ReturnStatus create_thread(pthread_t* thread,
                                              pthread_attr_t* attr,
                                              void* (*startFct)(void*),
                                              void* startArgs,
                                              const char* taskName,
                                              int cpuAffinity)
{
    int ret = pthread_create(thread, attr, startFct, startArgs);

    SOPC_ReturnStatus status = (0 == ret) ? SOPC_STATUS_OK : SOPC_STATUS_NOK;
    if (SOPC_STATUS_OK != status)
    {
        fprintf(stderr, "Error cannot create thread: %d\n", ret);
    }
    else
    {
        const char* name = taskName;
        char tmpTaskName[16];

        if (strlen(taskName) >= 16)
        {
            strncpy(tmpTaskName, taskName, 15);
            tmpTaskName[15] = '\0';
            name = tmpTaskName;
        }

        /* pthread_setname_np calls can fail. It is not a sufficient reason to stop processing. */
        ret = pthread_setname_np(*thread, name);
        if (0 != ret)
        {
            fprintf(stderr, "Error during set name \"%s\" to thread: %d\n", taskName, ret);
        }

        if (cpuAffinity >= 0)
        {
            cpu_set_t cpuset;
            CPU_ZERO(&cpuset);
            CPU_SET((size_t) cpuAffinity, &cpuset);

            /* pthread_setname_np calls can fail. It is not a sufficient reason to stop processing. */
            ret = pthread_setaffinity_np(*thread, sizeof(cpu_set_t), &cpuset);
            if (0 != ret)
            {
                fprintf(stderr, "Error during set affinity \"%d\" to thread: %d\n", cpuAffinity, ret);
            }
        }
    }

    return status;
}

SOPC_ReturnStatus SOPC_Thread_Create(SOPC_Thread* thread,
                                     void* (*startFct)(void*),
                                     void* startArgs,
                                     const char* taskName)
{
    if (NULL == thread || NULL == startFct)
    {
        return SOPC_STATUS_INVALID_PARAMETERS;
    }

    SOPC_Thread_Impl* threadImpl = SOPC_Calloc(1, sizeof(*threadImpl));

    if (SOPC_INVALID_THREAD == threadImpl)
    {
        return SOPC_STATUS_OUT_OF_MEMORY;
    }

    SOPC_ReturnStatus status = create_thread(&threadImpl->thread, NULL, startFct, startArgs, taskName, -1);

    if (SOPC_STATUS_OK == status)
    {
        *thread = threadImpl;
    }
    else
    {
        SOPC_Free(threadImpl);
    }

    return status;
}

SOPC_ReturnStatus SOPC_Thread_CreatePrioritized(SOPC_Thread* thread,
                                                void* (*startFct)(void*),
                                                void* startArgs,
                                                int priority,
                                                int cpuAffinity,
                                                const char* taskName)
{
    if (NULL == thread || NULL == startFct || priority < 0 || priority > 99)
    {
        return SOPC_STATUS_INVALID_PARAMETERS;
    }

    struct SOPC_Thread_Impl* threadImpl = SOPC_Calloc(1, sizeof(*threadImpl));

    if (SOPC_INVALID_THREAD == threadImpl)
    {
        return SOPC_STATUS_OUT_OF_MEMORY;
    }

    SOPC_ReturnStatus status = SOPC_STATUS_NOK;
    if (priority == 0)
    {
        status = create_thread(&threadImpl->thread, NULL, startFct, startArgs, taskName, cpuAffinity);
    }
    else
    {
        /* Initialize scheduling policy and priority */
        pthread_attr_t attr;
        int ret = pthread_attr_init(&attr);
        if (0 != ret)
        {
            fprintf(stderr, "Could not initialize pthread attributes: %d\n", ret);
        }
        if (0 == ret)
        {
            ret = pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED);
            if (0 != ret)
            {
                fprintf(stderr, "Could not unset scheduler inheritance in thread creation attributes: %d\n", ret);
            }
        }
        if (0 == ret)
        {
            ret = pthread_attr_setschedpolicy(&attr, SCHED_FIFO);
            if (0 != ret)
            {
                fprintf(stderr, "Could not set thread scheduling policy: %d\n", ret);
            }
        }
        if (0 == ret)
        {
            struct sched_param scp;
            scp.sched_priority = priority;
            ret = pthread_attr_setschedparam(&attr, &scp);
            if (0 != ret)
            {
                fprintf(stderr, "Could not set thread priority: %d\n", ret);
            }
        }

        if (0 == ret)
        {
            status = create_thread(&threadImpl->thread, &attr, startFct, startArgs, taskName, cpuAffinity);
        }
    }

    if (SOPC_STATUS_OK == status)
    {
        *thread = threadImpl;
    }
    else
    {
        SOPC_Free(threadImpl);
    }

    return status;
}

SOPC_ReturnStatus SOPC_Thread_Join(SOPC_Thread* thread)
{
    if (NULL == thread)
    {
        return SOPC_STATUS_INVALID_PARAMETERS;
    }
    SOPC_ReturnStatus status = SOPC_STATUS_NOK;
    SOPC_Thread_Impl* threadImpl = *thread;
    if (SOPC_INVALID_THREAD != threadImpl && pthread_join(threadImpl->thread, NULL) == 0)
    {
        status = SOPC_STATUS_OK;
        SOPC_Free(threadImpl);
        *thread = SOPC_INVALID_THREAD;
    }
    return status;
}

void SOPC_Sleep(unsigned int milliseconds)
{
    usleep(milliseconds * 1000);
}
