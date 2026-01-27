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

#include <s2opc/common/sopc_atomic.h>

int32_t SOPC_Atomic_Int_Get(int32_t* atomic)
{
#if !defined(__clang__) && (__GNUC__ > 4)
    // This version works with TSan, the other one creates false positives...
    return (int32_t) __atomic_load_4(atomic, __ATOMIC_SEQ_CST);
#else
    __sync_synchronize();
    return *atomic;
#endif
}

void SOPC_Atomic_Int_Set(int32_t* atomic, int32_t val)
{
#if !defined(__clang__) && (__GNUC__ > 4)
    __atomic_store_4(atomic, (unsigned int) val, __ATOMIC_SEQ_CST);
#else
    *atomic = val;
    __sync_synchronize();
#endif
}

int32_t SOPC_Atomic_Int_Add(int32_t* atomic, int32_t val)
{
#if !defined(__clang__) && (__GNUC__ > 4)
    return __atomic_fetch_add(atomic, val, __ATOMIC_SEQ_CST);
#else
    return __sync_fetch_and_add(atomic, val);
#endif
}

void* SOPC_Atomic_Ptr_Get(void** atomic)
{
#if !defined(__clang__) && (__GNUC__ > 4)

#if SOPC_PTR_SIZE == 4
    return (void*) __atomic_load_4(atomic, __ATOMIC_SEQ_CST);
#elif SOPC_PTR_SIZE == 8
    return (void*) __atomic_load_8(atomic, __ATOMIC_SEQ_CST);
#else
#error "Unsupported pointer size or SOPC_PTR_SIZE not defined"
#endif // SOPC_PTR_SIZE

#else
    __sync_synchronize();
    return *atomic;
#endif // !defined(clang)
}

void SOPC_Atomic_Ptr_Set(void** atomic, void* val)
{
#if !defined(__clang__) && (__GNUC__ > 4)

#if SOPC_PTR_SIZE == 4
    __atomic_store_4(atomic, (uintptr_t) val, __ATOMIC_SEQ_CST);
#elif SOPC_PTR_SIZE == 8
    __atomic_store_8(atomic, (uintptr_t) val, __ATOMIC_SEQ_CST);
#else
#error "Unsupported pointer size or SOPC_PTR_SIZE not defined"
#endif // SOPC_PTR_SIZE

#else
    *atomic = val;
    __sync_synchronize();
#endif // !defined(clang)
}
