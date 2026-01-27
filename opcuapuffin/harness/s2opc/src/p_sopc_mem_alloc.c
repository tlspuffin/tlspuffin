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

#include <stdlib.h>

#include <s2opc/common/sopc_macros.h>
#include <s2opc/common/sopc_mem_alloc.h>

void* SOPC_Malloc(size_t size)
{
    return malloc(size);
}

void SOPC_Free(void* ptr)
{
    free(ptr);
}

void* SOPC_Calloc(size_t nmemb, size_t size)
{
    return calloc(nmemb, size);
}

void* SOPC_Realloc(void* ptr, size_t old_size, size_t new_size)
{
    SOPC_UNUSED_ARG(old_size);
    return realloc(ptr, new_size);
}
