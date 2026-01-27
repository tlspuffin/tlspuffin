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

#include <s2opc/common/sopc_filesystem.h>

#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <s2opc/common/sopc_assert.h>
#include <s2opc/common/sopc_enums.h>
#include <s2opc/common/sopc_helper_string.h>
#include <s2opc/common/sopc_mem_alloc.h>

SOPC_FileSystem_CreationResult SOPC_FileSystem_mkdir(const char* directoryPath)
{
    int res = mkdir(directoryPath, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    if (res == 0)
    {
        return SOPC_FileSystem_Creation_OK;
    }
    else if (res == -1)
    {
        switch (errno)
        {
        case ENOENT:
            return SOPC_FileSystem_Creation_Error_PathPrefixInvalid;
        case EEXIST:
            return SOPC_FileSystem_Creation_Error_PathAlreadyExists;
        case EACCES:
            return SOPC_FileSystem_Creation_Error_PathPermisionDenied;
        default:
            return SOPC_FileSystem_Creation_Error_PathResolutionIssue;
        }
    }
    else
    {
        return SOPC_FileSystem_Creation_Error_UnknownIssue;
    }
}

SOPC_FileSystem_RemoveResult SOPC_FileSystem_rmdir(const char* directoryPath)
{
    int res = rmdir(directoryPath);
    if (res == 0)
    {
        return SOPC_FileSystem_Remove_OK;
    }
    else if (res == -1)
    {
        switch (errno)
        {
        case ENOENT:
            return SOPC_FileSystem_Remove_Error_PathInvalid;
        case ENOTEMPTY:
        case EEXIST:
            return SOPC_FileSystem_Remove_Error_PathNotEmpty;
        case EACCES:
        case EPERM:
        case EBUSY:
            return SOPC_FileSystem_Remove_Error_PathPermisionDenied;
        default:
            return SOPC_FileSystem_Remove_Error_UnknownIssue;
        }
    }
    else
    {
        return SOPC_FileSystem_Remove_Error_UnknownIssue;
    }
}

static SOPC_ReturnStatus get_file_path(const char* pDirectoryPath, const char* pFileName, char** ppFilePath)
{
    SOPC_ASSERT(NULL != pDirectoryPath && NULL != pFileName && NULL != ppFilePath);

    char* tmp = NULL;
    SOPC_ReturnStatus status = SOPC_StrConcat(pDirectoryPath, "/", &tmp);
    if (SOPC_STATUS_OK == status)
    {
        status = SOPC_StrConcat(tmp, pFileName, ppFilePath);
    }
    SOPC_Free(tmp);
    return status;
}

static SOPC_ReturnStatus is_regular_file(const char* pFilePath, bool* result)
{
    *result = true;
    /* Get informations about the current file */
    struct stat info = {0};
    int res = stat(pFilePath, &info);
    SOPC_ReturnStatus status = 0 == res ? SOPC_STATUS_OK : SOPC_STATUS_NOK;
    /* Only keep regular file => avoid dir, fifo, link ...*/
    if (SOPC_STATUS_OK == status)
    {
        if (!S_ISREG(info.st_mode))
        {
            *result = false;
        }
    }
    return status;
}

static void SOPC_Free_CstringFromPtr(void* data)
{
    if (NULL != data)
    {
        SOPC_Free(*(char**) data);
    }
}

/* if isName is set to True then ppFileInfos is an array of names else of paths. */
static SOPC_FileSystem_GetDirResult get_dir_files_infos(const char* directoryPath,
                                                        SOPC_Array** ppFileInfos,
                                                        const bool bIsName)
{
    SOPC_Array* pFileInfos = NULL;
    SOPC_ReturnStatus status = SOPC_STATUS_OK;
    DIR* d = NULL;
    struct dirent* dir = {0};
    char* pFilePath = NULL;
    char* pFileName = NULL;
    bool bIsRegular = false;
    bool bResAppend = false;

    d = opendir(directoryPath);
    if (NULL == d)
    {
        return SOPC_FileSystem_GetDir_Error_PathInvalid;
    }
    /* Read before while */
    dir = readdir(d);
    /* Create the array to store the informations */
    pFileInfos = SOPC_Array_Create(sizeof(char*), 0, SOPC_Free_CstringFromPtr);
    if (NULL == pFileInfos)
    {
        status = SOPC_STATUS_NOK;
    }
    while (NULL != dir && SOPC_STATUS_OK == status)
    {
        /* Retrieve the file path */
        status = get_file_path(directoryPath, dir->d_name, &pFilePath);
        if (SOPC_STATUS_OK == status)
        {
            /* We don't want sub folders! Is it a regular file? */
            status = is_regular_file(pFilePath, &bIsRegular);
        }
        /* Only keep regular file */
        if (!bIsRegular && SOPC_STATUS_OK == status)
        {
            /* Next iteration */
            SOPC_Free(pFilePath);
            pFilePath = NULL;
            dir = readdir(d);
            continue;
        }
        /* Append the fileName or the filePath to the array */
        if (SOPC_STATUS_OK == status)
        {
            if (bIsName)
            {
                pFileName = SOPC_strdup(dir->d_name);
                bResAppend = SOPC_Array_Append(pFileInfos, pFileName);
                SOPC_Free(pFilePath); // We do not need filePath anymore and have to free it.
                pFilePath = NULL;
            }
            else
            {
                bResAppend = SOPC_Array_Append(pFileInfos, pFilePath);
            }
            status = bResAppend ? SOPC_STATUS_OK : SOPC_STATUS_NOK;
        }
        /* Next iteration */
        dir = readdir(d);
    }
    /* Close after while */
    closedir(d);
    /* Clear */
    if (SOPC_STATUS_OK != status)
    {
        /* Clear */
        SOPC_Free(pFilePath);
        SOPC_Free(pFileName);
        SOPC_Array_Delete(pFileInfos);
        *ppFileInfos = NULL;
        return SOPC_FileSystem_GetDir_Error_UnknownIssue;
    }

    *ppFileInfos = pFileInfos;
    return SOPC_FileSystem_GetDir_OK;
}

SOPC_FileSystem_GetDirResult SOPC_FileSystem_GetDirFilePaths(const char* directoryPath, SOPC_Array** ppFilePaths)
{
    if (NULL == directoryPath || NULL == ppFilePaths)
    {
        return SOPC_FileSystem_GetDir_Error_InvalidParameters;
    }

    SOPC_FileSystem_GetDirResult res = get_dir_files_infos(directoryPath, ppFilePaths, false);

    return res;
}

FILE* SOPC_FileSystem_fmemopen(void* buf, size_t size, const char* opentype)
{
    return fmemopen(buf, size, opentype);
}
