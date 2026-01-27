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

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include <s2opc/common/sopc_askpass.h>
#include <s2opc/common/sopc_mem_alloc.h>

// 3 additional characters to guarantee retrieved value ends with "\n\0\0"
#define PWD_BUFFER_ADDITIONAL_CHARACTERS 3

bool SOPC_AskPass_CustomPromptFromTerminal(const char* prompt, char** outPassword)
{
    char* result = NULL;

    if (NULL == prompt || NULL == outPassword)
    {
        return false;
    }

    struct termios old = {0};
    struct termios new = {0};
    // Open TTY
    int fd_tty = open("/dev/tty", O_RDWR | O_NOCTTY);
    if (fd_tty < 0)
    {
        return false;
    }
    FILE* file_tty = fdopen(fd_tty, "w+");
    if (NULL == file_tty)
    {
        close(fd_tty);
        return false;
    }

    // Allocated password: 3 additional characters to guarantee max length: ends with "\n\0\0"
    char* pwd = SOPC_Calloc(sizeof(char), SOPC_PASSWORD_MAX_LENGTH + PWD_BUFFER_ADDITIONAL_CHARACTERS);
    if (NULL == pwd)
    {
        // note: also closes the underlying file descriptor
        fclose(file_tty);
        return false;
    }

    // Set no echo
    int res = tcgetattr(fd_tty, &old);

    if (0 == res)
    {
        new = old;
        new.c_lflag &= (tcflag_t) ~(ECHO | ECHOE | ECHOK | ECHONL);
        // TCSAFLUSH: the change occurs after all output transmitted and all input not read yet are discarded
        res = tcsetattr(fd_tty, TCSAFLUSH, &new);
    }

    if (0 == res)
    {
        // Prompt for the user for password
        fputs(prompt, file_tty);
        fflush(file_tty);

        // Retrieve the password (locking file_tty)
        result = fgets(pwd, SOPC_PASSWORD_MAX_LENGTH + PWD_BUFFER_ADDITIONAL_CHARACTERS, file_tty);

        // Restore echo
        tcsetattr(fd_tty, TCSAFLUSH, &old);
        fflush(file_tty);
        fputs("\n", file_tty);
    }

    // note: also closes the underlying file descriptor
    fclose(file_tty);

    if (NULL != result)
    {
        size_t len = strlen(pwd);

        // 1) Comply with CERT rule FIO37-C. Do not assume that fgets() returns a nonempty string when successful:
        //    len > 0 ensures write-outside-array-bounds error cannot happen
        // 2) Comply  with CERT rule FIO20-C. Avoid unintentional truncation when using fgets():
        //    len <= SOPC_PASSWORD_MAX_LENGTH + 1 ensures a '\n' character is present and no truncation occured
        if (len > 0 && len <= SOPC_PASSWORD_MAX_LENGTH + 1) // includes '\n'
        {
            pwd[len - 1] = '\0';
            *outPassword = pwd;
        }
        else
        {
            // Password exceeds maximum size
            result = NULL;
        }
    }

    if (NULL == result)
    {
        // Comply with CERT rule FIO40-C: reset strings on fgets() failure
        SOPC_Free(pwd);
        pwd = NULL;
    }

    return (NULL != pwd);
}
