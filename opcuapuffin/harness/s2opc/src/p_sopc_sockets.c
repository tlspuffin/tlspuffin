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
#include <fcntl.h>
#ifndef IPPROTO_TCP
#include <linux/in6.h>
#endif
#include <netinet/tcp.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "p_sopc_sockets.h"

#include <s2opc/common/sopc_macros.h>
#include <s2opc/common/sopc_mem_alloc.h>
#include <s2opc/common/sopc_raw_sockets.h>
#include <s2opc/common/sopc_threads.h>

#define SOPC_SECONDS_TO_MILLISECONDS 1000

SOPC_ReturnStatus SOPC_Socket_Network_Enable_Keepalive(SOPC_Socket sock,
                                                       unsigned int firstProbeDelay,
                                                       unsigned int interval,
                                                       unsigned int counter)
{
    SOPC_ReturnStatus status = SOPC_STATUS_INVALID_PARAMETERS;
    const int trueInt = true;
    int setOptStatus = -1;
    /* Set to a value slightly lower than last keep alive transmission delay
        to avoid potential cancellation */
    unsigned int user_timeout = (firstProbeDelay + interval * counter - 1) * SOPC_SECONDS_TO_MILLISECONDS;

    if (SOPC_INVALID_SOCKET == sock)
    {
        return status;
    }

    setOptStatus = setsockopt(sock->sock, SOL_SOCKET, SO_KEEPALIVE, (const void*) &trueInt, sizeof(int));

    if (setOptStatus != -1)
    {
        setOptStatus =
            setsockopt(sock->sock, IPPROTO_TCP, TCP_USER_TIMEOUT, (const void*) &user_timeout, sizeof(user_timeout));
    }

    if (setOptStatus != -1)
    {
        setOptStatus =
            setsockopt(sock->sock, IPPROTO_TCP, TCP_KEEPIDLE, (const void*) &firstProbeDelay, sizeof(firstProbeDelay));
    }

    if (setOptStatus != -1)
    {
        setOptStatus = setsockopt(sock->sock, IPPROTO_TCP, TCP_KEEPINTVL, (const void*) &interval, sizeof(interval));
    }

    if (setOptStatus != -1)
    {
        setOptStatus = setsockopt(sock->sock, IPPROTO_TCP, TCP_KEEPCNT, (const void*) &counter, sizeof(counter));
    }

    if (setOptStatus < 0)
    {
        status = SOPC_STATUS_NOK;
    }

    return status;
}

SOPC_ReturnStatus SOPC_Socket_Network_Disable_Keepalive(SOPC_Socket sock)
{
    SOPC_ReturnStatus status = SOPC_STATUS_INVALID_PARAMETERS;
    const int falseInt = false;
    const int zeroInt = 0;
    int setOptStatus = -1;

    if (SOPC_INVALID_SOCKET == sock)
    {
        return status;
    }

    setOptStatus = setsockopt(sock->sock, SOL_SOCKET, SO_KEEPALIVE, (const void*) &falseInt, sizeof(int));

    if (setOptStatus != -1)
    {
        setOptStatus = setsockopt(sock->sock, IPPROTO_TCP, TCP_USER_TIMEOUT, (const void*) &zeroInt, sizeof(zeroInt));
    }

    if (setOptStatus < 0)
    {
        status = SOPC_STATUS_NOK;
    }

    return status;
}

bool SOPC_Socket_Network_Initialize(void)
{
    return true;
}

bool SOPC_Socket_Network_Clear(void)
{
    return true;
}

SOPC_ReturnStatus SOPC_Socket_AddrInfo_Get(const char* hostname, const char* port, SOPC_Socket_AddressInfo** addrs)
{
    SOPC_ReturnStatus status = SOPC_STATUS_INVALID_PARAMETERS;
    SOPC_Socket_AddressInfo hints;
    memset(&hints, 0, sizeof(SOPC_Socket_AddressInfo));
    hints.addrInfo.ai_family = AF_UNSPEC; // AF_INET or AF_INET6  can be use to force IPV4 or IPV6
    hints.addrInfo.ai_socktype = SOCK_STREAM;
    hints.addrInfo.ai_flags = AI_PASSIVE;

    struct addrinfo* getAddrInfoRes = NULL;

    if ((hostname != NULL || port != NULL) && addrs != NULL)
    {
        if (getaddrinfo(hostname, port, &hints.addrInfo, &getAddrInfoRes) != 0)
        {
            status = SOPC_STATUS_NOK;
        }
        else
        {
            *addrs = (SOPC_Socket_AddressInfo*) getAddrInfoRes;
            status = SOPC_STATUS_OK;
        }
    }
    return status;
}

SOPC_Socket_AddressInfo* SOPC_Socket_AddrInfo_IterNext(SOPC_Socket_AddressInfo* addr)
{
    SOPC_Socket_AddressInfo* res = NULL;
    if (addr != NULL)
    {
        res = (SOPC_Socket_AddressInfo*) addr->addrInfo.ai_next;
    }
    return res;
}

uint8_t SOPC_Socket_AddrInfo_IsIPV6(const SOPC_Socket_AddressInfo* addr)
{
    return addr->addrInfo.ai_family == PF_INET6;
}

void SOPC_Socket_AddrInfoDelete(SOPC_Socket_AddressInfo** addrs)
{
    if (addrs != NULL)
    {
        freeaddrinfo(&(*addrs)->addrInfo);
        *addrs = NULL;
    }
}

void SOPC_SocketAddress_Delete(SOPC_Socket_Address** addr)
{
    if (NULL == addr)
    {
        return;
    }
    if (NULL != *addr)
    {
        SOPC_Free((*addr)->address.ai_addr);
    }
    SOPC_Free(*addr);
    *addr = NULL;
}

SOPC_Socket_Address* SOPC_Socket_CopyAddress(SOPC_Socket_AddressInfo* addr)
{
    SOPC_Socket_Address* result = SOPC_Calloc(1, sizeof(*result));
    if (NULL != result)
    {
        result->address.ai_addr = SOPC_Calloc(1, addr->addrInfo.ai_addrlen);
        result->address.ai_addrlen = addr->addrInfo.ai_addrlen;
        result->address.ai_family = addr->addrInfo.ai_family;
        if (NULL != result->address.ai_addr)
        {
            result->address.ai_addr =
                memcpy(result->address.ai_addr, addr->addrInfo.ai_addr, addr->addrInfo.ai_addrlen);
        }
        else
        {
            SOPC_Free(result);
            result = NULL;
        }
    }
    return result;
}

SOPC_Socket_Address* SOPC_Socket_GetPeerAddress(SOPC_Socket sock)
{
    if (sock == SOPC_INVALID_SOCKET)
    {
        return NULL;
    }
    SOPC_Socket_Address* result = SOPC_Calloc(1, sizeof(*result));
    struct sockaddr_storage* sockAddrStorage = SOPC_Calloc(1, sizeof(*sockAddrStorage));
    socklen_t sockAddrStorageLen = sizeof(*sockAddrStorage);
    int res = -1;
    if (NULL != result && NULL != sockAddrStorage)
    {
        res = getpeername(sock->sock, (struct sockaddr*) sockAddrStorage, &sockAddrStorageLen);
        if (0 == res)
        {
            result->address.ai_family = sockAddrStorage->ss_family;
            result->address.ai_addrlen = sockAddrStorageLen;
            result->address.ai_addr = (struct sockaddr*) sockAddrStorage;
        }
    }
    if (res != 0)
    {
        SOPC_Free(sockAddrStorage);
        SOPC_Free(result);
        result = NULL;
    }
    return result;
}

SOPC_ReturnStatus SOPC_SocketAddress_GetNameInfo(const SOPC_Socket_Address* addr, char** host, char** service)
{
    SOPC_ReturnStatus status = SOPC_STATUS_INVALID_PARAMETERS;
    if (NULL == addr || (NULL == host && NULL == service))
    {
        return status;
    }
    int flags = 0;
    status = SOPC_STATUS_OK;
    char* hostRes = NULL;
    char* serviceRes = NULL;
    if (NULL != host)
    {
        flags |= NI_NUMERICHOST;

        hostRes = SOPC_Calloc(NI_MAXHOST, sizeof(*hostRes));
        if (hostRes == NULL)
        {
            status = SOPC_STATUS_OUT_OF_MEMORY;
        }
    }
    if (SOPC_STATUS_OK == status && NULL != service)
    {
        flags |= NI_NUMERICSERV;
        serviceRes = SOPC_Calloc(NI_MAXSERV, sizeof(*serviceRes));
        if (serviceRes == NULL)
        {
            status = SOPC_STATUS_OUT_OF_MEMORY;
        }
    }
    if (SOPC_STATUS_OK == status)
    {
        int res = getnameinfo(addr->address.ai_addr, addr->address.ai_addrlen, hostRes, NI_MAXHOST, serviceRes,
                              NI_MAXSERV, flags);
        if (0 != res)
        {
            status = SOPC_STATUS_NOK;
        }
    }
    if (SOPC_STATUS_OK != status)
    {
        SOPC_Free(hostRes);
        SOPC_Free(serviceRes);
    }
    else
    {
        if (NULL != host)
        {
            *host = hostRes;
        }
        if (NULL != service)
        {
            *service = serviceRes;
        }
    }
    return status;
}

void SOPC_Socket_Clear(SOPC_Socket* sock)
{
    *sock = SOPC_INVALID_SOCKET;
}

static SOPC_ReturnStatus Socket_Configure(int sock, bool setNonBlocking)
{
    SOPC_ReturnStatus status = SOPC_STATUS_INVALID_PARAMETERS;
    const int trueInt = true;
    int setOptStatus = -1;

    if (sock != -1)
    {
        status = SOPC_STATUS_OK;

        // Deactivate Nagle's algorithm since we always write a TCP UA binary message (and not just few bytes)
        setOptStatus = setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const void*) &trueInt, sizeof(int));

        /*
        if(setOptStatus != -1){
            int rcvbufsize = UINT16_MAX;
            setOptStatus = setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbufsize, sizeof(int));
        }

        if(setOptStatus != -1){
            int sndbufsize = UINT16_MAX;
            setOptStatus = setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbufsize, sizeof(int));
        }
        */

        if (setOptStatus != -1 && setNonBlocking != false)
        {
            S2OPC_TEMP_FAILURE_RETRY(setOptStatus, fcntl(sock, F_SETFL, O_NONBLOCK));
        }

        if (setOptStatus < 0)
        {
            status = SOPC_STATUS_NOK;
        }
    }

    return status;
}

SOPC_ReturnStatus SOPC_Socket_CreateNew(SOPC_Socket_AddressInfo* addr,
                                        bool setReuseAddr,
                                        bool setNonBlocking,
                                        SOPC_Socket* sock)
{
    if (NULL == addr || NULL == sock)
    {
        return SOPC_STATUS_INVALID_PARAMETERS;
    }
    SOPC_Socket_Impl* socketImpl = SOPC_Calloc(1, sizeof(*socketImpl));
    if (NULL == socketImpl)
    {
        return SOPC_STATUS_OUT_OF_MEMORY;
    }
    SOPC_ReturnStatus status = SOPC_STATUS_NOK;
    const int trueInt = true;
    int setOptStatus = -1;

    socketImpl->sock = socket(addr->addrInfo.ai_family, addr->addrInfo.ai_socktype, addr->addrInfo.ai_protocol);

    if (socketImpl->sock < 0)
    {
        SOPC_Free(socketImpl);
        return SOPC_STATUS_NOK;
    }
    status = Socket_Configure(socketImpl->sock, setNonBlocking);

    if (SOPC_STATUS_OK == status)
    {
        setOptStatus = 0;
    } // else -1 due to init

    if (setOptStatus != -1 && setReuseAddr != false)
    {
        setOptStatus = setsockopt(socketImpl->sock, SOL_SOCKET, SO_REUSEADDR, (const void*) &trueInt, sizeof(int));
    }

    // Enforce IPV6 sockets can be used for IPV4 connections (if socket is IPV6)
    if (setOptStatus != -1 && addr->addrInfo.ai_family == AF_INET6)
    {
        const int falseInt = false;
        setOptStatus = setsockopt(socketImpl->sock, IPPROTO_IPV6, IPV6_V6ONLY, (const void*) &falseInt, sizeof(int));
    }

    if (setOptStatus < 0)
    {
        status = SOPC_STATUS_NOK;
    }
    if (SOPC_STATUS_OK == status)
    {
        *sock = socketImpl;
    }
    else
    {
        int res = -1;
        S2OPC_TEMP_FAILURE_RETRY(res, close(socketImpl->sock));
        SOPC_Free(socketImpl);
        *sock = SOPC_INVALID_SOCKET;
    }
    return status;
}

SOPC_ReturnStatus SOPC_Socket_Listen(SOPC_Socket sock, SOPC_Socket_AddressInfo* addr)
{
    if (SOPC_INVALID_SOCKET == sock)
    {
        return SOPC_STATUS_INVALID_PARAMETERS;
    }
    SOPC_ReturnStatus status = SOPC_STATUS_INVALID_PARAMETERS;
    int bindListenStatus = -1;
    if (addr != NULL)
    {
        bindListenStatus = bind(sock->sock, addr->addrInfo.ai_addr, addr->addrInfo.ai_addrlen);
        if (bindListenStatus != -1)
        {
            bindListenStatus = listen(sock->sock, SOMAXCONN);
        }
    }
    if (bindListenStatus != -1)
    {
        status = SOPC_STATUS_OK;
    }
    return status;
}

SOPC_ReturnStatus SOPC_Socket_Accept(SOPC_Socket listeningSock, bool setNonBlocking, SOPC_Socket* acceptedSock)
{
    if (SOPC_INVALID_SOCKET == listeningSock || NULL == acceptedSock)
    {
        return SOPC_STATUS_INVALID_PARAMETERS;
    }
    SOPC_Socket_Impl* acceptedImpl = SOPC_Calloc(1, sizeof(*acceptedImpl));
    if (NULL == acceptedImpl)
    {
        return SOPC_STATUS_OUT_OF_MEMORY;
    }
    SOPC_ReturnStatus status = SOPC_STATUS_INVALID_PARAMETERS;
    struct sockaddr remoteAddr;
    socklen_t addrLen = sizeof(remoteAddr);
    if (listeningSock->sock != -1)
    {
        S2OPC_TEMP_FAILURE_RETRY(acceptedImpl->sock, accept(listeningSock->sock, &remoteAddr, &addrLen));
        //        SOPC_CONSOLE_PRINTF("selectserver: new connection from %s on socket %d\n",
        //                inet_ntop(remoteaddr.sa_family,
        //                    get_in_addr((struct sockaddr*)&remoteaddr),
        //                    remoteIP, INET6_ADDRSTRLEN),
        //                acceptSock);
        if (acceptedImpl->sock != -1)
        {
            status = Socket_Configure(acceptedImpl->sock, setNonBlocking);
        }
    }
    if (SOPC_STATUS_OK == status)
    {
        *acceptedSock = acceptedImpl;
    }
    else
    {
        SOPC_Socket_Close(&acceptedImpl);
    }
    return status;
}

SOPC_ReturnStatus SOPC_Socket_Connect(SOPC_Socket sock, SOPC_Socket_AddressInfo* addr)
{
    SOPC_ReturnStatus status = SOPC_STATUS_INVALID_PARAMETERS;
    int connectStatus = -1;
    if (addr != NULL && sock != SOPC_INVALID_SOCKET)
    {
        S2OPC_TEMP_FAILURE_RETRY(connectStatus, connect(sock->sock, addr->addrInfo.ai_addr, addr->addrInfo.ai_addrlen));
        if (connectStatus < 0)
        {
            if (errno == EINPROGRESS)
            {
                // Non blocking connection started
                connectStatus = 0;
            }
        }
        if (connectStatus == 0)
        {
            status = SOPC_STATUS_OK;
        }
    }
    return status;
}

SOPC_ReturnStatus SOPC_Socket_ConnectToLocal(SOPC_Socket from, SOPC_Socket to)
{
    SOPC_ReturnStatus status = SOPC_STATUS_INVALID_PARAMETERS;
    SOPC_Socket_AddressInfo addr;
    struct sockaddr saddr;
    memset(&addr, 0, sizeof(SOPC_Socket_AddressInfo));
    memset(&saddr, 0, sizeof(struct sockaddr));
    addr.addrInfo.ai_addr = &saddr;
    addr.addrInfo.ai_addrlen = sizeof(struct sockaddr);

    if (0 == getsockname(to->sock, addr.addrInfo.ai_addr, &addr.addrInfo.ai_addrlen))
    {
        status = SOPC_Socket_Connect(from, &addr);
    }

    return status;
}

SOPC_ReturnStatus SOPC_Socket_CheckAckConnect(SOPC_Socket sock)
{
    SOPC_ReturnStatus status = SOPC_STATUS_INVALID_PARAMETERS;
    int error = 0;
    socklen_t len = sizeof(int);
    if (sock != SOPC_INVALID_SOCKET)
    {
        if (getsockopt(sock->sock, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error != 0)
        {
            status = SOPC_STATUS_NOK;
        }
        else
        {
            status = SOPC_STATUS_OK;
        }
    }
    return status;
}

SOPC_SocketSet* SOPC_SocketSet_Create(void)
{
    SOPC_SocketSet* res = SOPC_Calloc(1, sizeof(SOPC_SocketSet));
    if (NULL != res)
    {
        SOPC_SocketSet_Clear(res);
    }
    return res;
}

void SOPC_SocketSet_Delete(SOPC_SocketSet** set)
{
    if (NULL != set)
    {
        SOPC_Free(*set);
        *set = NULL;
    }
}

void SOPC_SocketSet_Add(SOPC_Socket sock, SOPC_SocketSet* sockSet)
{
    if (sock != SOPC_INVALID_SOCKET && sockSet != NULL)
    {
        FD_SET(sock->sock, &sockSet->set);
        if (sock->sock > sockSet->fdmax)
        {
            sockSet->fdmax = sock->sock;
        }
    }
}

bool SOPC_SocketSet_IsPresent(SOPC_Socket sock, SOPC_SocketSet* sockSet)
{
    if (sock != SOPC_INVALID_SOCKET && sockSet != NULL)
    {
        if (false == FD_ISSET(sock->sock, &sockSet->set))
        {
            return false;
        }
        else
        {
            return true;
        }
    }
    return false;
}

void SOPC_SocketSet_Clear(SOPC_SocketSet* sockSet)
{
    if (sockSet != NULL)
    {
        FD_ZERO(&sockSet->set);
        sockSet->fdmax = 0;
    }
}

int32_t SOPC_Socket_WaitSocketEvents(SOPC_SocketSet* readSet,
                                     SOPC_SocketSet* writeSet,
                                     SOPC_SocketSet* exceptSet,
                                     uint32_t waitMs)
{
    int32_t nbReady = 0;
    struct timeval timeout;
    struct timeval* val;
    int fdmax = 0;
    if (readSet->fdmax > writeSet->fdmax)
    {
        fdmax = readSet->fdmax;
    }
    else
    {
        fdmax = writeSet->fdmax;
    }
    if (exceptSet->fdmax > fdmax)
    {
        fdmax = exceptSet->fdmax;
    }

    if (waitMs == 0)
    {
        val = NULL;
    }
    else
    {
        timeout.tv_sec = (time_t)(waitMs / 1000);
        timeout.tv_usec = (suseconds_t)(1000 * (waitMs % 1000));
        val = &timeout;
    }
    S2OPC_TEMP_FAILURE_RETRY(nbReady, select(fdmax + 1, &readSet->set, &writeSet->set, &exceptSet->set, val));
    return (int32_t) nbReady;
}

SOPC_ReturnStatus SOPC_Socket_Write(SOPC_Socket sock, const uint8_t* data, uint32_t count, uint32_t* sentBytes)
{
    SOPC_ReturnStatus status = SOPC_STATUS_INVALID_PARAMETERS;
    ssize_t res = 0;
    if (sock != SOPC_INVALID_SOCKET && data != NULL && count <= INT32_MAX && sentBytes != NULL)
    {
        status = SOPC_STATUS_NOK;
        /* Don't generate a SIGPIPE signal if the peer on a stream-
              oriented socket has closed the connection. */
        S2OPC_TEMP_FAILURE_RETRY(res, send(sock->sock, data, count, MSG_NOSIGNAL));

        if (res >= 0)
        {
            status = SOPC_STATUS_OK;
            *sentBytes = (uint32_t) res;
        }
        else
        {
            *sentBytes = 0;

            // ERROR CASE
#if EWOULDBLOCK == EAGAIN
            if ((EAGAIN == errno))
#else
            if ((EAGAIN == errno) || (EWOULDBLOCK == errno))
#endif
            {
                // Try again in those cases
                status = SOPC_STATUS_WOULD_BLOCK;
            } // else: error, keep SOPC_STATUS_NOK
        }
    }
    return status;
}

SOPC_ReturnStatus SOPC_Socket_Read(SOPC_Socket sock, uint8_t* data, uint32_t dataSize, uint32_t* readCount)
{
    SOPC_ReturnStatus status = SOPC_STATUS_INVALID_PARAMETERS;
    ssize_t sReadCount = 0;
    if (sock != SOPC_INVALID_SOCKET && data != NULL && dataSize > 0 && NULL != readCount)
    {
        S2OPC_TEMP_FAILURE_RETRY(sReadCount, recv(sock->sock, data, dataSize, 0));

        /* Extract of man recv (release 3.54 of the Linux man-pages project):
         * RETURN VALUE
         * These calls return the number of bytes received, or -1 if an error occurred.  In the event of an error,
         * errno is set to indicate the error.  The return value will be 0 when the peer has performed  an orderly
         * shutdown. */

        if (sReadCount > 0)
        {
            *readCount = (uint32_t) sReadCount;
            status = SOPC_STATUS_OK;
        }
        else if (sReadCount == 0)
        {
            *readCount = 0;
            status = SOPC_STATUS_CLOSED;
        }
        else if (sReadCount == -1)
        {
            *readCount = 0;

            /* Extract of man recv (release 3.54 of the Linux man-pages project):
             * If  no  messages  are available at the socket, the receive calls wait for a message to arrive, unless the
             * socket is onblocking (see fcntl(2)), in which case the value -1 is returned and the external variable
             * errno is set to EAGAIN or  WOULDBLOCK.  The receive calls normally return any data available, up to the
             * requested amount, rather than waiting for receipt of the full amount requested.*/

#if EWOULDBLOCK == EAGAIN
            if ((EAGAIN == errno))
#else
            if ((EAGAIN == errno) || (EWOULDBLOCK == errno))
#endif
            {
                status = SOPC_STATUS_WOULD_BLOCK;
            }
        }
        else
        {
            status = SOPC_STATUS_NOK;
        }
    }
    return status;
}

SOPC_ReturnStatus SOPC_Socket_BytesToRead(SOPC_Socket sock, uint32_t* bytesToRead)
{
    SOPC_ReturnStatus status = SOPC_STATUS_INVALID_PARAMETERS;
    int nbBytes = 0;
    if (sock != SOPC_INVALID_SOCKET && bytesToRead != NULL)
    {
        int res = 0;
        S2OPC_TEMP_FAILURE_RETRY(res, ioctl(sock->sock, FIONREAD, &nbBytes));
        if (res == 0 && nbBytes >= 0)
        {
            if ((uint64_t) nbBytes < UINT32_MAX)
            {
                *bytesToRead = (uint32_t) nbBytes;
            }
            else
            {
                *bytesToRead = UINT32_MAX;
            }

            status = SOPC_STATUS_OK;
        }
        else
        {
            status = SOPC_STATUS_NOK;
        }
    }
    return status;
}

void SOPC_Socket_Close(SOPC_Socket* sock)
{
    if (sock != NULL && *sock != SOPC_INVALID_SOCKET)
    {
        int res = 0;
        S2OPC_TEMP_FAILURE_RETRY(res, close((*sock)->sock));
        if (res != -1)
        {
            SOPC_Free(*sock);
            *sock = SOPC_INVALID_SOCKET;
        }
    }
}
