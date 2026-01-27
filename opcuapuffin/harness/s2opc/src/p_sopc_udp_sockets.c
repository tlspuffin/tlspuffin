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

#include <s2opc/common/sopc_udp_sockets.h>

#include "p_sopc_sockets.h"

#include <s2opc/common/sopc_assert.h>
#include <s2opc/common/sopc_common_constants.h>
#include <s2opc/common/sopc_macros.h>
#include <s2opc/common/sopc_mem_alloc.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

static SOPC_ReturnStatus SOPC_UDP_Socket_AddrInfo_Get(bool IPv6,
                                                      const char* node,
                                                      const char* port,
                                                      SOPC_Socket_AddressInfo** addrs)
{
    SOPC_ReturnStatus status = SOPC_STATUS_INVALID_PARAMETERS;
    SOPC_Socket_AddressInfo hints;
    memset(&hints, 0, sizeof(SOPC_Socket_AddressInfo));
    hints.addrInfo.ai_family = (IPv6 ? AF_INET6 : AF_INET);
    hints.addrInfo.ai_socktype = SOCK_DGRAM;
    hints.addrInfo.ai_flags = AI_PASSIVE;
    hints.addrInfo.ai_protocol = IPPROTO_UDP;

    struct addrinfo* getAddrInfoRes = NULL;
    if ((NULL != node || NULL != port) && NULL != addrs)
    {
        if (getaddrinfo(node, port, &hints.addrInfo, &getAddrInfoRes) != 0)
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

SOPC_Socket_AddressInfo* SOPC_UDP_SocketAddress_Create(bool IPv6, const char* node, const char* service)
{
    SOPC_Socket_AddressInfo* addr = NULL;
    SOPC_ReturnStatus status = SOPC_UDP_Socket_AddrInfo_Get(IPv6, node, service, &addr);
    if (SOPC_STATUS_OK != status)
    {
        addr = NULL;
    }
    return addr;
}

void SOPC_UDP_SocketAddress_Delete(SOPC_Socket_AddressInfo** addr)
{
    SOPC_Socket_AddrInfoDelete(addr);
}

SOPC_ReturnStatus SOPC_UDP_Socket_Set_MulticastTTL(SOPC_Socket sock, uint8_t TTL_scope)
{
    int setOptStatus = -1;

    if (SOPC_INVALID_SOCKET != sock)
    {
        setOptStatus = setsockopt(sock->sock, IPPROTO_IP, IP_MULTICAST_TTL, &TTL_scope, sizeof(TTL_scope));

        if (setOptStatus < 0)
        {
            return SOPC_STATUS_NOK;
        }
        else
        {
            return SOPC_STATUS_OK;
        }
    }
    return SOPC_STATUS_INVALID_PARAMETERS;
}

static void* get_ai_addr(const SOPC_Socket_AddressInfo* addr)
{
    return addr->addrInfo.ai_addr;
}

static struct ip_mreqn SOPC_Internal_Fill_IP_mreq(const SOPC_Socket_AddressInfo* multiCastAddr, unsigned int if_index)
{
    SOPC_ASSERT(multiCastAddr != NULL);
    struct ip_mreqn membership;

    membership.imr_multiaddr.s_addr = ((struct sockaddr_in*) get_ai_addr(multiCastAddr))->sin_addr.s_addr;
    SOPC_ASSERT(if_index > 0);
    membership.imr_ifindex = (int) if_index;
    membership.imr_address.s_addr = htonl(INADDR_ANY);
    return membership;
}

static struct ipv6_mreq SOPC_Internal_Fill_IP6_mreq(const SOPC_Socket_AddressInfo* multiCastAddr, unsigned int if_index)
{
    SOPC_ASSERT(if_index > 0);
    SOPC_ASSERT(multiCastAddr != NULL);
    SOPC_ASSERT(SOPC_Socket_AddrInfo_IsIPV6(multiCastAddr));
    struct ipv6_mreq membership;

    membership.ipv6mr_multiaddr = ((struct sockaddr_in6*) get_ai_addr(multiCastAddr))->sin6_addr;
    membership.ipv6mr_interface = if_index;

    return membership;
}

static bool setMembershipOption(int sock,
                                const SOPC_Socket_AddressInfo* multicast,
                                unsigned int ifindex,
                                int level,
                                int optname)
{
    int setOptStatus = -1;
    if (IPPROTO_IPV6 == level)
    {
        if (SOPC_Socket_AddrInfo_IsIPV6(multicast))
        {
            struct ipv6_mreq membershipV6 = SOPC_Internal_Fill_IP6_mreq(multicast, ifindex);
            setOptStatus = setsockopt(sock, level, optname, &membershipV6, sizeof(membershipV6));
        }
    }
    else if (IPPROTO_IP == level)
    {
        struct ip_mreqn membership = SOPC_Internal_Fill_IP_mreq(multicast, ifindex);
        setOptStatus = setsockopt(sock, level, optname, &membership, sizeof(membership));
    }
    else
    {
        SOPC_ASSERT(false);
    }
    return (0 == setOptStatus);
}

static SOPC_ReturnStatus applyMembershipToAllInterfaces(int sock,
                                                        const SOPC_Socket_AddressInfo* multicast,
                                                        int optnameIPv4,
                                                        int optnameIPv6)
{
    // Without interfaceName provided: drop on all possible interfaces
    struct ifaddrs* ifap = NULL;
    int result = getifaddrs(&ifap);

    if (0 != result)
    {
        return SOPC_STATUS_NOT_SUPPORTED;
    }

    uint32_t counter = 0;
    bool atLeastOneItfSuccess = false;

    for (struct ifaddrs* ifa = ifap; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr)
        {
            if (AF_INET6 == multicast->addrInfo.ai_family)
            {
                if (AF_INET6 == ifa->ifa_addr->sa_family)
                {
                    counter++;
                    atLeastOneItfSuccess |=
                        setMembershipOption(sock, multicast, if_nametoindex(ifa->ifa_name), IPPROTO_IPV6, optnameIPv6);
                }
            }
            else
            {
                if (AF_INET == ifa->ifa_addr->sa_family)
                {
                    counter++;
                    atLeastOneItfSuccess |=
                        setMembershipOption(sock, multicast, if_nametoindex(ifa->ifa_name), IPPROTO_IP, optnameIPv4);
                }
            }
        }
    }
    freeifaddrs(ifap);

    if (0 == counter)
    {
        return SOPC_STATUS_NOT_SUPPORTED;
    }
    else
    {
        if (atLeastOneItfSuccess)
        {
            return SOPC_STATUS_OK;
        }
        else
        {
            return SOPC_STATUS_NOK;
        }
    }
}

static SOPC_ReturnStatus SOPC_UDP_Socket_AddMembership(int sock,
                                                       const char* interfaceName,
                                                       const SOPC_Socket_AddressInfo* multicast)
{
    if (NULL == multicast || -1 == sock)
    {
        return SOPC_STATUS_INVALID_PARAMETERS;
    }

    // Using interfaceName provided
    if (NULL != interfaceName)
    {
        unsigned int ifindex = if_nametoindex(interfaceName);
        bool ipv4success = false;
        bool ipv6success = false;
        ipv6success = setMembershipOption(sock, multicast, ifindex, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP);
        ipv4success = setMembershipOption(sock, multicast, ifindex, IPPROTO_IP, IP_ADD_MEMBERSHIP);
        if (!ipv6success && SOPC_Socket_AddrInfo_IsIPV6(multicast))
        {
            SOPC_CONSOLE_PRINTF("AddMembership failure (error='%s') on interface for IPv6: %s\n", strerror(errno),
                                interfaceName);
        }
        if (!ipv4success)
        {
            SOPC_CONSOLE_PRINTF("AddMembership failure (error='%s') on interface for IPv4: %s\n", strerror(errno),
                                interfaceName);
        }
        if (ipv4success || ipv6success)
        {
            return SOPC_STATUS_OK;
        }
        else
        {
            return SOPC_STATUS_NOK;
        }
    }

    return applyMembershipToAllInterfaces(sock, multicast, IP_ADD_MEMBERSHIP, IPV6_ADD_MEMBERSHIP);
}

static SOPC_ReturnStatus SOPC_UDP_Socket_CreateNew(const SOPC_Socket_AddressInfo* addr,
                                                   const char* interfaceName,
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
    SOPC_ReturnStatus status = SOPC_STATUS_INVALID_PARAMETERS;
    const int trueInt = true;
    int setOptStatus = -1;

    socketImpl->sock = socket(addr->addrInfo.ai_family, addr->addrInfo.ai_socktype, addr->addrInfo.ai_protocol);

    if (-1 == socketImpl->sock)
    {
        status = SOPC_STATUS_NOK;
    }
    else
    {
        status = SOPC_STATUS_OK;
    }

    if (SOPC_STATUS_OK == status && setReuseAddr)
    {
        setOptStatus = setsockopt(socketImpl->sock, SOL_SOCKET, SO_REUSEADDR, (const void*) &trueInt, sizeof(int));
        if (setOptStatus < 0)
        {
            status = SOPC_STATUS_NOK;
        }
    }

    /*
    // Enforce IPV6 sockets can be used for IPV4 connections (if socket is IPV6)
    if (setOptStatus != -1 && addr->addrin.sin_family == AF_INET6)
    {
        const int falseInt = false;
        setOptStatus = setsockopt(*sock, IPPROTO_IPV6, IPV6_V6ONLY, (const void*) &falseInt, sizeof(int));
        if (setOptStatus < 0)
        {
            status = SOPC_STATUS_NOK;
        }
    }
    */

    if (SOPC_STATUS_OK == status && setNonBlocking)
    {
        S2OPC_TEMP_FAILURE_RETRY(setOptStatus, fcntl(socketImpl->sock, F_SETFL, O_NONBLOCK));

        if (setOptStatus < 0)
        {
            status = SOPC_STATUS_NOK;
        }
    }

    if (SOPC_STATUS_OK == status && NULL != interfaceName)
    {
        setOptStatus =
            setsockopt(socketImpl->sock, SOL_SOCKET, SO_BINDTODEVICE, interfaceName, (socklen_t) strlen(interfaceName));
        if (setOptStatus < 0)
        {
            status = SOPC_STATUS_NOK;
        }
    }

    if (SOPC_STATUS_OK == status)
    {
        *sock = socketImpl;
    }
    else
    {
        SOPC_Socket_Close(&socketImpl);
    }

    return status;
}

SOPC_ReturnStatus SOPC_UDP_Socket_CreateToReceive(SOPC_Socket_AddressInfo* listenAddress,
                                                  const char* interfaceName,
                                                  bool setReuseAddr,
                                                  bool setNonBlocking,
                                                  SOPC_Socket* sock)
{
    SOPC_ReturnStatus status =
        SOPC_UDP_Socket_CreateNew(listenAddress, interfaceName, setReuseAddr, setNonBlocking, sock);
    if (SOPC_STATUS_OK == status)
    {
        SOPC_ASSERT(NULL != sock);
        int res = bind((*sock)->sock, listenAddress->addrInfo.ai_addr, listenAddress->addrInfo.ai_addrlen);
        if (res == -1)
        {
            SOPC_UDP_Socket_Close(sock);
            status = SOPC_STATUS_NOK;
        }
        else
        {
            bool isMC = false;
            if (listenAddress->addrInfo.ai_family == AF_INET)
            {
                // IPV4: first address byte indicates if this is a multicast address
                struct sockaddr_in* sAddr = (struct sockaddr_in*) get_ai_addr(listenAddress);
                const uint32_t ip = htonl(sAddr->sin_addr.s_addr);
                isMC = ((ip >> 28) & 0xF) == 0xE; // Multicast mask on 4 first bytes;
            }

            // If address is multicast, then add membership
            if (isMC)
            {
                status = SOPC_UDP_Socket_AddMembership((*sock)->sock, interfaceName, listenAddress);
            }
        }
    }
    return status;
}

SOPC_ReturnStatus SOPC_UDP_Socket_CreateToSend(SOPC_Socket_AddressInfo* destAddress,
                                               const char* interfaceName,
                                               bool setNonBlocking,
                                               SOPC_Socket* sock)
{
    return SOPC_UDP_Socket_CreateNew(destAddress, interfaceName, false, setNonBlocking, sock);
}

SOPC_ReturnStatus SOPC_UDP_Socket_SendTo(SOPC_Socket sock, const SOPC_Socket_AddressInfo* destAddr, SOPC_Buffer* buffer)
{
    if (SOPC_INVALID_SOCKET == sock || NULL == destAddr || NULL == buffer || buffer->position != 0)
    {
        return SOPC_STATUS_INVALID_PARAMETERS;
    }

    ssize_t res =
        sendto(sock->sock, buffer->data, buffer->length, 0, destAddr->addrInfo.ai_addr, destAddr->addrInfo.ai_addrlen);

    if (-1 == res || (uint32_t) res != buffer->length)
    {
        return SOPC_STATUS_NOK;
    }

    return SOPC_STATUS_OK;
}

SOPC_ReturnStatus SOPC_UDP_Socket_ReceiveFrom(SOPC_Socket sock, SOPC_Buffer* buffer)
{
    if (SOPC_INVALID_SOCKET == sock || NULL == buffer)
    {
        return SOPC_STATUS_INVALID_PARAMETERS;
    }

    struct sockaddr_in si_client;
    socklen_t slen = sizeof(si_client);

    ssize_t recv_len = 0;
    S2OPC_TEMP_FAILURE_RETRY(
        recv_len, recvfrom(sock->sock, buffer->data, buffer->current_size, 0, (struct sockaddr*) &si_client, &slen));

    if (recv_len == -1)
    {
        return SOPC_STATUS_NOK;
    }

    buffer->length = (uint32_t) recv_len;
    if (buffer->length == buffer->current_size)
    {
        // The message could be incomplete
        return SOPC_STATUS_OUT_OF_MEMORY;
    }

    return SOPC_STATUS_OK;
}

void SOPC_UDP_Socket_Close(SOPC_Socket* sock)
{
    // Linux does not need to drop membership explicitly in case of MC socket.
    SOPC_Socket_Close(sock);
}
