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

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <inttypes.h>
#include <time.h>
#include <unistd.h>

#include <linux/errqueue.h>
#include <linux/types.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "p_sopc_udp_sockets_custom.h"
#include <s2opc/common/sopc_assert.h>
#include <s2opc/common/sopc_common_constants.h>
#include <s2opc/common/sopc_macros.h>

/* Omit from static analysis due to use of memcpy into CMSG_DATA(controlMessage)
   which is wrongly detected as doing an overflow */
#ifndef __clang_analyzer__

#ifndef SO_EE_ORIGIN_TXTIME
#define SO_EE_ORIGIN_TXTIME 6
#define SO_EE_CODE_TXTIME_INVALID_PARAM 1
#define SO_EE_CODE_TXTIME_MISSED 2
#endif

/* Additional References:
https://github.com/torvalds/linux/blob/master/include/uapi/linux/net_tstamp.h
https://man7.org/linux/man-pages/man8/tc-etf.8.html
https://lwn.net/Articles/748879/
*/

SOPC_ReturnStatus SOPC_UDP_SO_TXTIME_Socket_Option(const char* interface, SOPC_Socket sock, uint32_t soPriority)
{
    /* This sample TSN application uses strict txtime with SO_PRIORITY 3 mode by
       default.
       There are two modes of transmission(strict and deadline).
       Strict mode - Packet will be dequeued at exact launch time.
       Deadline mode - Packet will be dequeued anytime within the timeslice.
       In future, the flags for enable/disable the modes will be user defined via
       XML.
    */
    SOPC_Socket_txtime txtimeSock;
    // To enable deadline mode, assign "SOF_TXTIME_DEADLINE_MODE" flag by
    // replacing 0.
    // Replace offload to deadline_mode in tc qdisc command - Refer QDisc man
    // page.
    static uint16_t useDeadlineMode = 0;
    // To enable packet drop report, assign "SOF_TXTIME_REPORT_ERRORS" flag by
    // replacing 0 - debugging purpose.
    static uint16_t receiveErrors = 0;

    // In near future, the SO_PRIORITY will be user defined via XML.
    // If soPriority is changed, then it has to mapped to TC in the Qdisc command.
    // Refer Qdisc man page.

    const int trueInt = true;
    int setOptStatus = -1;
    int res = 0;
    struct ifreq nwInterface;

    if (SOPC_INVALID_SOCKET == sock || NULL == interface)
    {
        return SOPC_STATUS_INVALID_PARAMETERS;
    }

    setOptStatus = setsockopt(sock->sock, SOL_SOCKET, SO_PRIORITY, &soPriority, sizeof(soPriority));
    if (setOptStatus < 0)
    {
        return SOPC_STATUS_NOK;
    }

    setOptStatus = setsockopt(sock->sock, SOL_SOCKET, SO_REUSEADDR, (const void*) &trueInt, sizeof(int));
    if (setOptStatus < 0)
    {
        return SOPC_STATUS_NOK;
    }

    // Configure network devices to use socket FD
    memset(&nwInterface, 0, sizeof(nwInterface));
    strncpy(nwInterface.ifr_name, interface, sizeof(nwInterface.ifr_name) - 1);
    S2OPC_TEMP_FAILURE_RETRY(res, ioctl(sock->sock, SIOCGIFINDEX, &nwInterface));
    if (res < 0)
    {
        return SOPC_STATUS_NOK;
    }

    // Bind the socket to ethernet hardware
    setOptStatus = setsockopt(sock->sock, SOL_SOCKET, SO_BINDTODEVICE, (void*) &nwInterface, sizeof(nwInterface));
    if (setOptStatus < 0)
    {
        SOPC_CONSOLE_PRINTF("Interface selection failed\n");
        return SOPC_STATUS_NOK;
    }

    memset(&txtimeSock, 0, sizeof(txtimeSock));
    // Reference clock for time based transmission - hardware time is set in TAI
    // coordinate
    txtimeSock.clockid = CLOCKID;
    // Only strict_txtime mode - so disabled deadline mode.
    // Error queue - disabled by default. Packet loss/drop will be identified
    // using TCPDUMP.
    txtimeSock.flags = (useDeadlineMode | receiveErrors);
    // SO_TXTIME - Socket option allows application to add transmission time
    setOptStatus = setsockopt(sock->sock, SOL_SOCKET, SO_TXTIME, &txtimeSock, sizeof(txtimeSock));
    if (setOptStatus < 0)
    {
        S2OPC_TEMP_FAILURE_RETRY(res, close(sock->sock));
        return SOPC_STATUS_NOK;
    }

    return SOPC_STATUS_OK;
}

SOPC_ReturnStatus SOPC_TX_UDP_send(SOPC_Socket sock,
                                   void* txBuffer,
                                   uint32_t txBuffLen,
                                   uint64_t txtime,
                                   const char* node,
                                   const char* service)
{
    // CMSG - control message used to send additional header
    char control[CMSG_SPACE(sizeof(txtime))] = {0};
    ssize_t res;
    struct cmsghdr* controlMessage;
    struct msghdr message;
    struct iovec fdIOBuffer;
    static struct in_addr mcastAddr;
    struct sockaddr_in sockIpAddr;

    if (SOPC_INVALID_SOCKET == sock)
    {
        return SOPC_STATUS_INVALID_PARAMETERS;
    }
    if (!inet_aton(node, &mcastAddr))
    {
        return SOPC_STATUS_NOK;
    }

    memset(&sockIpAddr, 0, sizeof(sockIpAddr));
    sockIpAddr.sin_family = AF_INET;
    sockIpAddr.sin_addr = mcastAddr;
    long int port = strtol(service, NULL, 10);
    SOPC_ASSERT(port <= UINT16_MAX);
    sockIpAddr.sin_port = htons((uint16_t) port);

    // Describes the buffer information to be sent
    fdIOBuffer.iov_base = txBuffer;
    fdIOBuffer.iov_len = (size_t) txBuffLen;

    memset(&message, 0, sizeof(message));
    message.msg_name = &sockIpAddr;
    message.msg_namelen = sizeof(sockIpAddr);
    // I/O buffer with length
    message.msg_iov = &fdIOBuffer;
    message.msg_iovlen = 1;
    // Contains additional information of packet
    message.msg_control = control;
    message.msg_controllen = sizeof(control);

    controlMessage = CMSG_FIRSTHDR(&message);
    // Manipulate the socket level
    controlMessage->cmsg_level = SOL_SOCKET;
    // Control-message header type
    controlMessage->cmsg_type = SCM_TXTIME;
    // Txtime length
    controlMessage->cmsg_len = CMSG_LEN(sizeof(uint64_t));
    memcpy(CMSG_DATA(controlMessage), &txtime, sizeof(uint64_t));
    // Send message on socket
    S2OPC_TEMP_FAILURE_RETRY(res, sendmsg(sock->sock, &message, 0));

    if ((uint32_t) res != txBuffLen || res < 1)
    {
        return SOPC_STATUS_NOK;
    }

    return SOPC_STATUS_OK;
}

SOPC_ReturnStatus SOPC_TX_UDP_Socket_Error_Queue(SOPC_Socket sock)
{
    if (SOPC_INVALID_SOCKET == sock)
    {
        return SOPC_STATUS_INVALID_PARAMETERS;
    }

    uint8_t messageControl[CMSG_SPACE(sizeof(struct sock_extended_err))];
    unsigned char errBuffer[sizeof(250)];
    struct sock_extended_err* sockErr;
    struct cmsghdr* controlMessage;
    uint64_t timestamp = 0;
    SOPC_ReturnStatus status = SOPC_STATUS_INVALID_PARAMETERS;

    struct iovec fdIOBuffer = {.iov_base = errBuffer, .iov_len = sizeof(errBuffer)};
    struct msghdr message = {.msg_iov = &fdIOBuffer,
                             .msg_iovlen = 1,
                             .msg_control = messageControl,
                             .msg_controllen = sizeof(messageControl)};

    int res = 0;
    S2OPC_TEMP_FAILURE_RETRY(res, recvmsg(sock->sock, &message, MSG_ERRQUEUE));

    if (res == -1)
    {
        SOPC_CONSOLE_PRINTF("Receive message failed from error queue\n");
        return SOPC_STATUS_NOK;
    }

    controlMessage = CMSG_FIRSTHDR(&message);
    while (controlMessage != NULL && status != SOPC_STATUS_NOK)
    {
        sockErr = (void*) CMSG_DATA(controlMessage);
        /* Only TXTIME error is handled for TSN activity.
           if the noticed error is not TXTIME error, then next messge header is
           traverses and loop breaks with reporting unknown error.
         */
        if (sockErr->ee_origin == SO_EE_ORIGIN_TXTIME)
        {
            /* Packets are dropped on enqueue() because of qdisc (or)
               on dequeue() - if the system misses their deadline.
               Those are reported as errors.
             */
            timestamp = ((uint64_t) sockErr->ee_data << 32) + sockErr->ee_info;
            switch (sockErr->ee_code)
            {
            case SO_EE_CODE_TXTIME_INVALID_PARAM:
            case SO_EE_CODE_TXTIME_MISSED:
                fprintf(stderr, "Packet with timestamp %" PRIu64 " dropped\n", timestamp);
                status = SOPC_STATUS_NOK;
                break;
            default:
                status = SOPC_STATUS_NOK;
                break;
            }
        }
        else
        {
            controlMessage = CMSG_NXTHDR(&message, controlMessage);
            status = SOPC_STATUS_NOK;
            SOPC_CONSOLE_PRINTF("Unknown error\n");
        }
    }

    return status;
}

#endif // not __clang_analyzer__
