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

#ifndef SOPC_P_UDP_SOCKETS_CUSTOM_H_
#define SOPC_P_UDP_SOCKETS_CUSTOM_H_

#include <inttypes.h>

#include "p_sopc_sockets.h"

#include <s2opc/common/sopc_enums.h>
#include <s2opc/common/sopc_raw_sockets.h>

#ifndef SO_TXTIME
#define SO_TXTIME 61
#define SCM_TXTIME SO_TXTIME
#endif

#define ONE_SEC 1000 * 1000 * 1000
#define CLOCKID CLOCK_TAI

/*
 * SO_TXTIME gets a struct sock_txtime with flags being an integer bit
 * field comprised of these values.
 */
enum txtime_flags
{
    SOF_TXTIME_DEADLINE_MODE = (1 << 0),
    SOF_TXTIME_REPORT_ERRORS = (1 << 1),

    SOF_TXTIME_FLAGS_LAST = SOF_TXTIME_REPORT_ERRORS,
    SOF_TXTIME_FLAGS_MASK = (SOF_TXTIME_FLAGS_LAST - 1) | SOF_TXTIME_FLAGS_LAST
};

/**
 *  \brief The API for SO_TXTIME is the below struct and enum, which will be
 *  provided by uapi/linux/net_tstamp.h in the near future.
 */
typedef struct
{
    clockid_t clockid;
    uint16_t flags;
} SOPC_Socket_txtime;

/**
 *  \brief Function to add new socket option and bind interface
 *
 *  \param interface   Interface selection - HW timestamp enabled NIC
 *  \param sock        Value pointed is set with the newly created socket
 *  \param soPriority Set priority of packets sent by this socket
 *  \return            SOPC_STATUS_OK if operation succeeded,
 * SOPC_STATUS_INVALID_PARAMETERS
 *  or SOPC_STATUS_NOK otherwise.
 */
SOPC_ReturnStatus SOPC_UDP_SO_TXTIME_Socket_Option(const char* interface, SOPC_Socket sock, uint32_t soPriority);

/**
 *  \brief Send data through the UDP socket to given IP address and port
 *
 *  \param sock        Value pointed is set with the newly created socket
 *  \param txBuffer    The buffer containing data to be sent.
 *  \param txBuffLen   The network message buffer length
 *  \param txtime      The frame transmission timestamp
 *  \param node        An IPv4 or IPv6 address.
 *  \param service     The param service  The port to use
 *
 *  \return            SOPC_STATUS_OK if operation succeeded,
 * SOPC_STATUS_INVALID_PARAMETERS
 *  or SOPC_STATUS_NOK otherwise.
 */
SOPC_ReturnStatus SOPC_TX_UDP_send(SOPC_Socket sock,
                                   void* txBuffer,
                                   uint32_t txBuffLen,
                                   uint64_t txtime,
                                   const char* node,
                                   const char* service);

/**
 *  \brief Function for socket error queue
 *
 *  \param sock      Socket file descriptor value
 *
 *  \return            SOPC_STATUS_OK if operation succeeded,
 * SOPC_STATUS_INVALID_PARAMETERS
 *  or SOPC_STATUS_NOK otherwise.
 */
SOPC_ReturnStatus SOPC_TX_UDP_Socket_Error_Queue(SOPC_Socket sock);

#endif /* SOPC_P_UDP_SOCKETS_CUSTOM_H_ */
