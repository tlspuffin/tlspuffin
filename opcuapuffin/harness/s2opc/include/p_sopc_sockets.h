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

#ifndef SOPC_P_SOCKETS_H_
#define SOPC_P_SOCKETS_H_

#include <netdb.h>
#include <sys/select.h>

/**
 *  \brief Socket base type
 */
struct SOPC_Socket_Impl
{
    int sock;
};

/**
 *  \brief Socket addressing information for listening or connecting operation type
 *  \note Internal treatment use the fact it is the first field as property
 */
struct SOPC_Socket_AddressInfo
{
    struct addrinfo addrInfo;
};

/**
 *  \brief Socket address information on a connected socket
 *  \note Internal treatment use the fact it is the first field as property
 *
 */
struct SOPC_Socket_Address
{
    struct addrinfo address;
};

/**
 *  \brief Set of sockets type
 */
struct SOPC_SocketSet
{
    int fdmax;  /**< max of the set */
    fd_set set; /**< set */
};

#endif /* SOPC_P_SOCKETS_H_ */
