/*
 * Copyright 2017-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __DEFINES__
#define __DEFINES__

#define ETH_TYPE_IPV4 0x0800
#define ETH_TYPE_ARP  0x0806
#define IP_PROTO_TCP 8w6
#define IP_PROTO_UDP 8w17
#define IP_VERSION_4 4w4
#define IPV4_IHL_MIN 4w5
#define MAX_PORTS 511

const bit<32> TYPE_HTTP_REQ_GET  = 0x47455420; // "GET "
const bit<32> TYPE_HTTP_REQ_POST = 0x504f5354; // "POST"
const bit<32> TYPE_HTTP_REQ_HEAD = 0x48454144;
const bit<32> TYPE_HTTP_REQ_PUT  = 0x50555420;
const bit<32> TYPE_HTTP_REQ_DELE = 0x44454c45;
const bit<32> TYPE_HTTP_REQ_CONN = 0x434f4e4e;
const bit<32> TYPE_HTTP_REQ_OPTI = 0x4f505449;
const bit<32> TYPE_HTTP_REQ_TRAC = 0x54524143;
const bit<32> TYPE_HTTP_REQ_PATC = 0x50415443;
// REQ_XX_SEP: include separator " /" after method
// "<METHOD> /"
const bit<40> TYPE_HTTP_REQ_GET_SEP  = 0x474554202f;
const bit<40> TYPE_HTTP_REQ_PUT_SEP  = 0x505554202f;
const bit<48> TYPE_HTTP_REQ_POST_SEP = 0x504f5354202f;
const bit<48> TYPE_HTTP_REQ_HEAD_SEP = 0x48454144202f;
const bit<56> TYPE_HTTP_REQ_TRAC_SEP = 0x5452414345202f;
const bit<56> TYPE_HTTP_REQ_PATC_SEP = 0x5041544348202f;
const bit<64> TYPE_HTTP_REQ_DELE_SEP = 0x44454c455445202f;
const bit<72> TYPE_HTTP_REQ_CONN_SEP = 0x434f4e4e454354202f;
const bit<72> TYPE_HTTP_REQ_OPTI_SEP = 0x4f5054494f4e53202f;

const bit<32> TYPE_HTTP_RES = 0x48545450; // "HTTP"
const bit<16> TYPE_HTTP_CRLF = 0x0d0a;

enum bit<8> Method {
    GET  = 0,
    POST = 1,
    HEAD = 2,
    PUT  = 3,
    DELETE = 4,
    CONNECT = 5,
    OPTIONS = 6,
    TRACE = 7,
    PATCH = 8
}

#ifndef _BOOL
#define _BOOL bool
#endif
#ifndef _TRUE
#define _TRUE true
#endif
#ifndef _FALSE
#define _FALSE false
#endif

typedef bit<48> mac_t;
typedef bit<32> ip_address_t;
typedef bit<16> l4_port_t;
typedef bit<9>  port_t;
typedef bit<16> next_hop_id_t;

const port_t CPU_PORT = 255;

typedef bit<8> MeterColor;
const MeterColor MeterColor_GREEN = 8w0;
const MeterColor MeterColor_YELLOW = 8w1;
const MeterColor MeterColor_RED = 8w2;

#endif
