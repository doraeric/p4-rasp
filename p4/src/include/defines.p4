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
// RES_SEP "HTTP/1.1 "
const bit<72> TYPE_HTTP_RES_SEP = 0x485454502f312e3120;
const bit<16> TYPE_HTTP_CRLF = 0x0d0a;
const bit<8> CHAR_SPACE = 0x20;
const bit<8> CHAR_0 = 0x30;
const bit<8> CHAR_CR = 0x0d;
const bit<8> CHAR_LF = 0x0a;
const bit<8> CHAR_COLON = 0x3a;
const bit<8> CHAR_DASH = 0x2d;
const bit<8> CHAR_MINUS = 0x2d;
const bit<8> CHAR_PLUS = 0x2b;

// alphabet
const bit<8> CHAR_A = 0x41;
const bit<8> CHAR_B = 0x42;
const bit<8> CHAR_C = 0x43;
const bit<8> CHAR_D = 0x44;
const bit<8> CHAR_E = 0x45;
const bit<8> CHAR_F = 0x46;
const bit<8> CHAR_G = 0x47;
const bit<8> CHAR_H = 0x48;
const bit<8> CHAR_I = 0x49;
const bit<8> CHAR_J = 0x4a;
const bit<8> CHAR_K = 0x4b;
const bit<8> CHAR_L = 0x4c;
const bit<8> CHAR_M = 0x4d;
const bit<8> CHAR_N = 0x4e;
const bit<8> CHAR_O = 0x4f;
const bit<8> CHAR_P = 0x50;
const bit<8> CHAR_Q = 0x51;
const bit<8> CHAR_R = 0x52;
const bit<8> CHAR_S = 0x53;
const bit<8> CHAR_T = 0x54;
const bit<8> CHAR_U = 0x55;
const bit<8> CHAR_V = 0x56;
const bit<8> CHAR_W = 0x57;
const bit<8> CHAR_X = 0x58;
const bit<8> CHAR_Y = 0x59;
const bit<8> CHAR_Z = 0x5a;

const bit<8> CHAR_a = 0x61;
const bit<8> CHAR_b = 0x62;
const bit<8> CHAR_c = 0x63;
const bit<8> CHAR_d = 0x64;
const bit<8> CHAR_e = 0x65;
const bit<8> CHAR_f = 0x66;
const bit<8> CHAR_g = 0x67;
const bit<8> CHAR_h = 0x68;
const bit<8> CHAR_i = 0x69;
const bit<8> CHAR_j = 0x6a;
const bit<8> CHAR_k = 0x6b;
const bit<8> CHAR_l = 0x6c;
const bit<8> CHAR_m = 0x6d;
const bit<8> CHAR_n = 0x6e;
const bit<8> CHAR_o = 0x6f;
const bit<8> CHAR_p = 0x70;
const bit<8> CHAR_q = 0x71;
const bit<8> CHAR_r = 0x72;
const bit<8> CHAR_s = 0x73;
const bit<8> CHAR_t = 0x74;
const bit<8> CHAR_u = 0x75;
const bit<8> CHAR_v = 0x76;
const bit<8> CHAR_w = 0x77;
const bit<8> CHAR_x = 0x78;
const bit<8> CHAR_y = 0x79;
const bit<8> CHAR_z = 0x7a;

enum bit<8> Method {
    GET  = 1,
    POST = 2,
    HEAD = 3,
    PUT  = 4,
    DELETE = 5,
    CONNECT = 6,
    OPTIONS = 7,
    TRACE = 8,
    PATCH = 9
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

#define ACL_TABLE_SIZE 1024

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
