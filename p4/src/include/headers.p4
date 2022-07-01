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

#ifndef __HEADERS__
#define __HEADERS__

#include "defines.p4"

@controller_header("packet_in")
header packet_in_header_t {
    bit<9> ingress_port;
    bit<7> _padding;
}

@controller_header("packet_out")
header packet_out_header_t {
    bit<9> egress_port;
    // handler
    // 0: parsing as normal
    // 1: no parsing, forward to egress_port
    // 2: instructions from controller
    bit<2> handler;
    bit<5> _padding;
}

header instruction_t {
    bit<8> id;
}

header reg_init_t {
    bit<2>  _pad;
    bit<10> index;
    bit<4>  max_short_get;
    bit<4>  max_short_other;
    bit<4>  max_long_other;
}

header reg_read_t {
    bit<6>  _pad;
    bit<10> index;
}

header reg_decrease_t {
    bit<2>  _pad;
    bit<10> index;
    bit<4>  http_type;
}

header ethernet_t {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}
const bit<8> ETH_HEADER_LEN = 14;

// https://csie.nqu.edu.tw/smallko/sdn/p4_rtp_h264.htm
header arp_t {
    bit<16> hw_type;
    bit<16> protocol;
    bit<8>  hlen;
    bit<8>  plen;
    bit<16> opcode;
    bit<48> hw_src_addr;
    bit<32> proto_src_addr;
    bit<48> hw_dst_addr;
    bit<32> proto_dst_addr;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<6>  dscp;
    bit<2>  ecn;
    bit<16> len;
    bit<16> identification;
    bit<3>  flags;
    bit<13> frag_offset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}
const bit<8> IPV4_MIN_HEAD_LEN = 20;

header tcp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header tcp_options_t {
    varbit<320> options;
}

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> length_;
    bit<16> checksum;
}
const bit<8> UDP_HEADER_LEN = 8;

header char_header_t {
    bit<8> char;
}

error {
  noAppLayerData,
  TcpDataOffsetTooSmall
}

#endif
