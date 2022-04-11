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

#ifndef __CUSTOM_HEADERS__
#define __CUSTOM_HEADERS__
struct headers_t {
    packet_out_header_t packet_out;
    packet_in_header_t packet_in;
    ethernet_t ethernet;
    ipv4_t ipv4;
    tcp_t tcp;
    udp_t udp;
    tcp_options_t tcp_options;
    char_header_t[4096] http_buffer;
}

struct local_metadata_t {
    bit<16>       l4_src_port;
    bit<16>       l4_dst_port;
    next_hop_id_t next_hop_id;
    @field_list(1)
    bool          update_tcp_checksum;
    @field_list(1)
    bit<16>       app_len;
    bit<1> flag_http_req_get;
    bit<1> flag_http_req_post;
    bit<1> flag_http_res;
    bit<16> http_body_len;
    @field_list(1)
    bit<16> tcp_len;
    bit<32> http_header_content_length;
    @field_list(1)
    bool bad_http_flag;
}

#endif
