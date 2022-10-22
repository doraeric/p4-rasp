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
    instruction_t instruction;
    pout_setup_t pout_setup;
    reg_init_t reg_init;
    reg_read_t reg_read;
    reg_update_cnt_t reg_cnt;
    reg_update_t[8] reg_update;
    ethernet_t ethernet;
    arp_t arp;
    ipv4_t ipv4;
    tcp_t tcp;
    udp_t udp;
    tcp_options_t tcp_options;
    char_header_t[200] http_buffer;
}

struct local_metadata_t {
    bit<16>       l4_src_port;
    bit<16>       l4_dst_port;
    next_hop_id_t next_hop_id;
    bool skip_next; // skip control pipelines
    @field_list(1)
    bool          update_tcp_checksum;
    @field_list(1)
    bit<16>       app_len; // http length in bytes
    bit<16> http_body_len;
    @field_list(1)
    bit<16> tcp_len;
    bit<32> http_header_content_length;
    @field_list(1)
    bool bad_http;
    @field_list(1)
    bool is_http_req_start;
    bit<8> http_method;
    bool is_http_res_start;
    bit<4> http_status;
    bit<4> crlf_start_count;
    bool has_2_crlf;
    bit<10> register_index;
}

#endif
