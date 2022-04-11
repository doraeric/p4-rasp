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

#ifndef __PARSERS__
#define __PARSERS__

#include "headers.p4"
#include "defines.p4"

parser parser_impl(
        packet_in packet,
        out headers_t hdr,
        inout local_metadata_t local_metadata,
        inout standard_metadata_t standard_metadata) {

    bit<8> http_header_key_len = 0;
    bit<4> http_header_key_state = 0;
    state start {
        local_metadata.flag_http_req_get = 0;
        local_metadata.flag_http_req_post = 0;
        local_metadata.flag_http_res = 0;
        local_metadata.bad_http_flag = false;
        transition select(standard_metadata.ingress_port) {
            CPU_PORT: parse_packet_out;
            default: parse_ethernet;
        }
    }

    state parse_packet_out {
        packet.extract(hdr.packet_out);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETH_TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        local_metadata.l4_src_port = hdr.tcp.src_port;
        local_metadata.l4_dst_port = hdr.tcp.dst_port;
        local_metadata.tcp_len = hdr.ipv4.len - (bit<16>)hdr.ipv4.ihl * 4;
        local_metadata.update_tcp_checksum = false;
        verify(hdr.tcp.data_offset >=5, error.TcpDataOffsetTooSmall);
        transition select(hdr.tcp.data_offset){
            5: parse_app_len;
            default: parse_tcp_options;
        }
    }

    state parse_tcp_options {
        bit<10> len = ((bit<10>)(hdr.tcp.data_offset - 5) * 4 * 8);
        packet.extract(hdr.tcp_options, (bit<32>)len);
        transition parse_app_len;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        local_metadata.l4_src_port = hdr.udp.src_port;
        local_metadata.l4_dst_port = hdr.udp.dst_port;
        transition accept;
    }

    state parse_app_len {
        local_metadata.app_len =
            hdr.ipv4.len - (bit<16>)(hdr.ipv4.ihl + hdr.tcp.data_offset) * 4;
        transition select(local_metadata.app_len) {
            0: accept;
            default: parse_app;
        }
    }

    state parse_app {
        transition select(hdr.tcp.dst_port) {
            80: parse_http_req;
            default: parse_app_2;
        }
    }

    state parse_app_2 {
        transition select(hdr.tcp.src_port) {
            80: parse_http_res;
            default: accept;
        }
    }

    state parse_http_req {
        transition select(packet.lookahead<bit<32>>()) {
            TYPE_HTTP_REQ_GET: parse_http_req_get;
            TYPE_HTTP_REQ_POST: parse_http_req_post;
            default: accept;
        }
    }

    state parse_http_req_post {
        local_metadata.flag_http_req_post = 1;
        transition parse_http_start_line_start;
    }
    state parse_http_req_get {
        local_metadata.flag_http_req_get = 1;
        transition parse_http_start_line_start;
    }

    state parse_http_start_line_start {
        local_metadata.http_body_len = 0;
        transition parse_http_start_line ;
    }
    state parse_http_start_line {
        packet.extract(hdr.http_buffer.next);
        transition select(packet.lookahead<bit<16>>()) {
            TYPE_HTTP_CRLF: parse_http_headers;
            default: parse_http_start_line;
        }
    }

    state parse_http_headers {
        transition parse_http_crlf_goto_header_line_start;
    }

    // extract start-line crlf and goto header line start
    state parse_http_crlf_goto_header_line_start {
        packet.extract(hdr.http_buffer.next);
        packet.extract(hdr.http_buffer.next);
        transition parse_http_header_line_start;
    }

    state parse_http_header_line_start {
        http_header_key_len = 0;
        http_header_key_state = 0;
        transition select(packet.lookahead<bit<16>>()) {
            // starts with crlf means it's the end crlf of headers
            // http body is followed by this crlf
            TYPE_HTTP_CRLF: parse_http_headers_stop;
            default: parse_http_header_key;
        }
    }

    state parse_http_headers_stop {
        packet.extract(hdr.http_buffer.next);
        packet.extract(hdr.http_buffer.next);
        local_metadata.http_body_len = local_metadata.app_len - (bit<16>)hdr.http_buffer.lastIndex;
        transition accept;
    }

    state parse_http_header_key {
        transition select(packet.lookahead<bit<16>>()) {
            TYPE_HTTP_CRLF: parse_http_header_line_start;
            default: parse_http_header_key_2;
        }
    }

    state parse_http_header_key_2 {
        packet.extract(hdr.http_buffer.next);
        http_header_key_len = http_header_key_len + 1;
        // last char == ':'
        if (hdr.http_buffer.last.char == 0x3a) {
            http_header_key_state = 1;
            http_header_key_len = http_header_key_len - 1;
            if (http_header_key_len == 14
                    && hdr.http_buffer[hdr.http_buffer.lastIndex - 1].char == 0x68
                    && hdr.http_buffer[hdr.http_buffer.lastIndex - 2].char == 0x74
                    && hdr.http_buffer[hdr.http_buffer.lastIndex - 3].char == 0x67
                    && hdr.http_buffer[hdr.http_buffer.lastIndex - 4].char == 0x6e
                    && hdr.http_buffer[hdr.http_buffer.lastIndex - 5].char == 0x65
                    && hdr.http_buffer[hdr.http_buffer.lastIndex - 6].char == 0x4c
                    && hdr.http_buffer[hdr.http_buffer.lastIndex - 7].char == 0x2d
                    && hdr.http_buffer[hdr.http_buffer.lastIndex - 8].char == 0x74
                    && hdr.http_buffer[hdr.http_buffer.lastIndex - 9].char == 0x6e
                    && hdr.http_buffer[hdr.http_buffer.lastIndex - 10].char == 0x65
                    && hdr.http_buffer[hdr.http_buffer.lastIndex - 11].char == 0x74
                    && hdr.http_buffer[hdr.http_buffer.lastIndex - 12].char == 0x6e
                    && hdr.http_buffer[hdr.http_buffer.lastIndex - 13].char == 0x6f
                    && hdr.http_buffer[hdr.http_buffer.lastIndex - 14].char == 0x43
                    ) {
                http_header_key_state = 2;
                local_metadata.http_header_content_length = 0;
            }
        }
        transition select(http_header_key_state) {
            0: parse_http_header_key;
            default: parse_http_header_value;
        }
    }

    state parse_http_header_value {
        transition select(packet.lookahead<bit<16>>()) {
            TYPE_HTTP_CRLF: parse_http_crlf_goto_header_line_start;
            default: parse_http_header_value_2;
        }
    }

    state parse_http_header_value_2 {
        packet.extract(hdr.http_buffer.next);
        transition select(http_header_key_state) {
            2: parse_http_header_content_length_2;
            default: parse_http_header_value;
        }
    }

    state parse_http_header_content_length_2 {
        if (hdr.http_buffer.last.char >= 0x30 && hdr.http_buffer.last.char <= 0x39) {
            local_metadata.http_header_content_length =
                local_metadata.http_header_content_length * 10 + (bit<32>)(hdr.http_buffer.last.char - 0x30);
        }
        transition parse_http_header_value;
    }

    state parse_http_res {
        transition select(packet.lookahead<bit<32>>()) {
            TYPE_HTTP_RES: parse_http_res_2;
            default: accept;
        }
    }

    state parse_http_res_2 {
        local_metadata.flag_http_res = 1;
        transition accept;
    }
}

control deparser(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.packet_in);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.tcp_options);
        packet.emit(hdr.udp);
        packet.emit(hdr.http_buffer);
    }
}

#endif
