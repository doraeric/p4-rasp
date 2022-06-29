#ifndef __HTTP_P4__
#define __HTTP_P4__

#include "headers.p4"
#include "defines.p4"
#include "int_definitions.p4"
// BMV2_V1MODEL_INSTANCE_TYPE_INGRESS_CLONE
// onos/pipelines/basic/src/main/resources/include/int_definitions.p4
// onos/pipelines/fabric/impl/src/main/resources/include/define.p4

struct new_ip_t {
    bit<32> src_addr;
    bit<32> dst_addr;
}

struct conn_match_t {
    bit<32> src_addr;
    bit<32> dst_addr;
    bit<16> src_port;
    bit<16> dst_port;
    bit<10> index;
    bit<1> is_http_req_start;
    bit<1> is_get;
    bit<1> has_2_crlf;
    bit<32> content_length;
}

control http_ingress(
        inout headers_t hdr,
        inout local_metadata_t meta,
        inout standard_metadata_t stdmeta) {

    register<bit<4>>(1024) max_short_gets;
    register<bit<4>>(1024) max_short_others;
    register<bit<4>>(1024) max_long_others;
    register<bit<4>>(1024) n_short_gets;
    register<bit<4>>(1024) n_short_others;
    register<bit<4>>(1024) n_long_others;

    action drop() {
        mark_to_drop(stdmeta);
    }

    action report_new_ip() {
        digest<new_ip_t>(1, {
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr
        });
    }

    action add_meta(bit<10> index) {
        meta.register_index = index;
    }

    table ip_pair {
        key = {
            hdr.ipv4.src_addr: exact;
            hdr.ipv4.dst_addr: exact;
        }
        actions = {
            add_meta;
            NoAction;
        }
    }

    apply {
        if (hdr.tcp.isValid()) {
            // The switch only sends one digest out per packet, be careful
            if (ip_pair.apply().hit) {
                if (meta.app_len > 0) {
                    // For debug
                    if (hdr.tcp.dst_port == 80) {
                        digest<conn_match_t>(1, {
                            hdr.ipv4.src_addr,
                            hdr.ipv4.dst_addr,
                            hdr.tcp.src_port,
                            hdr.tcp.dst_port,
                            meta.register_index,
                            meta.is_http_req_start ? 1w1: 0,
                            meta.http_method == Method.GET ? 1w1 : 0,
                            meta.has_2_crlf ? 1w1: 0,
                            meta.http_header_content_length
                        });
                    }
                    bit<32> index = (bit<32>)meta.register_index;
                    // bit<4> max_short_get;
                    // max_short_gets.read(max_short_get, index);
                }
            } else {
                // non ipv4 packet will always miss without header validation
                // for this program, tcp header is only valid when it's ipv4
                // when it's not a ipv4 packet, digest send ipv4 info that it
                // sent last time (?) or just hdr keeps old info?
                report_new_ip();
            }
            if (meta.http_header_content_length > 0) {
                if (meta.http_body_len > 0 &&
                        (bit<32>)meta.http_body_len * 20 < meta.http_header_content_length) {
                    // drop();
                    // ip_register.write(0, hdr.ipv4.src_addr);
                    meta.bad_http = true;
                    // clone_preserving_field_list(in CloneType type, in bit<32> session, bit<8> index)
                    // session: map session to clone port from controll plane
                    // index: copy local_matadata fields marked with @field_list(1) to cloned packets
                    clone_preserving_field_list(CloneType.I2E, (bit<32>)stdmeta.ingress_port, 1);
                }
            }
        }
        // bit<32> block_ip;
        // ip_register.read(block_ip, 0);
        // if (hdr.ipv4.src_addr == block_ip) {
        //     drop();
        // }
        if (hdr.instruction.isValid()) {
            if (hdr.instruction.id == 1) {
                bit<32> index = (bit<32>)hdr.reg_init.index;
                max_short_gets.write(index, hdr.reg_init.max_short_get);
                max_short_others.write(index, hdr.reg_init.max_short_other);
                max_long_others.write(index, hdr.reg_init.max_long_other);
                n_short_gets.write(index, 0);
                n_short_others.write(index, 0);
                n_long_others.write(index, 0);
            }
        }
    }
}

control http_egress(
        inout headers_t hdr,
        inout local_metadata_t meta,
        inout standard_metadata_t stdmeta) {
    action close_tcp() {
        hdr.ipv4.len = hdr.ipv4.len - meta.app_len;
        truncate(stdmeta.packet_length - (bit<32>)meta.app_len);
        meta.app_len = 0;
        meta.tcp_len = hdr.ipv4.len - (bit<16>)hdr.ipv4.ihl * 4;
        // FIN flag
        // hdr.tcp.ctrl = hdr.tcp.ctrl | 1;
        // hdr.tcp.ctrl = hdr.tcp.ctrl & 6w0b110111;
        // RST flag
        hdr.tcp.ctrl = 6w0b000100;
    }

    apply {
        if (meta.bad_http) {
            close_tcp();
            meta.update_tcp_checksum = true;
            if (stdmeta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_INGRESS_CLONE) {
                bit<48> tmp_mac = hdr.ethernet.src_addr;
                hdr.ethernet.src_addr = hdr.ethernet.src_addr;
                hdr.ethernet.dst_addr = tmp_mac;
                bit<32> tmp_ip = hdr.ipv4.src_addr;
                hdr.ipv4.src_addr = hdr.ipv4.dst_addr;
                hdr.ipv4.dst_addr = tmp_ip;
                bit<16> tmp_tcp = hdr.tcp.src_port;
                hdr.tcp.src_port = hdr.tcp.dst_port;
                hdr.tcp.dst_port = tmp_tcp;
                hdr.tcp.seq_no = hdr.tcp.ack_no;
                hdr.tcp.ack_no = 0;
            }
        }
    }
}

#endif
