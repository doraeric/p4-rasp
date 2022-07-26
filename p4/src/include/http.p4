#ifndef __HTTP_P4__
#define __HTTP_P4__

#include "headers.p4"
#include "defines.p4"
#include "int_definitions.p4"
// BMV2_V1MODEL_INSTANCE_TYPE_INGRESS_CLONE
// onos/pipelines/basic/src/main/resources/include/int_definitions.p4
// onos/pipelines/fabric/impl/src/main/resources/include/define.p4

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
    bit<16> http_body_len;
    bit<16> app_len;
}

struct registers_t {
    bit<10> index;
    bit<4> max_short_get;
    bit<4> max_short_other;
    bit<4> max_long_other;
    bit<4> n_short_get;
    bit<4> n_short_other;
    bit<4> n_long_other;
}

struct new_ip_t {
    bit<32> src_addr;
    bit<32> dst_addr;
}

struct fragment_t {
    bit<32> src_addr;
    bit<32> dst_addr;
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> app_len;
    bit<32> content_length;
    bit<1> is_req_start;
    bit<1> is_get;
    bit<1> has_2_crlf;
    bit<1> is_long;
}

struct http_res_t {
    bit<32> src_addr;
    bit<32> dst_addr;
    bit<16> src_port;
    bit<16> dst_port;
    bit<8> status_code;
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
    bool is_long;

    action drop() {
        mark_to_drop(stdmeta);
    }

    action report_conn_match() {
        digest<conn_match_t>(1, {
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr,
            hdr.tcp.src_port,
            hdr.tcp.dst_port,
            meta.register_index,
            meta.is_http_req_start ? 1w1: 0,
            meta.http_method == Method.GET ? 1w1 : 0,
            meta.has_2_crlf ? 1w1: 0,
            meta.http_header_content_length,
            meta.http_body_len,
            meta.app_len
        });
    }

    action report_registers() {
        bit<32> index = (bit<32>)hdr.reg_read.index;
        bit<4> v1;
        bit<4> v2;
        bit<4> v3;
        bit<4> v4;
        bit<4> v5;
        bit<4> v6;
        max_short_gets.read(v1, index);
        max_short_others.read(v2, index);
        max_long_others.read(v3, index);
        n_short_gets.read(v4, index);
        n_short_others.read(v5, index);
        n_long_others.read(v6, index);
        digest<registers_t>(1, {
            hdr.reg_read.index,
            v1, v2, v3, v4, v5, v6
        });
    }

    action report_new_ip() {
        digest<new_ip_t>(1, {
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr
        });
    }

    action report_fragment() {
        digest<fragment_t>(1, {
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr,
            hdr.tcp.src_port,
            hdr.tcp.dst_port,
            meta.app_len,
            meta.http_header_content_length,
            meta.is_http_req_start ? 1w1: 0,
            meta.http_method == Method.GET ? 1w1 : 0,
            meta.has_2_crlf ? 1w1: 0,
            is_long ? 1w1: 0
        });
    }

    action report_http_res() {
        digest<http_res_t>(1, {
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr,
            hdr.tcp.src_port,
            hdr.tcp.dst_port,
            (bit<8>)meta.http_status
        });
    }

    action add_meta(bit<10> index) {
        meta.register_index = index;
    }

    action mark_bad_http_and_clone() {
        meta.bad_http = true;
        // clone_preserving_field_list(in CloneType type, in bit<32> session, bit<8> index)
        // session: map session to clone port from controll plane
        // index: copy local_matadata fields marked with @field_list(1) to cloned packets
        clone_preserving_field_list(CloneType.I2E, (bit<32>)stdmeta.ingress_port, 1);
    }

// action can't conditional read/write registers, so use macro
#define update_register(update_index) if (hdr.reg_cnt.count > update_index) { \
    index = hdr.reg_update[update_index].index; \
    reg_id2 = hdr.reg_update[update_index].id2; \
    op = hdr.reg_update[update_index].op; \
    update = (bit<4>)hdr.reg_update[update_index].value; \
    if (reg_id2 == 0) { \
        n_short_gets.read(value, index); \
        n_short_gets.write(index, op == CHAR_PLUS ? \
            (value + update) : (value - update)); \
    } else if (reg_id2 == 1) { \
        n_short_others.read(value, index); \
        n_short_others.write(index, op == CHAR_PLUS ? \
            (value + update) : (value - update)); \
    } else if (reg_id2 == 2) { \
        n_long_others.read(value, index); \
        n_long_others.write(index, op == CHAR_PLUS ? \
            (value + update) : (value - update)); \
    } else if (reg_id2 == 3) { \
        max_short_gets.read(value, index); \
        max_short_gets.write(index, op == CHAR_PLUS ? \
            (value + update) : (value - update)); \
    } else if (reg_id2 == 4) { \
        max_short_others.read(value, index); \
        max_short_others.write(index, op == CHAR_PLUS ? \
            (value + update) : (value - update)); \
    } else if (reg_id2 == 5) { \
        max_long_others.read(value, index); \
        max_long_others.write(index, op == CHAR_PLUS ? \
            (value + update) : (value - update)); \
    } \
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
                    if (hdr.tcp.dst_port == 80) {
                        // For debug
                        // report_conn_match();
                        if (meta.is_http_req_start) {
                            bool do_report_fragment = false;
                            if ((bit<32>)meta.http_body_len ==
                                meta.http_header_content_length && meta.has_2_crlf
                            ) {
                                // new complete req
                                return;
                            } else {
                                // new fragmented req
                                bit<32> index = (bit<32>)meta.register_index;
                                is_long = (bit<32>)meta.http_body_len * 20
                                    < meta.http_header_content_length;
#ifndef CCSA
                                bit<4> max_conn;
                                bit<4> n_conn;
                                if (meta.http_method == Method.GET) {
                                    // fragmented short GET
                                    max_short_gets.read(max_conn, index);
                                    n_short_gets.read(n_conn, index);
                                    if (n_conn >= max_conn) {
                                        mark_bad_http_and_clone();
                                    } else {
                                        n_short_gets.write(index, n_conn + 1);
                                        do_report_fragment = true;
                                    }
                                } else if (!is_long) {
                                    // fragmented short non-GET
                                    max_short_others.read(max_conn, index);
                                    n_short_others.read(n_conn, index);
                                    if (n_conn >= max_conn) {
                                        mark_bad_http_and_clone();
                                    } else {
                                        n_short_others.write(index, n_conn + 1);
                                        do_report_fragment = true;
                                    }
                                } else {
                                    // fragmented long non-GET
                                    max_long_others.read(max_conn, index);
                                    n_long_others.read(n_conn, index);
                                    if (n_conn >= max_conn) {
                                        mark_bad_http_and_clone();
                                    } else {
                                        n_long_others.write(index, n_conn + 1);
                                        do_report_fragment = true;
                                    }
                                }
                                if (do_report_fragment) {
                                    // calling digest in different if condition
                                    // delays sending digest
                                    report_fragment();
                                }
#endif // ndef CCSA
                            }
                        }
#ifdef CCSA
                        report_fragment();
#endif // def CCSA
                    } else if (hdr.tcp.src_port == 80) {
                        if (meta.is_http_res_start) {
                            report_http_res();
                        }
                    }
                }
            } else {
                // non ipv4 packet will always miss without header validation
                // for this program, tcp header is only valid when it's ipv4
                // when it's not a ipv4 packet, digest send ipv4 info that it
                // sent last time (?) or just hdr keeps old info?
                report_new_ip();
            }
            // if (meta.http_header_content_length > 0) {
            //     if (meta.http_body_len > 0 &&
            //             (bit<32>)meta.http_body_len * 20 < meta.http_header_content_length) {
            //         // drop();
            //         // ip_register.write(0, hdr.ipv4.src_addr);
            //         mark_bad_http_and_clone();
            //     }
            // }
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
            } else if (hdr.instruction.id == 2) {
                report_registers();
            } else if (hdr.instruction.id == 3) {
                bit<32> index;
                bit<4> value;
                bit<8> reg_id2;
                bit<8> op;
                bit<4> update;
                update_register(0)
                update_register(1)
                update_register(2)
                update_register(3)
                update_register(4)
                update_register(5)
                update_register(6)
                update_register(7)
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
