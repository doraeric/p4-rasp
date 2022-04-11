#ifndef __HTTP_P4__
#define __HTTP_P4__

#include "headers.p4"
#include "defines.p4"
#include "int_definitions.p4"
// BMV2_V1MODEL_INSTANCE_TYPE_INGRESS_CLONE
// onos/pipelines/basic/src/main/resources/include/int_definitions.p4
// onos/pipelines/fabric/impl/src/main/resources/include/define.p4

control http_ingress(
        inout headers_t hdr,
        inout local_metadata_t local_metadata,
        inout standard_metadata_t standard_metadata) {

    // register<bit<32>>(1) ip_register;
    action drop() {
        mark_to_drop(standard_metadata);
    }

    apply {
        if (local_metadata.http_header_content_length > 0) {
            if (local_metadata.http_body_len > 0 &&
                    (bit<32>)local_metadata.http_body_len * 20 < local_metadata.http_header_content_length) {
                // drop();
                // ip_register.write(0, hdr.ipv4.src_addr);
                local_metadata.bad_http_flag = true;
                // clone_preserving_field_list(in CloneType type, in bit<32> session, bit<8> index)
                // session: map session to clone port from controll plane
                // index: copy local_matadata fields marked with @field_list(1) to cloned packets
                clone_preserving_field_list(CloneType.I2E, (bit<32>)standard_metadata.ingress_port, 1);
            }
        }
        // bit<32> block_ip;
        // ip_register.read(block_ip, 0);
        // if (hdr.ipv4.src_addr == block_ip) {
        //     drop();
        // }
    }
}

control http_egress(
        inout headers_t hdr,
        inout local_metadata_t local_metadata,
        inout standard_metadata_t standard_metadata) {
    action close_tcp() {
        hdr.ipv4.len = hdr.ipv4.len - local_metadata.app_len;
        truncate(standard_metadata.packet_length - (bit<32>)local_metadata.app_len);
        local_metadata.app_len = 0;
        local_metadata.tcp_len = hdr.ipv4.len - (bit<16>)hdr.ipv4.ihl * 4;
        // FIN flag
        // hdr.tcp.ctrl = hdr.tcp.ctrl | 1;
        // hdr.tcp.ctrl = hdr.tcp.ctrl & 6w0b110111;
        // RST flag
        hdr.tcp.ctrl = 6w0b000100;
    }

    apply {
        if (local_metadata.bad_http_flag) {
            close_tcp();
            local_metadata.update_tcp_checksum = true;
            if (standard_metadata.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_INGRESS_CLONE) {
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
