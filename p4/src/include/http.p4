#ifndef __HTTP_P4__
#define __HTTP_P4__

#include "headers.p4"
#include "defines.p4"

control http_ingress(
        inout headers_t hdr,
        inout local_metadata_t local_metadata,
        inout standard_metadata_t standard_metadata) {

    // register<bit<32>>(1) ip_register;
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action close_tcp() {
        hdr.ipv4.len = hdr.ipv4.len - local_metadata.app_len;
        truncate(standard_metadata.packet_length - (bit<32>)local_metadata.app_len);
        local_metadata.app_len = 0;
        local_metadata.tcp_len = hdr.ipv4.len - (bit<16>)hdr.ipv4.ihl * 4;
        // FIN flag
        hdr.tcp.ctrl = hdr.tcp.ctrl | 1;
        hdr.tcp.ctrl = hdr.tcp.ctrl & 6w0b110111;
    }

    apply {
        if (local_metadata.http_header_content_length > 0) {
            if (local_metadata.http_body_len > 0 &&
                    (bit<32>)local_metadata.http_body_len * 20 < local_metadata.http_header_content_length) {
                // drop();
                // ip_register.write(0, hdr.ipv4.src_addr);
                close_tcp();
                local_metadata.update_tcp_checksum = true;
            }
        }
        // bit<32> block_ip;
        // ip_register.read(block_ip, 0);
        // if (hdr.ipv4.src_addr == block_ip) {
        //     drop();
        // }
    }
}

#endif
