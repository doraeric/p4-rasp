#ifndef __NEXT__
#define __NEXT__

#include "headers.p4"
#include "defines.p4"

struct timestamp_digest_t {
    bit<48> ingress;
    bit<32> ipv4;
}

control next(
        inout headers_t hdr,
        inout local_metadata_t local_metadata,
        inout standard_metadata_t standard_metadata) {

    action arp_reply(mac_t target_addr) {
        hdr.ethernet.dst_addr = hdr.ethernet.src_addr;
        hdr.ethernet.src_addr = target_addr;
        hdr.arp.opcode = 2;
        hdr.arp.hw_dst_addr = hdr.arp.hw_src_addr;
        hdr.arp.hw_src_addr = target_addr;
        bit<32> tmp = hdr.arp.proto_dst_addr;
        hdr.arp.proto_dst_addr = hdr.arp.proto_src_addr;
        hdr.arp.proto_src_addr = tmp;
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    table arp_table {
        key = {
            hdr.arp.opcode: exact;
            hdr.arp.proto_dst_addr: exact;
        }
        actions = {
            arp_reply;
            NoAction;
        }
        size = 256;
        default_action = NoAction();
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(mac_t dst_addr, port_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr = dst_addr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action forward_to_cpu() {
        digest<timestamp_digest_t>(1, {standard_metadata.ingress_global_timestamp, hdr.ipv4.src_addr});
        standard_metadata.egress_spec = CPU_PORT;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dst_addr: lpm;
        }
        actions = {
            ipv4_forward;
            forward_to_cpu;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        if (hdr.arp.isValid()) {
            arp_table.apply();
        }
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
    }
}

#endif
