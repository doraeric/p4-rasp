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

#ifndef __TABLE0__
#define __TABLE0__

#include "headers.p4"
#include "defines.p4"

control Acl(
        inout headers_t hdr,
        inout local_metadata_t meta,
        inout standard_metadata_t stdmeta) {

    direct_counter(CounterType.packets_and_bytes) acl_counter;

    action set_next_hop_id(next_hop_id_t next_hop_id) {
        meta.next_hop_id = next_hop_id;
        acl_counter.count();
    }

    action send_to_cpu() {
        stdmeta.egress_spec = CPU_PORT;
        acl_counter.count();
    }

    action set_egress_port(port_t port) {
        stdmeta.egress_spec = port;
        acl_counter.count();
    }

    action drop() {
        mark_to_drop(stdmeta);
        meta.skip_next = true;
        acl_counter.count();
    }

    action nop_acl() {
        acl_counter.count();
    }

    table acl {
        key = {
            stdmeta.ingress_port    : ternary @name("ig_port");
            hdr.ethernet.src_addr   : ternary @name("eth_src");
            hdr.ethernet.dst_addr   : ternary @name("eth_dst");
            hdr.ethernet.ether_type : ternary @name("eth_type");
            hdr.ipv4.src_addr       : ternary @name("ipv4_src");
            hdr.ipv4.dst_addr       : ternary @name("ipv4_dst");
            hdr.ipv4.protocol       : ternary @name("ip_proto");
            hdr.tcp.ctrl            : ternary @name("tcp_flag");
            meta.l4_src_port        : ternary @name("l4_sport");
            meta.l4_dst_port        : ternary @name("l4_dport");
        }
        actions = {
            set_egress_port;
            send_to_cpu;
            set_next_hop_id;
            drop;
            nop_acl;
        }
        const default_action = nop_acl();
        size = ACL_TABLE_SIZE;
        counters = acl_counter;
    }

    apply {
        acl.apply();
     }
}

#endif
