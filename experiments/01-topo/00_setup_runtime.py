#!/usr/bin/env python3
import os

import p4runtime_sh.shell as sh

sh.setup(
    device_id=1,
    grpc_addr='localhost:50001',
    election_id=(0, 1), # (high, low)
    config=sh.FwdPipeConfig(
        os.getenv('P4INFO', '../../p4/build/p4info.txt'),
        os.getenv('P4BIN', '../../p4/build/bmv2.json')),
)
te = sh.TableEntry('ingress.next.ipv4_lpm')(action='ingress.next.ipv4_forward')
te.match["hdr.ipv4.dst_addr"] = "10.0.1.0/24"
te.action['dst_addr'] = '00:00:00:00:00:01'
te.action["port"] = "1"
te.insert()

te = sh.TableEntry('ingress.next.ipv4_lpm')(action='ingress.next.ipv4_forward')
te.match["hdr.ipv4.dst_addr"] = "10.0.2.0/24"
te.action['dst_addr'] = '08:00:00:00:02:00'
te.action["port"] = "2"
te.insert()

sh.teardown()

sh.setup(
    device_id=1,
    grpc_addr='localhost:50002',
    election_id=(0, 1), # (high, low)
    config=sh.FwdPipeConfig(
        os.getenv('P4INFO', '../../p4/build/p4info.txt'),
        os.getenv('P4BIN', '../../p4/build/bmv2.json')),
)

te = sh.TableEntry('ingress.next.ipv4_lpm')(action='ingress.next.ipv4_forward')
te.match["hdr.ipv4.dst_addr"] = "10.0.1.0/24"
te.action['dst_addr'] = '08:00:00:00:01:00'
te.action["port"] = "1"
te.insert()

te = sh.TableEntry('ingress.next.ipv4_lpm')(action='ingress.next.ipv4_forward')
te.match["hdr.ipv4.dst_addr"] = "10.0.2.0/24"
te.action['dst_addr'] = '00:00:00:00:00:02'
te.action["port"] = "2"
te.insert()

sh.teardown()
