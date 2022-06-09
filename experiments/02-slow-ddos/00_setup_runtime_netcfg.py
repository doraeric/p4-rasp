#!/usr/bin/env python3
import argparse
from dataclasses import dataclass
from hexdump import hexdump
import json
import logging
import os
from pathlib import Path
import readline

import p4runtime_sh.shell as sh

from gen_full_netcfg import set_default_net_config
from utils import p4sh_helper

logging.basicConfig(
        format='%(asctime)s.%(msecs)03d: %(process)d: %(levelname).1s/%(name)s: %(filename)s:%(lineno)d: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        level=logging.INFO)

@dataclass
class AppContext:
    net_config: dict
_app_context = AppContext(None)
P4INFO = os.getenv('P4INFO', '../../p4/build/p4info.txt')
P4BIN = os.getenv('P4BIN', '../../p4/build/bmv2.json')

def setup_all_switches() -> None:
    net_config = _app_context.net_config
    for switch in net_config['devices_by_name'].keys():
        setup_one_switch(switch)
        sh.teardown()

def setup_one_switch(switch: str) -> None:
    net_config = _app_context.net_config
    switch_info = net_config['devices_by_name'][switch]
    sh.setup(
        device_id=1,
        grpc_addr=f'localhost:5000{switch[-1]}',
        election_id=(0, 1), # (high, low)
        config=sh.FwdPipeConfig(P4INFO, P4BIN),
    )
    router_ipv4_net = switch_info['segmentrouting']['routerIpv4'] # 10.0.0.1/24
    router_ipv4_addr = router_ipv4_net.split('/')[0]
    # arp
    logging.info('insert arp')
    te = sh.TableEntry('ingress.next.arp_table')(action='ingress.next.arp_reply')
    te.match["hdr.arp.opcode"] = "1"
    te.match["hdr.arp.proto_dst_addr"] = router_ipv4_addr
    te.action['target_addr'] = switch_info['segmentrouting']['routerMac']
    te.insert()
    # to subnet default: drop
    logging.info('default subnet')
    te = sh.TableEntry('ingress.next.ipv4_lpm')(action='ingress.next.drop')
    te.match["hdr.ipv4.dst_addr"] = router_ipv4_net
    te.insert()
    # forward known destination
    for link in net_config['links_from'][switch]:
        dst_type = link['to']['type']
        dst_name = link['to']['name']
        if dst_type == 'host':
            dst_info = net_config['hosts_by_name'][dst_name]['basic']
            dst_ip = dst_info['ips'][0].split('/')[0]
            logging.info('forward host')
            logging.info('match dst_addr=%s/32', dst_ip)
            logging.info('dst_addr=%s, port=%s', dst_info['mac'], link['from']['port'])
            te = sh.TableEntry('ingress.next.ipv4_lpm')(action='ingress.next.ipv4_forward')
            te.match["hdr.ipv4.dst_addr"] = dst_ip + '/32'
            te.action['dst_addr'] = dst_info['mac']
            te.action["port"] = str(link['from']['port'])
            te.insert()
        elif dst_type == 'device':
            dst_info = net_config['devices_by_name'][dst_name]['segmentrouting']
            dst_ip = dst_info['routerIpv4']
            logging.info('forward device')
            te = sh.TableEntry('ingress.next.ipv4_lpm')(action='ingress.next.ipv4_forward')
            te.match["hdr.ipv4.dst_addr"] = dst_ip
            te.action['dst_addr'] = dst_info['routerMac']
            te.action["port"] = str(link['from']['port'])
            te.insert()
    # default gateway, interface or link
    set_gw = False
    for port_info in net_config['ports_by_device'].get(switch, {}).values():
        if not port_info['default_gateway']: continue
        port = port_info['port']
        if port_info.get('interfaces') is not None:
            dst_addr = port_info['interfaces'][0]['gw_mac']
        else:
            other = net_config['links_from'][f'device:{switch}/{port}']
            if other['type'] == 'host':
                dst_addr = net_config['hosts_by_name'][other['name']]['basic']['mac']
            else:
                dst_addr = net_config['devices_by_name'][other['name']]['segmentrouting']['routerMac']
        logging.info('default gateway')
        te = sh.TableEntry('ingress.next.ipv4_lpm')(action='ingress.next.ipv4_forward')
        te.action['dst_addr'] = dst_addr
        te.action["port"] = port
        te.insert()
        set_gw = True
        break
    if not set_gw:
        # insert no action as default table entry for consistent behaviour
        logging.info('default gateway')
        te = sh.TableEntry('ingress.next.ipv4_lpm')(action='NoAction')
        te.insert()
        set_gw = True
    # clone packet to port
    for i in list(range(1, 4)) + [255]:
        clone_entry = sh.CloneSessionEntry(session_id=i)
        clone_entry.add(egress_port=i)
        clone_entry.insert()

def cmd_one(args):
    """Setup one switch and sniff.

    Args:
        args.switch: Switch name. Both `-s 1` and `-s s1` are acceptable.
    """
    switch = args.switch
    if not switch.startswith('s'):
        switch = 's' + switch
    setup_one_switch(switch)
    if args.listen:
        # Change default gateway to controller
        te = sh.TableEntry('ingress.next.ipv4_lpm')(action='ingress.next.forward_to_cpu')
        te.modify()
        # Listening
        print('Listening on controller for switch "{}"'.format(switch))
        packet_in = p4sh_helper.PacketIn(sh.client)
        @packet_in.on_packet_in
        def packet_in_handler(packet):
            print('PacketIn.payload')
            hexdump(packet.payload)
            ingress_port = int.from_bytes(packet.metadata[0].value, 'big')
            print(f'PacketIn.metadata[0]: ingress_port={ingress_port}')
        packet_in.recv_bg()
        while True:
            try:
                cmd = input('> ').lower().strip()
                if cmd == 'exit':
                    break
            except:
                break
        packet_in.stop()
    sh.teardown()

def main():
    pser = argparse.ArgumentParser()
    # pser.add_argument('mode', choices=['all', 'one'], default='all', help='Set rules for all switch or one switch')
    subparsers = pser.add_subparsers(required=True, help='Setup rules for all switches or one switch')
    pser_all = subparsers.add_parser('all')
    pser_all.set_defaults(func=lambda args: setup_all_switches())
    pser_one = subparsers.add_parser('one')
    pser_one.add_argument('-s', '--switch', required=True, help='The switch name in mininet')
    pser_one.add_argument('-l', '--listen', action='store_true', help='Listen on controller for packet in')
    pser_one.set_defaults(func=cmd_one)
    args = pser.parse_args()
    print(f'P4INFO={Path(P4INFO).resolve()}')
    print(f'P4BIN={Path(P4BIN).resolve()}')
    net_config = json.load(Path(__file__, '..', "netcfg.json").resolve().open())
    set_default_net_config(net_config)
    _app_context.net_config = net_config
    args.func(args)

if __name__ == '__main__':
    main()
