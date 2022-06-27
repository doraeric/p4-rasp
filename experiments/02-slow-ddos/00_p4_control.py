#!/usr/bin/env python3
import argparse
from dataclasses import dataclass
from hexdump import hexdump
import json
import logging
import logging.handlers
import os
from pathlib import Path
import readline # noqa

import p4runtime_sh.shell as sh

from gen_full_netcfg import set_default_net_config
from utils import p4sh_helper

log = logging.getLogger('p4_control')
# Do not propagate to root log
log.propagate = False
formatter = logging.Formatter(
    ('%(asctime)s.%(msecs)03d: %(levelname).1s/%(name)s: '
     '%(filename)s:%(lineno)d: %(message)s'),
    datefmt='%H:%M:%S',
)


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
    log.info('===  Configure switch %s  ===', switch)
    net_config = _app_context.net_config
    switch_info = net_config['devices_by_name'][switch]
    sh.setup(
        device_id=1,
        grpc_addr=f'localhost:5000{switch[-1]}',
        election_id=(0, 1),  # (high, low)
        config=sh.FwdPipeConfig(P4INFO, P4BIN),
    )
    # routerIpv4: 10.0.0.1/24
    router_ipv4_net = switch_info['segmentrouting']['routerIpv4']
    router_ipv4_addr = router_ipv4_net.split('/')[0]
    # arp
    target_addr = switch_info['segmentrouting']['routerMac']
    log.info('insert arp %s -> %s', router_ipv4_addr, target_addr)
    te = p4sh_helper.TableEntry('ingress.next.arp_table')(
        action='ingress.next.arp_reply')
    te.match["hdr.arp.opcode"] = "1"
    te.match["hdr.arp.proto_dst_addr"] = router_ipv4_addr
    te.action['target_addr'] = target_addr
    te.insert()
    # default action for no matching packet in subnet: drop
    log.info('drop no matching packet in %s', router_ipv4_net)
    te = p4sh_helper.TableEntry('ingress.next.ipv4_lpm')(
        action='ingress.next.drop')
    te.match["hdr.ipv4.dst_addr"] = router_ipv4_net
    te.insert()
    # forward known destination
    for link in net_config['links_from'][switch]:
        dst_type = link['to']['type']
        dst_name = link['to']['name']
        if dst_type == 'host':
            dst_info = net_config['hosts_by_name'][dst_name]['basic']
            dst_ip = dst_info['ips'][0].split('/')[0]
            log.info('forward dst=%s/32 to host', dst_ip)
            log.debug(
                'dst_addr=%s, port=%s', dst_info['mac'], link['from']['port'])
            te = p4sh_helper.TableEntry('ingress.next.ipv4_lpm')(
                action='ingress.next.ipv4_forward')
            te.match["hdr.ipv4.dst_addr"] = dst_ip + '/32'
            te.action['dst_addr'] = dst_info['mac']
            te.action["port"] = str(link['from']['port'])
            te.insert()
        elif dst_type == 'device':
            dst_info = (net_config['devices_by_name'][dst_name]
                        ['segmentrouting'])
            dst_ip = dst_info['routerIpv4']
            log.info('forward dst=%s to device', dst_ip)
            te = p4sh_helper.TableEntry('ingress.next.ipv4_lpm')(
                action='ingress.next.ipv4_forward')
            te.match["hdr.ipv4.dst_addr"] = dst_ip
            te.action['dst_addr'] = dst_info['routerMac']
            te.action["port"] = str(link['from']['port'])
            te.insert()
    # default gateway, interface or link
    set_gw = False
    for port_info in net_config['ports_by_device'].get(switch, {}).values():
        if not port_info['default_gateway']:
            continue
        port = port_info['port']
        if port_info.get('interfaces') is not None:
            dst_addr = port_info['interfaces'][0]['gw_mac']
        else:
            other = net_config['links_from'][f'device:{switch}/{port}']
            if other['type'] == 'host':
                dst_addr = (net_config['hosts_by_name'][other['name']]
                            ['basic']['mac'])
            else:
                dst_addr = (net_config['devices_by_name'][other['name']]
                            ['segmentrouting']['routerMac'])
        log.info('default gateway: %s', dst_addr)
        te = p4sh_helper.TableEntry('ingress.next.ipv4_lpm')(
            action='ingress.next.ipv4_forward')
        te.action['dst_addr'] = dst_addr
        te.action["port"] = port
        te.insert()
        set_gw = True
        break
    if not set_gw:
        # insert no action as default table entry for consistent behaviour
        log.info('default gateway: no action')
        te = sh.TableEntry('ingress.next.ipv4_lpm')(action='NoAction')
        te.insert()
        set_gw = True
    # clone packet to port
    for i in list(range(1, 4)) + [255]:
        clone_entry = sh.CloneSessionEntry(session_id=i)
        clone_entry.add(egress_port=i)
        clone_entry.insert()


def handle_digest_timestamp(packet):
    members = packet.data[0].struct.members
    ts = int.from_bytes(members[0].bitstring, 'big')
    ip = int.from_bytes(members[1].bitstring, 'big')
    print(f'ingress_global_timestamp = {ts} us, {ts/1000000} s')
    print(f'ipv4 = {ip>>24&0xff}.{ip>>16&0xff}.{ip>>8&0xff}.{ip&0xff}')


def handle_new_conn(packet):
    import random
    members = packet.data[0].struct.members
    te = p4sh_helper.TableEntry('ingress.http_ingress.tcp_conn')(
        action='add_meta')
    te.match["hdr.ipv4.src_addr"] = members[0].bitstring
    te.match["hdr.ipv4.dst_addr"] = members[1].bitstring
    te.match["hdr.tcp.src_port"] = members[2].bitstring
    te.match["hdr.tcp.dst_port"] = members[3].bitstring
    n = random.randint(1, 1023)
    te.action['index'] = str(n)
    te.insert()
    log.info('Random: %s', n)


def handle_conn_match(packet, p4i: p4sh_helper.P4Info):
    names = p4i.get_member_names(packet.digest_id)
    members = packet.data[0].struct.members
    values = [int.from_bytes(i.bitstring, 'big') for i in members]
    message = dict(zip(names, values))
    log.info('conn_match: %s', message)


def handle_digest_debug(packet):
    pass


def enable_digest(p4i: p4sh_helper.P4Info, name: str) -> None:
    update = p4i.DigestEntry(name).as_update()
    sh.client.write_update(update)
    log.info('Enable digest: %s', name)

def cmd_one(args):  # noqa: C901
    """Setup one switch and sniff.

    Args:
        args.switch: Switch name. Both `-s 1` and `-s s1` are acceptable.
    """
    switch = args.switch
    switch = 's' + switch if not switch.startswith('s') else switch
    if args.all:
        net_config = _app_context.net_config
        for s in net_config['devices_by_name'].keys():
            if s == switch:
                continue
            setup_one_switch(s)
            sh.teardown()
    setup_one_switch(switch)
    if args.listen:
        # Change default gateway to controller
        # te = sh.TableEntry('ingress.next.ipv4_lpm')(
        #     action='ingress.next.forward_to_cpu')
        # te.modify()

        # Insert digest
        p4i = p4sh_helper.P4Info.read_txt(P4INFO)
        enable_digest(p4i, 'timestamp_digest_t')
        enable_digest(p4i, 'new_conn_t')
        enable_digest(p4i, 'conn_match_t')
        try:
            update = p4i.DigestEntry('debug_digest_t').as_update()
            sh.client.write_update(update)
        except KeyError:
            log.info('No debug digest in p4')

        # Listening
        print('Listening on controller for switch "{}"'.format(switch))
        stream_client = p4sh_helper.StreamClient(sh.client)

        @stream_client.on('packet')
        def packet_in_handler(packet):
            print('PacketIn.payload')
            hexdump(packet.payload)
            ingress_port = int.from_bytes(packet.metadata[0].value, 'big')
            print(f'PacketIn.metadata[0]: ingress_port={ingress_port}')

        @stream_client.on('digest')
        def digest_handler(packet):
            name = p4i.get_digest_name(packet.digest_id)
            log.info('Receive digest %s #%s len=%s',
                     name, packet.list_id, len(packet.data))
            if len(packet.data) == 1:
                log.debug(packet.data[0])
            else:
                log.debug(packet)
            if name == 'timestamp_digest_t':
                handle_digest_timestamp(packet)
            elif name == 'new_conn_t':
                handle_new_conn(packet)
            elif name == 'debug_digest_t':
                handle_digest_debug(packet)
            elif name == 'conn_match_t':
                handle_conn_match(packet, p4i)

        stream_client.recv_bg()
        while True:
            try:
                cmd = input('> ').lower().strip()
                if cmd == 'exit':
                    break
            except (EOFError, KeyboardInterrupt):
                break
        stream_client.stop()
    sh.teardown()


def setup_logging(args):
    if args.log_level is not None:
        level = logging.getLevelName(args.log_level)
    else:
        level = logging.INFO
    log.setLevel(level)
    if len(args.log) == 0:
        console = logging.StreamHandler()
        console.setFormatter(formatter)
        log.addHandler(console)
    for log_dest in args.log:
        if log_dest.startswith('tcp:'):
            tcp = log_dest.split(':')
            tcp = logging.handlers.SocketHandler(tcp[1], int(tcp[2]))
            # https://blog.csdn.net/mvpboss1004/article/details/54425819
            tcp.makePickle = lambda r: (tcp.format(r) + '\n').encode('utf-8')
            tcp.setFormatter(formatter)
            log.addHandler(tcp)
        elif log_dest.endswith('.log'):
            file_handler = logging.FileHandler(log_dest)
            file_handler.setFormatter(logging.Formatter(
                formatter._fmt, datefmt='%Y-%m-%d %H:%M:%S'))
            log.addHandler(file_handler)
        elif log_dest == 'stdout':
            console = logging.StreamHandler()
            console.setFormatter(formatter)
            log.addHandler(console)


def main():
    pser = argparse.ArgumentParser()
    pser.add_argument('--log', action='append', default=[],
                      help='log to stdout, tcp:<ip>:<port>, or <file.log>')
    # https://stackoverflow.com/questions/14097061
    pser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        help="Set the logging level")
    pser.add_argument(
        '--debug', '-d', action="store_const", const=logging.DEBUG,
        dest='log_level', help="Set the logging level to debug")
    subparsers = pser.add_subparsers(
        required=True, help='Setup rules for all switches or one switch')
    pser_all = subparsers.add_parser('all')
    pser_all.set_defaults(func=lambda args: setup_all_switches())
    pser_one = subparsers.add_parser('one')
    pser_one.add_argument('-s', '--switch', required=True,
                          help='The switch name in mininet')
    pser_one.add_argument('-l', '--listen', action='store_true',
                          help='Listen on controller for packet in')
    pser_one.add_argument(
        '-a', '--all', action='store_true',
        help='Add rules for all switches, but listening only works for '
        'specified switch')
    pser_one.set_defaults(func=cmd_one)
    args = pser.parse_args()

    setup_logging(args)
    print(f'P4INFO={Path(P4INFO).resolve()}')
    print(f'P4BIN={Path(P4BIN).resolve()}')
    net_config = json.load(
        Path(__file__, '..', "netcfg.json").resolve().open())
    set_default_net_config(net_config)
    _app_context.net_config = net_config
    args.func(args)


if __name__ == '__main__':
    main()