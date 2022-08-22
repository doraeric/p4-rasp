#!/usr/bin/env python3
import argparse
from dataclasses import dataclass, field
from hexdump import hexdump
import json
import logging
import logging.handlers
import os
from pathlib import Path
import readline # noqa
# import time
import threading

import IPython

from gen_full_netcfg import set_default_net_config
from utils import p4sh_helper
from utils import protocol
from utils.p4sh_helper import P4RTClient
from utils.threading import EventTimer, EventThread

import importlib

P4INFO = os.getenv('P4INFO', '../../p4/build-ccsa/p4info.txt')
P4BIN = os.getenv('P4BIN', '../../p4/build-ccsa/bmv2.json')
os.environ['P4INFO'] = P4INFO
os.environ['P4BIN'] = P4BIN

p4_control = importlib.import_module('00_p4_control')
setup_all_switches = p4_control.setup_all_switches
setup_one_switch = p4_control.setup_one_switch
to_tcp_key = p4_control.to_tcp_key
req_register_read = p4_control.req_register_read
reg_update = p4_control.reg_update
enable_digest = p4_control.enable_digest
setup_logging = p4_control.setup_logging

log = logging.getLogger('p4_control')
default_max_conns = [8, 8, 4]
default_min_conns = [2, 2, 1]


@dataclass
class IpPairInfo:
    # the order is: short_get, short_other, long_other
    index: int
    client: P4RTClient
    members_ip: list
    trust_counter: int = 100
    blocked: bool = False


@dataclass
class AppContext:
    net_config: dict
    ip_counter: int = 0
    ip_pair_info: dict[tuple, IpPairInfo] = field(default_factory=dict)
    conns: dict = field(default_factory=dict)
    num_socket_use: int = 0


_app_context = AppContext(None)
p4_control._app_context = _app_context


def acl_del(client: P4RTClient, ipv4_src: bytes, ipv4_dst: bytes) -> None:
    te = client.TableEntry('ingress.acl.acl')(action='ingress.acl.drop')
    te.priority = 1
    te.match["eth_type"] = protocol.ETH_TYPE_IPV4
    te.match["ip_proto"] = protocol.IP_PROTO_TCP
    te.match["ipv4_src"] = ipv4_src
    te.match["ipv4_dst"] = ipv4_dst
    te.delete()


def acl_add_drop(client: P4RTClient, ipv4_src: bytes, ipv4_dst: bytes) -> None:
    te = client.TableEntry('ingress.acl.acl')(action='ingress.acl.drop')
    te.priority = 1
    te.match["eth_type"] = protocol.ETH_TYPE_IPV4
    te.match["ip_proto"] = protocol.IP_PROTO_TCP
    te.match["ipv4_src"] = ipv4_src
    te.match["ipv4_dst"] = ipv4_dst
    te.insert()


def handle_new_ip(packet, client: P4RTClient):
    ip_pair_info = _app_context.ip_pair_info
    members = [i.bitstring for i in packet.data[0].struct.members]
    ips = members[:2]
    ip_str = ['.'.join([str(i) for i in ip]) for ip in ips]
    key = tuple(sorted(ips))
    if key in ip_pair_info:
        return
    index = _app_context.ip_counter
    _app_context.ip_counter += 1
    ip_pair_info[key] = IpPairInfo(index=index, client=client, members_ip=ips)
    # bidirectional
    for ip1, ip2 in [ips, ips[::-1]]:
        te = client.TableEntry('ingress.http_ingress.ip_pair')(
            action='add_meta')
        te.match["hdr.ipv4.src_addr"] = ip1
        te.match["hdr.ipv4.dst_addr"] = ip2
        te.action['index'] = str(index)
        te.insert()
    log.info('> ip_pair[%s] = %s <-> %s', index, ip_str[0], ip_str[1])


def safe_block(ip_key, desc=''):
    info = _app_context.ip_pair_info[ip_key]
    if info.blocked:
        return False
    info.blocked = True
    ips = info.members_ip
    acl_add_drop(info.client, *ips)
    log.info('> block %s %s.%s.%s.%s -> %s.%s.%s.%s', desc, *ips[0], *ips[1])
    return True


def safe_unblock(ip_key, reset=True, desc=''):
    info = _app_context.ip_pair_info[ip_key]
    if not info.blocked:
        return False
    ips = info.members_ip
    acl_del(info.client, *ips)
    if reset:
        info.trust_counter = 100
    info.blocked = False
    if desc == 'short':
        log.info(
            '> unblock %s %s.%s.%s.%s -> %s.%s.%s.%s, credit=%s',
            desc, *ips[0], *ips[1], info.trust_counter)
    else:
        log.info('> unblock %s %s -> %s', desc, ips[0], ips[1])
    return True


def handle_fragment(
    packet, msg: dict, client: P4RTClient, app_exit: threading.Event
):
    members = [i.bitstring for i in packet.data[0].struct.members]
    ip_key = tuple(sorted(members[:2]))
    for k in ['src_addr', 'dst_addr', 'src_port', 'dst_port']:
        msg.pop(k)
    for k in ['is_req_start', 'is_get', 'has_2_crlf', 'is_long']:
        msg[k] = msg[k] == 1
    ip_pair_info = _app_context.ip_pair_info[ip_key]
    ip_pair_info.trust_counter -= 1
    if ip_pair_info.trust_counter <= 100 * 0 and not ip_pair_info.blocked:
        # block ip
        do_block = safe_block(ip_key, 'long')
        if do_block:
            EventTimer(300, safe_unblock, app_exit, args=(ip_key,), kwargs={
                'desc': 'long'}).start()
    tcp_key = to_tcp_key(members[:4])
    if _app_context.conns.get(tcp_key) is None:
        _app_context.conns[tcp_key] = True
        _app_context.num_socket_use += 1
        free_socket_check(app_exit)


def handle_http_res(packet, msg: dict, client: P4RTClient):
    members = [i.bitstring for i in packet.data[0].struct.members]
    tcp_key = to_tcp_key(members[:4])
    if tcp_key not in _app_context.conns:
        return
    _app_context.num_socket_use -= 1
    del _app_context.conns[tcp_key]


def free_socket_check(app_exit: threading.Event):
    if (100 - _app_context.num_socket_use) / 100 < 0.2:
        ban = False
        for k, v in _app_context.ip_pair_info.items():
            if v.trust_counter < 0.5*100:
                ban = True
                if safe_block(k, 'short'):
                    EventTimer(60.0, safe_unblock, app_exit, args=(
                        k, False, 'short')).start()
        if not ban:
            log.info('Not ban')


def clock(pill: threading.Event):
    while True:
        # now = time.time()
        pill.wait(60)
        if pill.is_set():
            break


def setup_switch_listen(switch: str, app_exit: threading.Event) -> P4RTClient:
    client = setup_one_switch(switch)
    p4i = client.p4i

    # Insert digest
    client.enable_all_digest()

    # Listening
    print('Listening on controller for switch "{}"'.format(switch))
    stream_client = p4sh_helper.StreamClient(client, app_exit)

    # callbacks
    @stream_client.on('packet')
    def packet_in_handler(packet):
        print('PacketIn.payload')
        hexdump(packet.payload)
        ingress_port = int.from_bytes(packet.metadata[0].value, 'big')
        print(f'PacketIn.metadata[0]: ingress_port={ingress_port}')

    @stream_client.on('digest')
    def digest_handler(packet):
        name = p4i.get_digest_name(packet.digest_id)
        # log.info('< Receive digest %s #%s len=%s',
        #          name, packet.list_id, len(packet.data))
        if len(packet.data) == 1:
            names = p4i.get_member_names(packet.digest_id)
            members = [i.bitstring for i in packet.data[0].struct.members]
            msg = {k: int.from_bytes(v, 'big') if not k.endswith('_addr')
                   else ('.'.join(str(i) for i in v) if len(v) == 4
                         else ':'.join(f'{i:02x}' for i in v))
                   for k, v in zip(names, members)}
            # log.info('< %s', msg)
        else:
            log.debug(packet)
        if name == 'new_ip_t':
            handle_new_ip(packet, client)
        elif name == 'fragment_t':
            handle_fragment(packet, msg, client, app_exit)
        elif name == 'http_res_t':
            if msg['status_code'] == 4 or msg['status_code'] == 5:
                log.info('< %s', msg)
            handle_http_res(packet, msg, client)

    stream_client.recv_bg()
    return client


def cmd_each(args):
    """Setup each switch and sniff.

    Args:
        args.switch: Switch names. Both `-s 1 2` and `-s s1 s2` are acceptable.
    """
    switches = args.switch
    switches = ['s' + i if not i.startswith('s') else i for i in switches]
    if args.all:
        net_config = _app_context.net_config
        for s in net_config['devices_by_name'].keys():
            if s in switches:
                continue
            client = setup_one_switch(s)
            client.tear_down()
    if not args.listen:
        for switch in switches:
            client = setup_one_switch(switch)
            client.tear_down()
    else:
        app_exit = threading.Event()
        time_thread = EventThread(clock, app_exit)
        time_thread.start()
        clients = [setup_switch_listen(i, app_exit) for i in switches]

        # Open IPython shell
        IPython.embed(colors="neutral")
        app_exit.set()
        for client in clients:
            client.tear_down()
    return


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
    pser.add_argument('--topo', default='topos/netcfg.json',
                      help='Path to net config json')
    subparsers = pser.add_subparsers(
        required=True, help='Setup rules for all switches or one switch')
    pser_all = subparsers.add_parser('all')
    pser_all.set_defaults(func=lambda args: setup_all_switches())
    pser_each = subparsers.add_parser('each')
    pser_each.add_argument(
        '-s', '--switch', required=True, nargs='+',
        help='The switch name in mininet')
    pser_each.add_argument(
        '-l', '--listen', action='store_true',
        help='Listen on controller for packet in')
    pser_each.add_argument(
        '-a', '--all', action='store_true',
        help='Add rules for all switches, but listening only works for '
        'specified switch')
    pser_each.set_defaults(func=cmd_each)
    args = pser.parse_args()

    setup_logging((log, logging.getLogger('p4sh_helper')), args)
    print(f'P4INFO={Path(P4INFO).resolve()}')
    print(f'P4BIN={Path(P4BIN).resolve()}')
    topo_path = Path(__file__, '..', args.topo).resolve()
    net_config = json.load(topo_path.open())
    set_default_net_config(net_config)
    _app_context.net_config = net_config
    args.func(args)


if __name__ == '__main__':
    main()
