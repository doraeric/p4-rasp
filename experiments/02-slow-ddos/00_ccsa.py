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
import time
import threading

import IPython
import p4runtime_sh.shell as sh

from gen_full_netcfg import set_default_net_config
from utils import p4sh_helper
from utils import protocol
from utils.threading import EventTimer, EventThread

import importlib
p4_control = importlib.import_module('00_p4_control')
setup_all_switches = p4_control.setup_all_switches
setup_one_switch = p4_control.setup_one_switch
to_tcp_key = p4_control.to_tcp_key
req_register_read = p4_control.req_register_read
reg_update = p4_control.reg_update
enable_digest = p4_control.enable_digest

log = logging.getLogger('p4_control')
# Do not propagate to root log
log.propagate = False
formatter = logging.Formatter(
    ('%(asctime)s.%(msecs)03d: %(levelname).1s/%(name)s: '
     '%(filename)s:%(lineno)d: %(message)s'),
    datefmt='%H:%M:%S',
)
default_max_conns = [8, 8, 4]
default_min_conns = [2, 2, 1]


@dataclass
class IpPairInfo:
    # the order is: short_get, short_other, long_other
    index: int
    trust_counter: int = 100
    blocked: bool = False


@dataclass
class AppContext:
    net_config: dict
    ip_counter: int = 0
    ip_pair_info: dict[tuple, IpPairInfo] = field(default_factory=dict)
    conns: dict = field(default_factory=dict)


_app_context = AppContext(None)
p4_control._app_context = _app_context
P4INFO = os.getenv('P4INFO', '../../p4/build/p4info.txt')
P4BIN = os.getenv('P4BIN', '../../p4/build/bmv2.json')


def acl_del(ipv4_src: bytes, ipv4_dst: bytes) -> None:
    te = p4sh_helper.TableEntry('ingress.acl.acl')(action='ingress.acl.drop')
    te.priority = 1
    te.match["eth_type"] = protocol.ETH_TYPE_IPV4
    te.match["ip_proto"] = protocol.IP_PROTO_TCP
    te.match["ipv4_src"] = ipv4_src
    te.match["ipv4_dst"] = ipv4_dst
    te.delete()


def acl_add_drop(ipv4_src: bytes, ipv4_dst: bytes) -> None:
    te = p4sh_helper.TableEntry('ingress.acl.acl')(action='ingress.acl.drop')
    te.priority = 1
    te.match["eth_type"] = protocol.ETH_TYPE_IPV4
    te.match["ip_proto"] = protocol.IP_PROTO_TCP
    te.match["ipv4_src"] = ipv4_src
    te.match["ipv4_dst"] = ipv4_dst
    te.insert()


def handle_new_ip(packet, p4i: p4sh_helper.P4Info):
    ip_pair_info = _app_context.ip_pair_info
    members = [i.bitstring for i in packet.data[0].struct.members]
    ips = members[:2]
    ip_str = ['.'.join([str(i) for i in ip]) for ip in ips]
    key = tuple(sorted(ips))
    if key in ip_pair_info:
        return
    index = _app_context.ip_counter
    _app_context.ip_counter += 1
    ip_pair_info[key] = IpPairInfo(index=index)
    info = ip_pair_info[key]
    # bidirectional
    for ip1, ip2 in [ips, ips[::-1]]:
        te = p4sh_helper.TableEntry('ingress.http_ingress.ip_pair')(
            action='add_meta')
        te.match["hdr.ipv4.src_addr"] = ip1
        te.match["hdr.ipv4.dst_addr"] = ip2
        te.action['index'] = str(index)
        te.insert()
    log.info('> ip_pair[%s] = %s <-> %s', index, ip_str[0], ip_str[1])


def handle_fragment(packet, msg: dict, app_exit: threading.Event):
    members = [i.bitstring for i in packet.data[0].struct.members]
    conns = _app_context.conns
    tcp_key = to_tcp_key(members[:4])
    ip_key = tuple(sorted(members[:2]))
    _msg = msg
    msg = msg.copy()
    for k in ['src_addr', 'dst_addr', 'src_port', 'dst_port']:
        msg.pop(k)
    for k in ['is_req_start', 'is_get', 'has_2_crlf', 'is_long']:
        msg[k] = msg[k] == 1
    ip_pair_info = _app_context.ip_pair_info[ip_key]
    ip_pair_info.trust_counter -= 1
    if ip_pair_info.trust_counter <= 100 * 0 and not ip_pair_info.blocked:
        # block ip
        ip_pair_info.blocked = True
        acl_add_drop(*members[:2])
        log.info('> block %s -> %s', _msg['src_addr'], _msg['dst_addr'])
        def unblock():
            acl_del(*members[:2])
            ip_pair_info.trust_counter = 100
            ip_pair_info.blocked = False
            log.info('> unblock %s -> %s', _msg['src_addr'], _msg['dst_addr'])
        EventTimer(300, unblock, app_exit).start()


def handle_http_res(packet, msg: dict):
    members = [i.bitstring for i in packet.data[0].struct.members]
    tcp_key = to_tcp_key(members[:4])
    if tcp_key not in _app_context.conns:
        return
    conn = _app_context.conns[tcp_key]
    ip_key = tuple(sorted(members[:2]))
    ip_pair_info = _app_context.ip_pair_info[ip_key]
    index = ip_pair_info.index
    id2 = 0 if conn['is_get'] else 1 if not conn['is_long'] else 2
    updates = []
    updates.append(reg_update(index, id2, '-', 1))
    p = sh.PacketOut(b'\3%c' % len(updates) + b''.join(updates))
    p.metadata['handler'] = '2'
    p.send()
    log.info('> reg_decrease index=%s, id2=%s', index, id2)
    del _app_context.conns[tcp_key]


def handle_new_conn(packet):
    import random
    members = [i.bitstring for i in packet.data[0].struct.members]
    te = p4sh_helper.TableEntry('ingress.http_ingress.tcp_conn')(
        action='add_meta')
    te.match["hdr.ipv4.src_addr"] = members[0]
    te.match["hdr.ipv4.dst_addr"] = members[1]
    te.match["hdr.tcp.src_port"] = members[2]
    te.match["hdr.tcp.dst_port"] = members[3]
    n = random.randint(1, 1023)
    te.action['index'] = str(n)
    te.insert()
    log.info('Random: %s', n)


def clock(pill: threading.Event):
    while True:
        now = int(time.time())
        pill.wait(60)
        if pill.is_set():
            break


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
        for digest_name in p4i.preamble_names['Digest'].values():
            enable_digest(p4i, digest_name)

        # Listening
        print('Listening on controller for switch "{}"'.format(switch))
        stream_client = p4sh_helper.StreamClient(sh.client)

        app_exit = threading.Event()
        time_thread = EventThread(clock, app_exit)
        time_thread.start()

        @stream_client.on('packet')
        def packet_in_handler(packet):
            print('PacketIn.payload')
            hexdump(packet.payload)
            ingress_port = int.from_bytes(packet.metadata[0].value, 'big')
            print(f'PacketIn.metadata[0]: ingress_port={ingress_port}')

        @stream_client.on('digest')
        def digest_handler(packet):
            name = p4i.get_digest_name(packet.digest_id)
            log.info('< Receive digest %s #%s len=%s',
                     name, packet.list_id, len(packet.data))
            if len(packet.data) == 1:
                names = p4i.get_member_names(packet.digest_id)
                members = [i.bitstring for i in packet.data[0].struct.members]
                msg = {k: int.from_bytes(v, 'big') if not k.endswith('_addr')
                       else ('.'.join(str(i) for i in v) if len(v) == 4
                             else ':'.join(f'{i:02x}' for i in v))
                       for k, v in zip(names, members)}
                log.info('< %s', msg)
            else:
                log.debug(packet)
            if name == 'new_conn_t':
                # TODO: remove
                handle_new_conn(packet)
            elif name == 'new_ip_t':
                handle_new_ip(packet, p4i)
            elif name == 'fragment_t':
                handle_fragment(packet, msg, app_exit)
            elif name == 'http_res_t':
                handle_http_res(packet, msg)

        stream_client.recv_bg()

        # Open IPython shell
        IPython.embed(colors="neutral")
        stream_client.stop()
        time_thread.stop()
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
