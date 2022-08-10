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
from utils.entries import rst_entry
from utils.packetout import rst_packet
from utils.threading import EventTimer, EventThread

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
    max_conns: list[int] = field(default_factory=lambda: [8, 8, 4])
    n_conns: list[int] = field(default_factory=lambda: [0, 0, 0])
    accu_error: list[int] = field(default_factory=lambda: [0, 0, 0])
    error_ts: list[int] = field(default_factory=lambda: [0, 0, 0])


@dataclass
class AppContext:
    net_config: dict
    ip_counter: int = 0
    ip_pair_info: dict[tuple, IpPairInfo] = field(default_factory=dict)
    conns: dict = field(default_factory=dict)
    eth_addr: dict = field(default_factory=dict)


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
        grpc_addr=f'localhost:{switch_info["basic"]["p4rt_port"]}',
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


def to_tcp_key(members: list[bytes]):
    """Convert bytes to tcp_key for _app_context.conns"""
    assert len(members) == 4
    assert all(len(i) == 4 for i in members[:2])
    ip_str = ['.'.join([str(i) for i in ip]) for ip in members[:2]]
    tcp_ports = [int.from_bytes(i, 'big') for i in members[2:]]
    tcp_key = tuple(sorted(zip(ip_str, tcp_ports)))
    return tcp_key


def handle_digest_timestamp(packet):
    members = packet.data[0].struct.members
    ts = int.from_bytes(members[0].bitstring, 'big')
    ip = int.from_bytes(members[1].bitstring, 'big')
    print(f'ingress_global_timestamp = {ts} us, {ts/1000000} s')
    print(f'ipv4 = {ip>>24&0xff}.{ip>>16&0xff}.{ip>>8&0xff}.{ip&0xff}')


def req_register_read(index: int = 0):
    payload = index
    p = sh.PacketOut(b'\2' + payload.to_bytes(2, 'big'))
    p.metadata['handler'] = '2'
    p.send()


def send_updates(updates: list):
    if len(updates) == 0:
        return
    p = sh.PacketOut(b'\3%c' % len(updates) + b''.join(updates))
    p.metadata['handler'] = '2'
    p.send()


def punish(members: list, http_type: int) -> list:
    info = _app_context.ip_pair_info[tuple(sorted(members[:2]))]
    info.accu_error[http_type] += 1
    info.error_ts[http_type] = time.time()
    index = info.index
    updates = []
    if info.accu_error[http_type] >= 3:
        info.accu_error[http_type] -= 3
        if info.accu_error[http_type] < 0:
            info.accu_error[http_type] = 0
        if info.max_conns[http_type] > default_min_conns[http_type]:
            info.max_conns[http_type] -= 1
            updates.append(reg_update(index, http_type+3, '-', 1))
            log.info(
                '> reg_update(index=%s, reg_id=%s, op=%s, value=%s)',
                index, http_type+3, '-', 1
            )
    return updates


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
    _app_context.eth_addr[ips[0]] = members[2].rjust(6, b"\0")
    _app_context.eth_addr[ips[1]] = members[3].rjust(6, b"\0")
    # Initialize ip pair register
    # instruction, (index, max_short_get, max_short_other, max_long_other)
    payload = ((index << 12) + (info.max_conns[0] << 8) +
               (info.max_conns[1] << 4) + info.max_conns[2])
    p = sh.PacketOut(b'\1' + payload.to_bytes(3, 'big'))
    p.metadata['handler'] = '2'
    # bidirectional
    for ip1, ip2 in [ips, ips[::-1]]:
        te = p4sh_helper.TableEntry('ingress.http_ingress.ip_pair')(
            action='add_meta')
        te.match["hdr.ipv4.src_addr"] = ip1
        te.match["hdr.ipv4.dst_addr"] = ip2
        te.action['index'] = str(index)
        te.insert()
    p.send()
    log.info('> ip_pair[%s] = %s <-> %s', index, ip_str[0], ip_str[1])


def send_rst(
    src_ip: bytes, dst_ip: bytes, src_port: bytes, dst_port: bytes, seq: int,
):
    src_eth = _app_context.eth_addr[src_ip]
    dst_eth = _app_context.eth_addr[dst_ip]
    p = rst_packet(src_eth, dst_eth, src_ip, dst_ip, src_port, dst_port, seq)
    p.send()
    log.info(
        '> RST %d.%d.%d.%d:%s -> %d.%d.%d.%d:%s',
        *src_ip, int.from_bytes(src_port, 'big'),
        *dst_ip, int.from_bytes(dst_port, 'big'),
    )


def send_rst_bi(
    src_ip: bytes, dst_ip: bytes, src_port: bytes, dst_port: bytes,
    seq: int, ack: int
):
    src_eth = _app_context.eth_addr[src_ip]
    dst_eth = _app_context.eth_addr[dst_ip]
    p = rst_packet(src_eth, dst_eth, src_ip, dst_ip, src_port, dst_port, seq)
    p.send()
    p = rst_packet(dst_eth, src_eth, dst_ip, src_ip, dst_port, src_port, ack)
    p.send()
    log.info(
        '> RST %d.%d.%d.%d:%s <--> %d.%d.%d.%d:%s',
        *src_ip, int.from_bytes(src_port, 'big'),
        *dst_ip, int.from_bytes(dst_port, 'big'),
    )


def insert_rst_entry_bi(sip, dip, sport, dport):
    rst_entry(p4sh_helper, sip, dip, sport, dport).insert()
    rst_entry(p4sh_helper, dip, sip, dport, sport).insert()
    log.info(
        '> ins rst %s.%s.%s.%s:%s <--> %s.%s.%s.%s:%s',
        *sip, int.from_bytes(sport, 'big'),
        *dip, int.from_bytes(dport, 'big'),
    )


def delete_rst_entry_bi(sip, dip, sport, dport):
    rst_entry(p4sh_helper, sip, dip, sport, dport).delete()
    rst_entry(p4sh_helper, dip, sip, dport, sport).delete()
    log.info(
        '> del rst %s.%s.%s.%s:%s <--> %s.%s.%s.%s:%s',
        *sip, int.from_bytes(sport, 'big'),
        *dip, int.from_bytes(dport, 'big'),
    )


def del_then_send_rst(tcp_key, sip, dip, sport, dport):
    conn = _app_context.conns.get(tcp_key)
    delete_rst_entry_bi(sip, dip, sport, dport)
    if conn is not None:
        send_rst_bi(sip, dip, sport, dport, conn['seq_no'], conn['ack_no'])
        del _app_context.conns[tcp_key]


def schedule_rst(members, app_exit: threading.Event, return_update=False):
    """Close connection with table rules and RST packet.

    RST only close client if seq is not correct so convert packets to RST first

    Returns:
        register_update if there is an update and return_update is True
        None otherwise
    """
    tcp_key = to_tcp_key(members[:4])
    conn = _app_context.conns.get(tcp_key)
    if conn is None or conn['rst_added']:
        return
    conn['rst_added'] = True

    # send rst to server first
    send_rst(*members[:4], conn['seq_no'])

    # decrease conn register
    info = _app_context.ip_pair_info[tuple(sorted(members[:2]))]
    http_type = conn['http_type']
    info.n_conns[http_type] -= 1
    update = reg_update(info.index, http_type, '-', 1)

    # block by RST and send RST
    src_ip = members[0].rjust(4, b'\0')
    dst_ip = members[1].rjust(4, b'\0')
    src_port = members[2].rjust(2, b'\0')
    dst_port = members[3].rjust(2, b'\0')
    insert_rst_entry_bi(src_ip, dst_ip, src_port, dst_port)
    EventTimer(20.0, del_then_send_rst, app_exit, args=(
        tcp_key, src_ip, dst_ip, src_port, dst_port)).start()
    if return_update:
        return update
    else:
        send_updates([update])


def check_req_timeout(members: list, app_exit: threading.Event):
    tcp_key = to_tcp_key(members[:4])
    conn = _app_context.conns.get(tcp_key)
    info = _app_context.ip_pair_info[tuple(sorted(members[:2]))]
    if conn is None:
        return
    conn['timer'] = None
    http_type = conn['http_type']
    if http_type == 2:
        client = members[0], int.from_bytes(members[2], 'big')
        log.error('long-term non-GET conn timeout %s:%s', *client)
        return
    if http_type == 0:
        rst_added = conn['rst_added']
        # try to punish
        if not rst_added:
            updates = []
            updates.extend(punish(members, 0))
            update = schedule_rst(members[:4], app_exit)
            if update is not None:
                updates.append(update)
            send_updates(updates)
    elif http_type == 1:
        if info.n_conns[2] < info.max_conns[2]:
            info.n_conns[2] += 1
            info.n_conns[1] -= 1
            send_updates([
                reg_update(info.index, 2, '+', 1),
                reg_update(info.index, 1, '-', 1),
            ])
        else:
            updates = []
            # updates.extend(punish(members, 1))
            update = schedule_rst(members[:4], app_exit)
            if update is not None:
                updates.append(update)
            send_updates(updates)


def handle_fragment(packet, msg: dict, app_exit: threading.Event): # noqa: C901
    members = [i.bitstring for i in packet.data[0].struct.members]
    conns = _app_context.conns
    tcp_key = to_tcp_key(members[:4])
    ip_key = tuple(sorted(members[:2]))
    msg = msg.copy()
    for k in ['src_addr', 'dst_addr', 'src_port', 'dst_port']:
        msg.pop(k)
    for k in ['is_req_start', 'is_get', 'has_2_crlf', 'is_long']:
        msg[k] = msg[k] == 1
    if msg['is_req_start']:
        if (conns.get(tcp_key) is not None and
                conns[tcp_key]['timer'] is not None):
            return
        conns[tcp_key] = msg
        conn = conns[tcp_key]
        conn['seq_no'] = (msg['seq_no'] + msg['app_len']) % 2 ** 32
        conn['timer'] = None
        conn['rst_added'] = False
        http_type = 0 if conn['is_get'] else 1 if not conn['is_long'] else 2
        conn['http_type'] = http_type
        ip_pair_info = _app_context.ip_pair_info[ip_key]
        ip_pair_info.n_conns[http_type] += 1
        if http_type == 0 or http_type == 1:
            timer = EventTimer(10.0, check_req_timeout, app_exit, args=(
                members[:4], app_exit,
            ))
            conn['timer'] = timer
            timer.start()
        return
    if tcp_key not in conns:
        return
    conn = conns[tcp_key]
    conn['seq_no'] = (msg['seq_no'] + msg['app_len']) % 2 ** 32
    conn['ack_no'] = msg['ack_no']
    if conn['has_2_crlf']:
        return
    if not conn['is_get'] and msg['content_length'] > 0:
        conn['content_length'] = msg['content_length']
        info = _app_context.ip_pair_info[ip_key]
        # http_type 1 -> 2 because late identify
        if conn['http_type'] == 1:
            # long term, late identify: don't punish
            # short-term to long-term and exceed: punish
            if conn['timer'] is not None:
                conn['timer'].cancel()
                conn['timer'] = None
            if info.n_conns[2] >= info.max_conns[2]:
                schedule_rst(members[:4], app_exit)
            else:
                conn['http_type'] = 2
                info.n_conns[2] += 1
                info.n_conns[1] -= 1
                send_updates([
                    reg_update(info.index, 2, '+', 1),
                    reg_update(info.index, 1, '-', 1),
                ])
    if msg['has_2_crlf']:
        conn['has_2_crlf'] = True


def reg_update(index: int, id2: int, op: str, value: int) -> bytes:
    payload = (index << 24) + (id2 << 16) + (ord(op) << 8) + value
    payload = payload.to_bytes(7, 'big')
    return payload


def handle_http_res(packet, msg: dict):
    members = [i.bitstring for i in packet.data[0].struct.members]
    tcp_key = to_tcp_key(members[:4])
    if tcp_key not in _app_context.conns:
        return
    conn = _app_context.conns[tcp_key]
    if conn['timer'] is not None:
        conn['timer'].cancel()
        conn['timer'] = None
    ip_key = tuple(sorted(members[:2]))
    ip_pair_info = _app_context.ip_pair_info[ip_key]
    index = ip_pair_info.index
    id2 = 0 if conn['is_get'] else 1 if not conn['is_long'] else 2
    ip_pair_info.n_conns[id2] -= 1
    updates = []
    if msg['status_code'] == 4:
        updates.extend(punish(members, id2))
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


def handle_conn_match(packet, p4i: p4sh_helper.P4Info):
    # names = p4i.get_member_names(packet.digest_id)
    # members = packet.data[0].struct.members
    # values = [int.from_bytes(i.bitstring, 'big') for i in members]
    # msg = dict(zip(names, values))
    # log.info('conn_match: %s', msg)
    pass


def handle_digest_debug(packet):
    pass


def enable_digest(p4i: p4sh_helper.P4Info, name: str) -> None:
    update = p4i.DigestEntry(name).as_update()
    sh.client.write_update(update)
    log.info('Enable digest: %s', name)


def clock(pill: threading.Event):
    while True:
        now = int(time.time())
        for info in _app_context.ip_pair_info.values():
            updates = []
            for i in range(3):
                info.accu_error[i] = 0
                if (info.max_conns[i] < default_max_conns[i] and
                        now - info.error_ts[i] > 60):
                    info.max_conns[i] += 1
                    updates.append(reg_update(info.index, i+3, '+', 1))
                    log.info(
                        '> reg_update(index=%s, id2=%s, op=%s, value=%s)',
                        info.index, i+3, '+', 1
                    )
            if len(updates) > 0:
                p = sh.PacketOut(b'\3%c' % len(updates)+b''.join(updates))
                p.metadata['handler'] = '2'
                p.send()
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
            if name == 'timestamp_digest_t':
                handle_digest_timestamp(packet)
            elif name == 'new_conn_t':
                # TODO: remove
                handle_new_conn(packet)
            elif name == 'debug_digest_t':
                handle_digest_debug(packet)
            elif name == 'conn_match_t':
                handle_conn_match(packet, p4i)
            elif name == 'new_ip_t':
                handle_new_ip(packet, p4i)
            elif name == 'fragment_t':
                handle_fragment(packet, msg, app_exit)
            elif name == 'http_res_t':
                handle_http_res(packet, msg)

        stream_client.recv_bg()

        # Open IPython shell
        IPython.embed(colors="neutral")
        app_exit.set()
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
    pser.add_argument('--topo', default='topos/netcfg.json',
                      help='Path to net config json')
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
    topo_path = Path(__file__, '..', args.topo).resolve()
    net_config = json.load(topo_path.open())
    set_default_net_config(net_config)
    _app_context.net_config = net_config
    args.func(args)


if __name__ == '__main__':
    main()
