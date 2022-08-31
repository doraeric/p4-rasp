#!/usr/bin/env python3
import argparse
import asyncio
import concurrent
import logging
import subprocess
from threading import Thread
import time

import pyshark
import requests

# logging
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter(
    ('%(asctime)s.%(msecs)03d: %(levelname).1s/%(name)s: '
     '%(filename)s:%(lineno)d: %(message)s'),
    datefmt='%H:%M:%S',
))
log = logging.getLogger('shda-agent')
log.addHandler(console_handler)
log.setLevel(logging.INFO)

white_list = [
    '10.0.2.2', '10.0.2.3', '10.0.2.4', '10.0.2.5', '10.0.2.6', '10.0.2.7']


def clean_str(s):
    return str(s).encode('ascii', 'ignore').decode('ascii')


def create_server_dir() -> bool:
    try:
        requests.put('http://localhost:9090/pkts')
        return True
    except requests.ConnectionError:
        log.info('file server off')
    return False


def clock(timeout: float, conn_threshold: int, close_client=True):
    # Try not to use clock, only use it if pyshark is too slow
    start_ts = time.time()
    stop_ts = start_ts + timeout
    interval = 5
    exceed_counter = 0
    log.info('clock start')
    while time.time() < stop_ts:
        # check num of sockets
        lines = subprocess.check_output(
            ("netstat -tnp | grep 10.0.1.1:80 | awk '{print $5}' "
                "| sed 's/:/ /g'"),
            shell=True,
        ).decode('ascii').splitlines()
        if len(lines) >= 150:
            exceed_counter += 1
            if exceed_counter >= 3:
                log.info('clock close')
                exceed_counter = 0
                for line in lines:
                    conn = line.split()
                    if not close_client and conn[0] in white_list:
                        continue
                    subprocess.run(
                        ['ss', '-K', 'dst', conn[0], 'dport', '=', conn[1]],
                        capture_output=True,
                    )
                    log.info('disconn %s:%s', conn[0], conn[1])
        else:
            exceed_counter = 0
        if time.time() + interval < stop_ts:
            time.sleep(interval)
        else:
            break


def capture_interface(  # noqa: C901
    interface: str, timeout: float, close_client=True, aggressive_close=False,
):
    log.info('start')
    log.info(
        'close_client=%s, aggressive_close=%s', close_client, aggressive_close)
    upload_counter = 0
    conn_threshold = 120
    conns = set()
    # FIN and RST may come before other packets, maybe it's pyshark's bug
    # never add deleted connections back
    deleted_conns = set()
    packets = []
    timeout_error = (
        asyncio.exceptions.TimeoutError if hasattr(asyncio, 'exceptions')
        else concurrent.futures._base.TimeoutError
    )
    file_server_on = create_server_dir()
    # clock thread
    t = Thread(target=clock, args=[timeout, conn_threshold, close_client])
    t.start()
    capture = pyshark.LiveCapture(
        interface=interface, bpf_filter='tcp port 80',
        use_json=True, include_raw=True,
    )

    def packet_handler(p: pyshark.packet.packet.Packet):
        nonlocal upload_counter, packets
        raw = p.get_raw_packet()
        src_ip, dst_ip = p.ip.src, p.ip.dst
        src_port, dst_port = p.tcp.srcport, p.tcp.dstport
        tcp_rst = p.tcp.flags_tree.reset == '1'
        tcp_fin = p.tcp.flags_tree.fin == '1'
        remote = (dst_ip, dst_port) if src_port == '80' else (src_ip, src_port)
        if any((tcp_rst, tcp_fin)):  # close connections
            if remote in conns:
                conns.remove(remote)
                deleted_conns.add(remote)
                packets = list(filter(
                    lambda i: i['remote'] != remote, packets))
                log.info('del %s:%s', *remote)
        else:  # open connections
            if remote not in deleted_conns:
                conns.add(remote)
                packets.append({'raw': raw, 'remote': remote})
                log.info('add %s:%s', *remote)
        # log.info(f'{src_ip}:{src_port} -> {dst_ip}:{dst_port}')

        # activate
        if len(conns) >= conn_threshold:
            log.info('activate, n_conns=%s', len(conns))
            log.info(conns)

            log.info('sending packets to controller')
            for packet in packets:
                # should send to controller via PacketIn
                if file_server_on:
                    save_name = f'{upload_counter}.pkt'
                    requests.post(
                        f'http://localhost:9090/pkts/{save_name}',
                        files={'blob': packet['raw']})
                upload_counter += 1
            packets.clear()

            for conn in conns:
                # Hack for recovery, enable this for exp3
                if not close_client and conn[0] in white_list:
                    # Don't really close good client if it can be reconnected
                    # by SHDA because the recovery is not implemented
                    # This can be removed once recovery is done
                    continue
                subprocess.run(
                    ['ss', '-K', 'dst', conn[0], 'dport', '=', conn[1]],
                    capture_output=True,
                )
                log.info('disconn %s:%s', conn[0], conn[1])
            conns.clear()

            # disconn any one
            if aggressive_close:
                lines = subprocess.check_output(
                    ("netstat -tnp | grep 10.0.1.1:80 | awk '{print $5}' "
                     "| sed 's/:/ /g'"),
                    shell=True,
                ).decode('ascii').splitlines()
                for line in lines:
                    conn = line.split()
                    if not close_client and conn[0] in white_list:
                        continue
                    subprocess.run(
                        ['ss', '-K', 'dst', conn[0], 'dport', '=', conn[1]],
                        capture_output=True,
                    )
                    log.info('disconn %s:%s', conn[0], conn[1])
    try:
        capture.apply_on_packets(packet_handler, timeout=timeout)
    except timeout_error:
        pass
    log.info('exit')


def main(interface='lo'):
    pser = argparse.ArgumentParser()
    pser.add_argument('-i', '--interface', default='lo')
    pser.add_argument('-t', '--timeout', type=float, default=3.0)
    pser.add_argument('--close-client', action='store_true', default=True)
    pser.add_argument(
        '--no-close-client', dest='close_client', action='store_false')
    pser.add_argument('--aggressive-close', action='store_true', default=False)
    args = pser.parse_args()
    capture_interface(**vars(args))


if __name__ == '__main__':
    main()
