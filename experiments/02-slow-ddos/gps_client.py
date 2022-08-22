#!/usr/bin/env python3
import argparse
import asyncio
from asyncio import wait_for
from datetime import datetime
import logging
import json
import random
import time
from urllib.parse import urlparse

log = logging.getLogger('gps_client')
formatter = logging.Formatter(
    ('%(asctime)s.%(msecs)03d: %(levelname).1s/%(name)s: '
     '%(filename)s:%(lineno)d: %(message)s'),
    datefmt='%H:%M:%S',
)
console = logging.StreamHandler()
console.setFormatter(formatter)
log.addHandler(console)
log.setLevel(logging.INFO)


async def conn(hostname, port, path, conn_time, desc, conn_id=None):
    try:
        start_ts = time.time()
        stop_ts = start_ts + conn_time
        conn_id = random.randrange(1000) if conn_id is None else conn_id
        log.info('[%03d] open conn', conn_id)
        reader, writer = await wait_for(
            asyncio.open_connection(hostname, 80), stop_ts - time.time())

        # generate request
        start_line = 'POST {path} HTTP/1.1\r\n'.format(path=path).encode()
        headers = (
            'Host: {hostname}\r\n'
            'Content-Type: application/json\r\n'
            'Content-Length: {length}\r\n'
            '\r\n'
        )
        now = time.time()
        now_dt = datetime.fromtimestamp(now)
        data = {
            "lat": 25.017292249596167, "lng": 121.53977833610736,
            "sat": 0, "desc": desc, "alt": 29.19999885559082,
            "acc": 14.963000297546387, "dir": 0.0, "prov": "network",
            "spd": 0.0, "timestamp": now,
            "time": now_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3],
            "date": now_dt.strftime("%Y-%m-%d"),
            "battery": 100.0, "ischarging": True, "aid": "64d3bca9d3209fee",
            "ser": "64d3bca9d3209fee", "profile": "default",
        }
        data_encode = json.dumps(data, ensure_ascii=False).encode('utf-8')
        headers = headers.format(hostname=hostname, length=len(data_encode))
        headers = headers.encode('utf-8')

        # write
        writer.write(start_line + headers)
        await wait_for(writer.drain(), stop_ts - time.time())
        writer.write(data_encode)

        content_length = 0
        start_line = await wait_for(reader.readline(), stop_ts - time.time())
        version, code, text = start_line.decode('utf-8').split(' ', 2)
        while True:
            line = await wait_for(reader.readline(), stop_ts - time.time())
            if line.startswith(b'Content-Length: '):
                content_length = int(line[16:-2])
            if line == b'\r\n':
                break
        data = b''
        if content_length > 0:
            remain_size = content_length - len(data)
            while remain_size > 0:
                data += await wait_for(
                    reader.read(remain_size), stop_ts - time.time())
                remain_size = content_length - len(data)
        log.info('[%03d] <%s> close conn', conn_id, code)
        writer.close()
        if code.startswith('2'):
            return True
    except asyncio.TimeoutError:
        log.info('[%03d] asyncio.TimeoutError', conn_id)
    except Exception as e:
        log.info(e)
    return False


async def upload_loop(
    url: str, timeout: float, connect_timeout: float, interval: float,
    desc: str,
):
    start_ts = time.time()
    stop_ts = start_ts + timeout
    loop = asyncio.get_event_loop()
    u = urlparse(url)
    hostname = u.hostname
    port = 80 if u.port is None else u.port
    path = u.path if len(u.path) > 0 else '/'
    tasks = []
    now = time.time()
    counter = 0
    while now < stop_ts:
        tasks.append(loop.create_task(
            conn(
                hostname=hostname,
                port=port,
                path=path,
                conn_time=connect_timeout,
                desc=desc,
                conn_id = counter,
            )
        ))
        counter += 1
        if now + interval > stop_ts:
            break
        await asyncio.sleep(interval)
        now = time.time()
    try:
        resps = await wait_for(asyncio.gather(*tasks), timeout + 3)
        log.info('success = %s', sum(resps))
        log.info('fail = %s', len(resps) - sum(resps))
    except asyncio.TimeoutError:
        log.info('asyncio.TimeoutError')


def custom_exception_handler(loop, context):
    # https://stackoverflow.com/questions/43207927/
    # first, handle with default handler
    loop.default_exception_handler(context)


def main():
    pser = argparse.ArgumentParser()
    pser.add_argument('url')
    pser.add_argument(
        '--connect-timeout', type=float, default=1.0,
        help='each connection needs to be finished within timeout',
    )
    pser.add_argument(
        '--timeout', type=float, default=3.0,
        help='loop timeout',
    )
    pser.add_argument(
        '-i', '--interval', type=float, default=1.0,
        help='interval between each request',
    )
    pser.add_argument('--desc', default="hxx")
    args = pser.parse_args()
    # asyncio.run(attack(**vars(args)))
    loop = asyncio.get_event_loop()
    loop.set_exception_handler(custom_exception_handler)
    loop.run_until_complete(upload_loop(**vars(args)))


if __name__ == '__main__':
    main()
