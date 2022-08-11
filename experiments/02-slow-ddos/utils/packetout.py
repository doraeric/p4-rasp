from utils.p4sh_helper import P4RTClient


def rst_packet(
    client: P4RTClient,
    src_eth: bytes, dst_eth: bytes,
    src_ip: bytes, dst_ip: bytes,
    src_port: bytes, dst_port: bytes,
    seq: int,
):
    src_eth = src_eth.rjust(6, b'\0')
    dst_eth = dst_eth.rjust(6, b'\0')
    src_ip = src_ip.rjust(4, b'\0')
    dst_ip = dst_ip.rjust(4, b'\0')
    src_port = src_port.rjust(2, b'\0')
    dst_port = dst_port.rjust(2, b'\0')
    seq = seq.to_bytes(4, 'big')
    payload = b'\1'
    payload += dst_eth + src_eth + b'\x08\x00'
    payload += b'\x45\x00\x00\x28\0\0\x40\0\x40\x06\0\0' + src_ip + dst_ip
    payload += src_port + dst_port + seq + b'\0\0\0\0\x50\x04\0\0\0\0\0\0'
    p = client.PacketOut(payload)
    p.metadata['handler'] = '3'
    return p
