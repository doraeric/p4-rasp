from utils.p4sh_helper import P4RTClient
from utils import protocol


def rst_entry(
    client: P4RTClient,
    src_ip: bytes, dst_ip: bytes, src_port: bytes, dst_port: bytes
):
    te = client.TableEntry('ingress.http_ingress.conn')(
        action='add_bad_meta')
    te.match["hdr.ipv4.src_addr"] = src_ip
    te.match["hdr.ipv4.dst_addr"] = dst_ip
    te.match["hdr.tcp.src_port"] = src_port
    te.match["hdr.tcp.dst_port"] = dst_port
    return te


def drop_syn(client: P4RTClient, src_ip: bytes, dst_ip: bytes):
    te = client.TableEntry('ingress.acl.acl')(action='ingress.acl.drop')
    te.priority = 1
    te.match["eth_type"] = protocol.ETH_TYPE_IPV4
    te.match["ip_proto"] = protocol.IP_PROTO_TCP
    te.match["ipv4_src"] = src_ip
    te.match["ipv4_dst"] = dst_ip
    te.match["tcp_flag"] = b'\x02'
    return te
