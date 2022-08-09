def rst_entry(
    helper, src_ip: bytes, dst_ip: bytes, src_port: bytes, dst_port: bytes
):
    te = helper.TableEntry('ingress.http_ingress.conn')(
        action='add_bad_meta')
    te.match["hdr.ipv4.src_addr"] = src_ip
    te.match["hdr.ipv4.dst_addr"] = dst_ip
    te.match["hdr.tcp.src_port"] = src_port
    te.match["hdr.tcp.dst_port"] = dst_port
    return te
