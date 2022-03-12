global_options["canonical_bytestrings"] = False

te = table_entry['ingress.next.ipv4_lpm'](action='ingress.next.ipv4_forward')
te.match["hdr.ipv4.dst_addr"] = "10.0.1.0/24"
te.action['dst_addr'] = '00:00:00:00:00:01'
te.action["port"] = "1"
te.insert()

te = table_entry['ingress.next.ipv4_lpm'](action='ingress.next.ipv4_forward')
te.match["hdr.ipv4.dst_addr"] = "10.0.2.0/24"
te.action['dst_addr'] = '08:00:00:00:02:00'
te.action["port"] = "2"
te.insert()

# te = table_entry["MyIngress.ipv4_lpm"](action="MyIngress.ipv4_forward")
# te.match["hdr.ipv4.dstAddr"] = "10.0.1.0/24"
# te.action["dstAddr"] = "00:00:00:00:00:01"
# te.action["port"] = "1"
# te.insert()

# te = table_entry["MyIngress.ipv4_lpm"](action="MyIngress.ipv4_forward")
# te.match["hdr.ipv4.dstAddr"] = "10.0.2.0/24"
# te.action["dstAddr"] = "08:00:00:00:02:00"
# te.action["port"] = "2"
# te.insert()
