"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

import json
import os
import sys

from mininet.link import Intf, TCLink
from mininet.net import Mininet
from mininet.topo import Topo

from .gen_full_netcfg import set_default_net_config, select_mn_vhost

try:
    dir_path = os.path.dirname(os.path.realpath(__file__))
except:
    dir_path = os.getcwd()

topo_name = sys.argv[sys.argv.index('--topo') + 1]
topo_file = os.path.join(dir_path, 'topos', topo_name + '.json')
topo_file = (topo_file if os.path.exists(topo_file)
             else os.path.join(dir_path, 'topos', "netcfg.json"))
print('Topo file is ' + os.path.basename(topo_file))

# Load network topology from json
net_config = json.load(open(topo_file))
set_default_net_config(net_config)

apache_site_conf = '''
<Proxy *>
    Order allow,deny
    Allow from all
</Proxy>

ProxyPass /api http://localhost:3000
ProxyPassReverse /api http://localhost:3000
ProxyPass / http://localhost:9090/
ProxyPassReverse / http://localhost:9090/
ProxyPreserveHost on
'''[1:]


def setup_old_apache(h):
    # https://stackoverflow.com/questions/45483844/how-to-insert-a-string-into-second-to-last-line-of-a-file
    h.cmd('a2dismod reqtimeout')
    h.cmd("sed -i '13i\\\tLimitRequestFields 0\\' /etc/apache2/sites-available/000-default.conf")
    h.cmd(r"sed -i 's/^Timeout [0-9]\+$/Timeout 60/' /etc/apache2/apache2.conf")


def setup_backend(h):
    h.cmd('mkdir -p /opt/pad.js')
    h.cmd('mkdir -p /var/log/padjs')
    h.cmd('mkdir -p /var/log/json-server')
    h.cmd('pad.js --servedir=/opt/pad.js --timeout=-1 >/var/log/padjs/access.log 2>/var/log/padjs/error.log &')
    # example gps data: https://gpslogger.app/#customurl
    data = ('{"gps-locations":[{"id": 1, "lat": 0.1, "lng": 0.1, "device_id": '
            '"ABCDEF", "battery": 99.8, "timestamp": 1660792443.696}]}')
    h.cmd("echo '{}' > /opt/db.json".format(data))
    # `--watch` causes server to restart and listen on the same port
    h.cmd('json-server /opt/db.json >/var/log/json-server/access.log 2>/var/log/json-server/error.log &')

original_build = Mininet.build
def build(self):
    """Set default gateway and add neighbor arp for hosts"""
    original_build(self)
    for host_conf in filter(select_mn_vhost, net_config['hosts'].values()):
        name = host_conf['basic']['name']
        host = self.nameToNode[name]
        router = net_config['links_from'][name][0]['to']['name']
        router_ip = net_config['devices_by_name'][router]['segmentrouting']['routerIpv4'].split('/')[0]
        router_mac = net_config['devices_by_name'][router]['segmentrouting']['routerMac']
        # Add default gateway and arp
        host.cmd('route add default gw {gateway} dev {name}-eth0'.format(gateway=router_ip, name=name))
        host.cmd('arp -i {name}-eth0 -s {ip} {mac}'.format(name=name, ip=router_ip, mac=router_mac))
        # Enable conntrack
        # https://manpages.ubuntu.com/manpages/xenial/man8/flowtop.8.html
        host.cmd('iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT')
        host.cmd('iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT')
        for link in net_config['links_from'][router]:
            point = link['to']
            if point['name'] == name or point['type'] == 'device': continue
            other = net_config['hosts_by_name'][point['name']]['basic']
            other_ip = other['ips'][0].split('/')[0]
            other_mac = other['mac']
            # Add neighbor arp
            host.cmd('arp -i {name}-eth0 -s {ip} {mac}'.format(name=name, ip=other_ip, mac=other_mac))
    # add interface
    print('*** Adding interfaces:')
    added_interfaces = []
    for port_id, port_info in net_config.get('ports', {}).items():
        if port_info.get('interfaces') is None or len(port_info['interfaces']) == 0:
            continue
        interface_name = port_info['interfaces'][0]['name']
        if not os.path.exists('/sys/class/net/{}'.format(interface_name)):
            print('Interface {} not found'.format(interface_name))
            continue
        device_name = port_id.split('/')[0].split(':')[-1]
        node = self.nameToNode[device_name]
        port = int(port_info['port'])
        Intf(interface_name, node=node, port=port)
        added_interfaces.append('device:{}/{}->{}'.format(device_name, port, interface_name))
        # s1 = self.nameToNode['s1']
        # Intf('vmnet3', node=s1, port=3)
        # mininet> py s1.intfs
    if len(added_interfaces) > 0:
        print(' '.join(added_interfaces))
    # Start h1 apache server
    h1 = self.nameToNode['h1']
    setup_old_apache(h1)
    setup_backend(h1)
    # https://arthurchiao.art/blog/conntrack-design-and-implementation-zh/#%E8%A7%A3%E5%86%B3%E6%96%B9%E5%BC%8F
    # SYN, SYN+ACK, ACK, blocked -> established not close
    # socket will be closed in a strange timeout, better to fix manually
    h1.cmd('sysctl -w net.netfilter.nf_conntrack_tcp_timeout_established=63')
    h1.cmd('echo "ServerName 127.0.0.1" >> /etc/apache2/apache2.conf')
    h1.cmd('a2enmod proxy')
    h1.cmd('a2enmod proxy_http')
    h1.cmd('a2enmod rewrite')
    with open('/etc/apache2/sites-available/000-default.conf', 'r+') as fd:
        contents = fd.readlines()
        contents.insert(29, apache_site_conf)
        fd.seek(0)
        fd.writelines(contents)
    h1.cmd('service apache2 start')

Mininet.build = build

class MyTopo( Topo ):
    "Simple topology example."

    def build( self ):
        "Create custom topo."

        # Add mininet host
        mn_hosts = {}
        for host in filter(select_mn_vhost, net_config['hosts'].values()):
            mac = host['basic']['mac']
            name = host['basic']['name']
            ip = host['basic']['ips'][0]
            mn_hosts[name] = self.addHost(name, ip=ip, mac=mac)
        # Add mininet switch
        mn_switches = {}
        for name in net_config['devices_by_name']:
            mn_switches[name] = self.addSwitch(name)
        # Add mininet link
        for link in filter(lambda i: i['basic']['is_mn_link'], net_config['links'].values()):
            ps = link['basic']['endpoints']
            hs = [mn_hosts[p['name']] if p['type'] == 'host' else mn_switches[p['name']] for p in ps]
            self.addLink(hs[0], hs[1], ps[0]['port'], ps[1]['port'], cls=TCLink, **link.get('mnkw', {}))

topos = { topo_name: ( lambda: MyTopo() ) }
