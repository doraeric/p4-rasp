"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

import json
import os

from mininet.net import Mininet
from mininet.topo import Topo

try:
    dir_path = os.path.dirname(os.path.realpath(__file__))
except:
    dir_path = os.getcwd()

def merge_two_dicts(x, y):
    z = x.copy()
    z.update(y)
    return z

def set_default_net_config(net_config):
    for device_id, device in net_config['devices'].items():
        device['basic'] = merge_two_dicts(device.get('basic', {}), {
            'name': device_id.split(':')[-1],
        })
    net_config['devices_by_name'] = {
        i['basic']['name']: i for i in net_config['devices'].values()
    }
    for host_id, host in net_config['hosts'].items():
        host['basic'] = merge_two_dicts(host.get('basic', {}), {
            'mac': host_id.split('/')[0],
            'is_mn_vhost': host.get('basic', {}).get('is_mn_vhost', True),
        })
    net_config['hosts_by_name'] = {
        i['basic']['name']: i for i in net_config['hosts'].values()
    }
    for link_id, link in net_config['links'].items():
        # 'type:name/port-type:name/port'
        endpoints = [i.split(':') for i in link_id.split('-')]
        endpoints = [{
            'type': i[0],
            'name': i[1].split('/')[0],
            'port': int(i[1].split('/')[1]),
        } for i in endpoints]
        i = endpoints[0]
        link['basic'] = merge_two_dicts(link.get('basic', {}), {
            'endpoints': endpoints,
            'is_mn_link': all([(
                i['type'] == 'device' or
                (i['type'] == 'host' and net_config['hosts_by_name'][i['name']]['basic']['is_mn_vhost'])
            ) for i in endpoints])
        })
    def reducer(accu, curr):
        endpoints = curr['basic']['endpoints']
        names = [i['name'] for i in endpoints]
        for index, point in enumerate(endpoints):
            other = endpoints[1] if index == 0 else endpoints[0]
            links_for_node = accu.get(point['name'], [])
            links_for_node.append(other)
            accu[point['name']] = links_for_node
        return accu
    net_config['links_from'] = reduce(reducer, net_config['links'].values(), {})
def select_mn_vhost(host_info):
    is_mn_vhost = host_info['basic']['is_mn_vhost']
    return is_mn_vhost

# Load network topology from json
net_config = json.load(open(os.path.join(dir_path, "netcfg.json")))
set_default_net_config(net_config)

original_build = Mininet.build
def build(self):
    """Set default gateway and add neighbor arp for hosts"""
    original_build(self)
    for host_conf in filter(select_mn_vhost, net_config['hosts'].values()):
        name = host_conf['basic']['name']
        host = self.nameToNode[name]
        router = net_config['links_from'][name][0]['name']
        router_ip = net_config['devices_by_name'][router]['segmentrouting']['routerIpv4'].split('/')[0]
        router_mac = net_config['devices_by_name'][router]['segmentrouting']['routerMac']
        # Add default gateway and arp
        host.cmd('route add default gw {gateway} dev {name}-eth0'.format(gateway=router_ip, name=name))
        host.cmd('arp -i {name}-eth0 -s {ip} {mac}'.format(name=name, ip=router_ip, mac=router_mac))
        for point in net_config['links_from'][router]:
            if point['name'] == name or point['type'] == 'device': continue
            other = net_config['hosts_by_name'][point['name']]['basic']
            other_ip = other['ips'][0].split('/')[0]
            other_mac = other['mac']
            # Add neighbor arp
            host.cmd('arp -i {name}-eth0 -s {ip} {mac}'.format(name=name, ip=other_ip, mac=other_mac))
    # Start h1 apache server
    h1 = self.nameToNode['h1']
    h1.cmd('echo "ServerName 127.0.0.1" >> /etc/apache2/apache2.conf')
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
            self.addLink(hs[0], hs[1], ps[0]['port'], ps[1]['port'])

topos = { 'mytopo': ( lambda: MyTopo() ) }
