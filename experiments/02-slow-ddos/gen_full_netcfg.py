#!/usr/bin/env python3
from functools import reduce
import json

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
            links_for_node.append({
                "from": point,
                "to": other,
            })
            accu[point['name']] = links_for_node
        return accu
    net_config['links_from'] = reduce(reducer, net_config['links'].values(), {})
    for link_id, link in net_config['links'].items():
        keys = link_id.split('-')
        net_config['links_from'][keys[0]] = link['basic']['endpoints'][1]
        net_config['links_from'][keys[1]] = link['basic']['endpoints'][0]
    net_config['ports_by_device'] = {}
    for port_id, port in net_config.get('ports', {}).items():
        id_type, id_name = port_id.split(':')
        id_name, id_port = id_name.split('/')
        port['type'] = id_type
        port['name'] = id_name
        port['port'] = id_port
        info = net_config['ports_by_device'].get(id_name, {})
        info[id_port] = port
        net_config['ports_by_device'][id_name] = info
def select_mn_vhost(host_info):
    is_mn_vhost = host_info['basic']['is_mn_vhost']
    return is_mn_vhost

if __name__ == '__main__':
    import argparse
    from pathlib import Path
    pser = argparse.ArgumentParser()
    pser.add_argument('--topo', default='topos/netcfg.json',
                      help='Path to net config json')
    args = pser.parse_args()
    topo_path = Path(__file__, '..', args.topo).resolve()
    net_config = json.load(topo_path.open())
    set_default_net_config(net_config)
    print(json.dumps(net_config))
