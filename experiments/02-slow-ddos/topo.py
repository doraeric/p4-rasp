"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.net import Mininet
from mininet.topo import Topo

original_build = Mininet.build
def build(self):
    original_build(self)
    h1 = self.nameToNode['h1']
    h2 = self.nameToNode['h2']
    h3 = self.nameToNode['h3']
    h1.cmd('route add default gw 10.0.1.10 dev h1-eth0')
    h1.cmd('arp -i h1-eth0 -s 10.0.1.10 08:00:00:00:01:00')
    print('Starting apache. It takes some time...')
    h1.cmd('service apache2 start')
    h2.cmd('route add default gw 10.0.2.20 dev h2-eth0')
    h2.cmd('arp -i h2-eth0 -s 10.0.2.20 08:00:00:00:02:00')
    h3.cmd('route add default gw 10.0.2.20 dev h3-eth0')
    h3.cmd('arp -i h3-eth0 -s 10.0.2.20 08:00:00:00:02:00')

Mininet.build = build

class MyTopo( Topo ):
    "Simple topology example."

    def build( self ):
        "Create custom topo."

        # Add hosts and switches
        # h1 -- s1 -- s2 -- h2
        h1 = self.addHost('h1', ip='10.0.1.1/24')
        h2 = self.addHost('h2', ip='10.0.2.2/24')
        h3 = self.addHost('h3', ip='10.0.2.3/24')
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')

        # Add links
        self.addLink(h1, s1)
        self.addLink(s1, s2)
        self.addLink(s2, h2)
        self.addLink(s2, h3)

topos = { 'mytopo': ( lambda: MyTopo() ) }
