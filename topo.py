from mininet.clean import Cleanup
from mininet.cli import CLI
from mininet.net import Mininet
from mininet.node import Controller, Node, OVSSwitch, RemoteController
from mininet.term import tunnelX11


class OptionalRemoteController(RemoteController):
    def __init__(self, name, ip, port=None, **kwargs):
        Controller.__init__(self, name, ip=ip, port=port, **kwargs)

    def checkListening(self):
        """Ignore controller not accessible warning"""
        pass

    def stop(self):
        super(Controller, self).stop(deleteIntfs=True)


def create_network() -> Mininet:
    """
                +-------------------------+
                |            c0           |
                |                         |
                +--c0-eth0-------c0-eth1--+
                      |             |
                      |             |
                      3             3
     +----+        +----+        +----+        +----+
     | h1 |0------1| s1 |2------2| s2 |1------0| h2 |
     +----+        +----+        +----+        +----+
    10.0.0.1                                  10.0.0.2
    """

    net = Mininet(controller=None, build=False, cleanup=True)

    net.addController('cc0', OptionalRemoteController, ip='10.0.1.1', port=6653)

    s1 = net.addSwitch('s1', cls=OVSSwitch, failmode='standalone')
    s2 = net.addSwitch('s2', cls=OVSSwitch, failmode='standalone')

    h1 = net.addHost('h1')
    h2 = net.addHost('h2')
    c0 = net.addHost('c0')

    link_h1s1 = net.addLink(h1, s1, intfName1='h1-eth0', intfName2='s1-eth1')
    link_h2s2 = net.addLink(h2, s2, intfName1='h2-eth0', intfName2='s2-eth1')
    link_s1s2 = net.addLink(s1, s2, intfName1='s1-eth2', intfName2='s2-eth2')

    link_c0s1 = net.addLink(c0, s1, intfName1='c0-eth0', intfName2='s1-eth3')
    link_c0s2 = net.addLink(c0, s2, intfName1='c0-eth1', intfName2='s2-eth3')

    net.build()

    link_c0s1.intf1.config(ip='10.0.1.1/24')
    link_c0s2.intf1.config(ip='10.0.1.1/24')

    link_h1s1.intf1.config(mac='00:00:00:00:00:01', ip='10.0.0.1/24')
    link_h2s2.intf1.config(mac='00:00:00:00:00:02', ip='10.0.0.2/24')

    return net


def make_xterm(node: Node, title='Node', display=None, xterm_args=None, cmd='bash'):
    title = '%s: %s' % (title, node.name)
    if xterm_args is None:
        xterm_args = []
    display, tunnel = tunnelX11(node, display)
    if display is None:
        return []
    term = node.popen(['xterm', '-title', title, '-display', display, *xterm_args, '-e',
                       'env TERM=ansi %s' % cmd])
    return [tunnel, term] if tunnel else [term]


if __name__ == '__main__':
    net = create_network()
    net.start()

    c0 = net.get('c0')
    h1 = net.get('h1')
    h2 = net.get('h2')
    s1 = net.get('s1')
    s2 = net.get('s2')

    net.terms += make_xterm(c0, xterm_args=['-geometry', '120x25+50+50'])
    # net.terms += make_xterm(s1, xterm_args=['-geometry', '120x20+50+600'])
    net.terms += make_xterm(h1, xterm_args=['-geometry', '80x20+1050+50'])
    net.terms += make_xterm(h2, xterm_args=['-geometry', '80x20+1050+340'])
    net.terms += make_xterm(s1, xterm_args=['-geometry', '80x20+1050+630'])

    CLI(net)

    net.stop()
    Cleanup.cleanup()
