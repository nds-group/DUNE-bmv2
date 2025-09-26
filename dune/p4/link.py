from mininet.link import TCIntf, Link

class P4Intf(TCIntf):
    def config(self, *args, **kwargs):
        TCIntf.config(self, *args, **kwargs)
        self.cmd('ip link set dev', self.name, 'mtu 9000')

class P4Link(Link):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault('cls1', P4Intf)
        kwargs.setdefault('cls2', P4Intf)
        Link.__init__(self, *args, **kwargs)

links = { 'p4link' : P4Link }
