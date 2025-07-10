from mininet.node import Host, Switch, Controller

class P4Host(Host):
    def config(self, **_params):
        r = Host.config(self, **_params)

        intf = self.defaultIntf()
        for off in ['rx', 'tx', 'sg']:
            cmd = f'/sbin/ethtool --offload {intf} {off} off'
            self.cmd(cmd)

        # disable IPv6
        self.cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=1')
        self.cmd('sysctl -w net.ipv6.conf.default.disable_ipv6=1')
        self.cmd('sysctl -w net.ipv6.conf.lo.disable_ipv6=1')

        return r

hosts = { 'p4host' : P4Host }

class P4SimpleSwitchGRPC(Switch):
    def __init__(self, name, **kwargs):
        Switch.__init__(self, name, **kwargs)
        print('Switch init')
                    model_config=self.model_assignment[sw],
                    model_dir=self.models_dir,
                    log_dir=self.log_dir,
                    pcap_dir=self.pcap_dir
 
    def config(self):
        print('Switch config')

    def start(self, controllers):
        print('Switch start')

    def stop(self):
        print('Switch stop')

    def connected(self):
        print('Switch connected')


switches = { 'p4simpleswitchgrpc' : P4SimpleSwitchGRPC }

class P4Controller(Controller):
    def __init__(self, name, **kwargs):
        Controller.__init__(self, name, **kwargs)
        print('Controller init')

    #def config(self, grpc_port, thrift_port, device_id, classe):
    #    print('Controller config')
    #    pass

    def start(self):
        print('Controller start')
        pass

    def stop(self):
        print('Controller stop')
        pass


controllers = { 'p4controller' : P4Controller }
