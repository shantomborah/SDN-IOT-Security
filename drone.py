from mininet.node import CPULimitedHost
from mininet.node import RemoteController
from mininet.link import TCLink
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import setLogLevel

import topology
import networktest

def controller(net, path, tls_data=None):

	# Get controller and switches
	c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)

	# Set switch parameters
	for switch in net.switches:

		# Set TLS certificates
		if tls_data is not None:
			switch.cmd('ovs-vsctl set-ssl %s %s %s' % (tls_data['sc-privkey'], tls_data['sc-cert'], tls_data['sc-cacert']))
			switch.cmd('ovs-vsctl set-controller %s ssl:127.0.0.1:6633' % (switch.name))
		else:
			switch.cmd('ovs-vsctl set-controller %s tcp:127.0.0.1:6633' % (switch.name))

		# Set OF version
		switch.cmd('ovs-vsctl set Bridge %s protocols=OpenFlow13' % (switch.name))

	# Start Controller
	if tls_data is None:
		c0.cmd('ryu-manager %s &' % (path))
	else:
		c0.cmd('ryu-manager --ctl-privkey %s --ctl-cert %s --ca-certs %s %s &' % (tls_data['ctl-privkey'], tls_data['ctl-cert'], tls_data['ctl-cacert'], path))

if __name__ == '__main__':

	# Parameters
	controller_path = 'controllers/traffic_monitor.py'
	tls_data = {'sc-privkey'  : '~/workshop/drone_security/tls/sc-privkey.pem',
		    'sc-cert'     : '~/workshop/drone_security/tls/sc-cert.pem',
		    'sc-cacert'   : '/var/lib/openvswitch/pki/controllerca/cacert.pem',
		    'ctl-privkey' : '~/workshop/drone_security/tls/ctl-privkey.pem',
		    'ctl-cert'    : '~/workshop/drone_security/tls/ctl-cert.pem',
		    'ctl-cacert'  : '/var/lib/openvswitch/pki/switchca/cacert.pem'}

	# Start up the net
	net = Mininet(topo=topology.zodiac(n=3), host=CPULimitedHost, link=TCLink, controller=None)
	net.start()
	controller(net, controller_path, tls_data=tls_data)
	CLI(net)
	net.stop()
