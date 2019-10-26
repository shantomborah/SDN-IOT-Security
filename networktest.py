from mininet.cli import CLI

# Network Test Definitions
def iperf(net, startCLI=False):
	
	# Ping Test
	print "\n\t!!! Ping Test !!!\n"
	net.pingAll()
	
	# Iperf Test
	print "\n\t!!! Iperf Test !!!\n"
	h1, h2 = net.get('h1', 'h2')
	net.iperf((h1, h2))
	
	# Start CLI
	if startCLI:
		print "\n\t!!! Command Line Interface !!!\n"
		CLI(net)
	else:
		print "\n\t!!! Iperf Test Complete !!!\n"

def dos(net, startCLI=False):

	# Iperf Test
	iperf(net)

	# DoS simulation
	h1, h2, h3 = net.get('h1', 'h2', 'h3')
	h2.cmd('ping 10.0.0.1 &')

	# DoS Iperf
	print "\n\t!!! Iperf under DoS!!!\n"
	net.iperf((h1, h3))

	# Start CLI
	if startCLI:
		print "\n\t!!! Command Line Interface !!!\n"
		CLI(net)
	else:
		print "\n\t!!! DoS Simulation Complete !!!\n"

# Network Test Dictionary
tests = {'iperf' : iperf, 'dos' : dos}
