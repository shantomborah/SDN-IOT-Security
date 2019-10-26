from mininet.topo import Topo

# Topology Definitions
class zodiac(Topo):
	
	def build(self, n=3):
		
		# Add Switches
		switch = self.addSwitch('s1')

		# Add Hosts and Links
		for i in range(n):
			host = self.addHost('h%s' %(i+1), cpu=.5/n)
			self.addLink(host, switch, bw=10, delay='5ms', loss=0, max_queue_size=1000, use_htb=True)

# Topology Dictionary
topos = {'zodiac' : zodiac}
