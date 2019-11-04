from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import ofp_event
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.ofproto import ofproto_v1_3
from ryu.base import app_manager
from ryu.lib import hub

import copy

class switching_hub(app_manager.RyuApp):

	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

	# Initialization
	def __init__(self, *args, **kwargs):
		
		# Call superclass __init__ and start monitor thread
		super(switching_hub, self).__init__(*args, **kwargs)
		self.monitor_thread = hub.spawn(self.monitor)

		# Initialize tables
		self.mac_to_port = {}
		self.packet_counter = {}
		self.switches = {}
		self.suspects = {}

		# Constants
		self.omega = 8
		self.rho = 5

	# Display packet counts
	def monitor(self):

		# Loop every 10 seconds
		while True:

			# Loop over switches
			for dpid in self.packet_counter:

				# Print data
				counter = copy.deepcopy(self.packet_counter[dpid])
				self.logger.info("Datapath Id %s", dpid)
				S = 0

				# Loop over ports
				for in_port in self.packet_counter[dpid]:
					self.logger.info("Port %s --> %s", in_port, self.packet_counter[dpid][in_port])
					S += self.packet_counter[dpid][in_port]
					self.packet_counter[dpid][in_port] = 0

				# Compare with threshold for DoS detection
				if (S > self.omega) and (dpid not in self.suspects):
					self.suspects[dpid] = counter
					self.dos_detect(dpid)
					continue

				# Process between host or switch attack for existing suspect
				if dpid in self.suspects:
					if S > self.omega:
						self.switch_defender(dpid)
					else:
						self.host_defender(dpid)
					del self.suspects[dpid]

			# Wait 10 seconds
			hub.sleep(10)

	# DoS detector
	def dos_detect(self, dpid):

		# Get switch info
		datapath = self.switches[dpid]
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		match = parser.OFPMatch()

		# Remove table miss entry
		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [])]
		mod = parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst, cookie=1, command=ofproto.OFPFC_MODIFY_STRICT)
		datapath.send_msg(mod)

		# Record suspect
		self.logger.info("DoS detected at switch id %s", dpid)

	# Host defender
	def host_defender(self, dpid):

		# Log message
		self.logger.info("Host defender activated for switch id %s", dpid)

		# Get switch info
		datapath = self.switches[dpid]
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		# Id attackers and block
		for port, count in self.suspects[dpid].items():

			# Threshold comparison
			if count > self.rho:

				# Block
				match = parser.OFPMatch(in_port=port)
				self.add_flow(datapath, 2, match, [], cookie=2)

		# Repair table-miss
		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
		mod = parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst, cookie=1, command=ofproto.OFPFC_MODIFY_STRICT)
		datapath.send_msg(mod)

	# Switch defender
	def switch_defender(self, dpid):

		# Log message
		self.logger.info("Switch defender activated for switch id %s", dpid)

	# Install table-miss flow entry
	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):

		# Get switch info
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		# Add to switch list
		self.switches[datapath.id] = datapath

		# Install table-miss entry
		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
		self.add_flow(datapath, 0, match, actions, cookie=1)

	# Handle received packets
	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def packet_in_handler(self, ev):

		# Get switch info
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		# Get datapath id and add to mactable if not present
		dpid = datapath.id
		self.mac_to_port.setdefault(dpid, {})
		self.packet_counter.setdefault(dpid, {})

		# Analyze packets
		pkt = packet.Packet(msg.data)
		eth_pkt = pkt.get_protocol(ethernet.ethernet)
		src = eth_pkt.src
		dst = eth_pkt.dst

		# Update mactable
		in_port = msg.match['in_port']
		self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
		self.mac_to_port[dpid][src] = in_port

		# Increment packet count
		self.packet_counter[dpid].setdefault(in_port, 0)
		self.packet_counter[dpid][in_port] += 1

		# Check for existing flow entry and flood if not found
		if dst in self.mac_to_port[dpid]:
			out_port = self.mac_to_port[dpid][dst]
		else:
			out_port = ofproto.OFPP_FLOOD

		# Construct action list
		actions = [parser.OFPActionOutput(out_port)]

		# Add flow entry to avoid further floods
		if out_port != ofproto.OFPP_FLOOD:
			match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
			self.add_flow(datapath, 1, match, actions)

		# Send packet out back to switch
		out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=in_port, actions=actions, data=msg.data)
		datapath.send_msg(out)

	# Add a flow entry
	def add_flow(self, datapath, priority, match, actions, cookie=0):

		# Get switch info
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		# Compile instruction set
		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

		# Send flow mod message
		mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst, cookie=cookie)
		datapath.send_msg(mod)
