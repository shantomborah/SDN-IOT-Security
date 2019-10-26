from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import ofp_event
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.ofproto import ofproto_v1_3
from ryu.base import app_manager

class switching_hub(app_manager.RyuApp):

	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

	# Initialization
	def __init__(self, *args, **kwargs):
		
		# Call superclass __init__ and initialize mactable
		super(switching_hub, self).__init__(*args, **kwargs)
		self.mac_to_port = {}

	# Install table-miss flow entry
	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		
		# Get switch info
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		# Install table-miss entry
		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
		self.add_flow(datapath, 0, match, actions)

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

		# Analyze packets
		pkt = packet.Packet(msg.data)
		eth_pkt = pkt.get_protocol(ethernet.ethernet)
		src = eth_pkt.src
		dst = eth_pkt.dst

		# Update mactable
		in_port = msg.match['in_port']
		self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
		self.mac_to_port[dpid][src] = in_port

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
	def add_flow(self, datapath, priority, match, actions):

		# Get switch info
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		# Compile instruction set
		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

		# Send flow mod message
		mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
		datapath.send_msg(mod)
