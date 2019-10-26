from operator import attrgetter

from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import ofp_event
from ryu.lib import hub

import switching_hub

class traffic_monitor(switching_hub.switching_hub):

	# Initialization
	def __init__(self, *args, **kwargs):

		# Initialize monitor thread and call superclass __init__
		super(traffic_monitor, self).__init__(*args, **kwargs)
		self.datapaths = {}
		self.monitor_thread = hub.spawn(self.monitor)

	# Monitor thread
	def monitor(self):

		# Periodically request stats
		while True:
			for dp in self.datapaths.values():
				self.request_stats(dp)
			hub.sleep(10)

	# Monitor and update connections and disconnections
	@set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
	def state_change_handler(self, ev):

		# Get switch info
		datapath = ev.datapath

		# Check connection status and add/remove datapath
		if ev.state == MAIN_DISPATCHER:
			if datapath.id not in self.datapaths:
				self.logger.debug('register datapath %016x', datapath.id)
				self.datapaths[datapath.id] = datapath
		elif ev.state == DEAD_DISPATCHER:
			if datapath.id in self.datapaths:
				self.logger.debug('deregister datapath %016x', datapath.id)
				del self.datapaths[datapath.id]
	# Request switch stats
	def request_stats(self, datapath):

		# Get switch info
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		# Send flow and port stats request
		flowreq = parser.OFPFlowStatsRequest(datapath)
		portreq = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
		datapath.send_msg(flowreq)
		datapath.send_msg(portreq)

	# Handle flow stats
	@set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
	def flow_stats_handler(self, ev):

		# Title
		body = ev.msg.body
		self.logger.info('    datapath     '
				 'in-port       eth-dst      '
				 'out-port packets   bytes   ')
		self.logger.info('---------------- '
				 '-------- ----------------- '
				 '-------- -------- -------- ')

		# Display data
		for stat in sorted([flow for flow in body if flow.priority == 1], 
		key=lambda flow: (flow.match['in_port'], flow.match['eth_dst'])):
			self.logger.info('%016x %8x %17s %8x %8d %8d', ev.msg.datapath.id, stat.match['in_port'],
			stat.match['eth_dst'], stat.instructions[0].actions[0].port, stat.packet_count, stat.byte_count)

	# Handle port stats
	@set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
	def port_stats_handler(self, ev):

		# Title
		body = ev.msg.body
		self.logger.info('    datapath       port   '
				 'rx-pkts  rx-bytes rx-error '
				 'tx-pkts  tx-bytes tx-error')
		self.logger.info('---------------- -------- '
				 '-------- -------- -------- '
				 '-------- -------- --------')

		# Display data
		for stat in sorted(body, key=attrgetter('port_no')):
			self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d', ev.msg.datapath.id, stat.port_no,
			stat.rx_packets, stat.rx_bytes, stat.rx_errors, stat.tx_packets, stat.tx_bytes, stat.tx_errors)
