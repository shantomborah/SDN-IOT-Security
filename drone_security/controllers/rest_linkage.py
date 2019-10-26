from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import ofp_event
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.base import app_manager
from ryu.lib import dpid as dpid_lib
from ryu.lib import lacplib
from webob import Response

import switching_hub
import json

hub_instance_name = 'hub_api_app'
url = '/hub/mactable/{dpid}'

class rest_linkage(switching_hub.switching_hub):

	_CONTEXTS = {'lacplib' : lacplib.LacpLib, 'wsgi' : WSGIApplication}

	# Initialization
	def __init__(self, *args, **kwargs):

		# Call superclass __init__ and initialize switch list
		super(rest_linkage, self).__init__(*args, **kwargs)
		self.switches = {}

		# Register hub_controller as wsgi application
		wsgi = kwargs['wsgi']
		wsgi.register(hub_controller, {hub_instance_name : self})

	# Switch features initialization
	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):

		# Call superclass handler
		super(rest_linkage, self).switch_features_handler(ev)

		# Add switch to switch list and initialize empty mactable
		datapath = ev.msg.datapath
		self.switches[datapath.id] = datapath
		self.mac_to_port.setdefault(datapath.id, {})

	# Modify mactable
	def set_mac_to_port(self, dpid, entry):

		# Get mactable and datapath
		mac_table = self.mac_to_port.setdefault(dpid, {})
		datapath = self.switches.get({dpid})

		# Get entry data
		entry_port = entry['port']
		entry_mac = entry['mac']

		# Add entries
		if datapath is not None:
			parser = datapath.ofproto_parser
			if entry_port not in mac_table.values():

				# Add flow entries to and from new entry
				for mac, port in mac_table.items():
					match = parser.OFPMatch(in_port=port, eth_dst=entry_mac)
					actions = [parser.OFPActionOutput(entry_port)]
					self.add_flow(datapath, 1, match, actions)
					match = parser.OFPMatch(in_port=entry_port, eth_dst=mac)
					actions = [parser.OFPActionOutput(port)]
					self.add_flow(datapath, 1, match, actions)

				# Update mactable
				mac_table.update({entry_mac : entry_port})

		# Return mactable
		return mac_table

class hub_controller(ControllerBase):

	# Initialization
	def __init__(self, req, link, data, **config):

		# Call superclass __init__ and get hub application
		super(hub_controller, self).__init__(req, link, data, **config)
		self.hub_app = data[hub_instance_name]

	# Get mactable
	@route('switching_hub', url, methods=['GET'], requirements={'dpid' : dpid_lib.DPID_PATTERN})
	def list_mac_table(self, req, **kwargs):

		# Get hub app and datapath id
		hub = self.hub_app
		dpid = dpid_lib.str_to_dpid(kwargs['dpid'])

		# Check for invalid datapath id
		if dpid not in hub.mac_to_port:
			return Response(status=404)

		# Return required mactable
		mac_table = hub.mac_to_port.get(dpid, {})
		body = json.dumps(mac_table)
		return Response(content_type='application/json', body=body)

	# Put mactable
	@route('switching_hub', url, methods=['PUT'], requirements={'dpid' : dpid_lib.DPID_PATTERN})
	def put_mac_table(self, req, **kwargs):

		# Gaet hub app and datapath id
		hub = self.hub_app
		dpid = dpid_lib.str_to_dpid(kwargs['dpid'])

		# Get new entry
		try:
			new_entry = req.json if req.body else {}
		except ValueError:
			return Response(status=400)

		# Add new entry to mactable
		try:
			mac_table = hub.set_mac_to_port(dpid, new_entry)
			body = json.dumps(mac_table)
			return Response(content_type='application/json', body=body)
		except:
			return Response(status=500)
