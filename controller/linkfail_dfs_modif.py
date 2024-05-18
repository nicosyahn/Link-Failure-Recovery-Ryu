from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER,  DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import ether_types
from ryu.lib import mac, ip
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event

from collections import defaultdict
from operator import itemgetter

import os
import random
import time

from ryu.base.app_manager import RyuApp
from ryu.controller.ofp_event import EventOFPSwitchFeatures
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.ofproto.ofproto_v1_2 import OFPG_ANY
from ryu.ofproto.ofproto_v1_3 import OFP_VERSION
from ryu.lib.mac import haddr_to_bin

# Cisco Reference bandwidth = 1 Gbps
REFERENCE_BW = 10000000

DEFAULT_BW = 10000000

MAX_PATHS = 1

idle_time=3000

class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProjectController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topology_api_app = self
        self.datapath_list = {}
        self.datapaths = {}
        self.arp_table = {}
        self.switches = []
        self.hosts = {}
        self.multipath_group_ids = {}
        self.group_ids = []
        self.adjacency = defaultdict(dict)
        self.bandwidths = defaultdict(lambda: defaultdict(lambda: DEFAULT_BW))
        self.en_clear_flow_entry = False
        self.disable_packet_in = False
        self.input_port=0
        self.actions_miss_flow_entry=""
        self.avoid_arp_function = False

    def get_paths(self, src, dst):
        computation_start = time.time()
        if src == dst:
            return [[src]]
        paths = []
        stack = [(src, [src])]
        i = 0
        while stack:
            (node, path) = stack.pop()
            for next in set(self.adjacency[node].keys()) - set(path):
                if next is dst:
                    paths.append(path + [next])
                else:
                    stack.append((next, path + [next]))
                i = i + 1
        print("===== Paths Finding With Link Failure DFS Modification =====")
        print("Iteration : ", i)  
        #print("Path Execution Time : ", time.time() - computation_start)
        return paths

    def get_link_cost(self, s1, s2):
        e1 = self.adjacency[s1][s2]
        e2 = self.adjacency[s2][s1]
        bl = min(self.bandwidths[s1][e1], self.bandwidths[s2][e2])
        ew = REFERENCE_BW/bl
        return ew

    def get_path_cost(self, path):
        cost = 0
        for i in range(len(path) - 1):
            cost += self.get_link_cost(path[i], path[i+1])
        return cost
       
    def get_optimal_paths(self, src, dst):
        paths = self.get_paths(src, dst)
        paths_count = len(paths) if len(
            paths) < MAX_PATHS else MAX_PATHS
        return sorted(paths, key=lambda x: self.get_path_cost(x))[0:(paths_count)]

    def add_ports_to_paths(self, paths, first_port, last_port):
        paths_p = []
        for path in paths:
            p = {}
            in_port = first_port
            for s1, s2 in zip(path[:-1], path[1:]):
                out_port = self.adjacency[s1][s2]
                p[s1] = (in_port, out_port)
                in_port = self.adjacency[s2][s1]
            p[path[-1]] = (in_port, last_port)
            paths_p.append(p)
        return paths_p

    def generate_openflow_gid(self):
        n = random.randint(0, 2**32)
        while n in self.group_ids:
            n = random.randint(0, 2**32)
        return n

    def install_paths(self, src_switch, first_port, dst_switch, last_port, ip_src, ip_dst):
        computation_start = time.time()
        paths = self.get_optimal_paths(src_switch, dst_switch)
        print("Available Paths from Source IP ", ip_src,"to Destination IP ",ip_dst,"is ", paths)
        minimum_cost=0xffff
        pw = []
        for path in paths:
            pw.append(self.get_path_cost(path))
            print ("cost = ", pw[len(pw) - 1], "\n")
            if(pw[len(pw) - 1] <minimum_cost):      minimum_cost = pw[len(pw) - 1]
        sum_of_pw = sum(pw)
        paths_with_ports = self.add_ports_to_paths(paths, first_port, last_port)
        switches_in_paths = set().union(*paths)
        single_path=paths_with_ports[0]
        key_val= [key_val for key_val in single_path.keys()]
        for j in range(len(key_val) ):
            if(j== len(key_val)-1):
                src_sw_dp = self.datapath_list[key_val[j]]
                mac= self.arp_table[ip_src]
                final_out = single_path[key_val[len(key_val)-1]][1]
                src_sw_dp = self.datapath_list[key_val[j]]
                ofp = src_sw_dp.ofproto
                ofp_parser = src_sw_dp.ofproto_parser
                match_ip = ofp_parser.OFPMatch(
                        eth_type=0x0800, 
                        ipv4_src=ip_src, 
                        ipv4_dst=ip_dst
                    )
                match_arp = ofp_parser.OFPMatch(
                        eth_type=0x0806, 
                        arp_spa=ip_src, 
                        arp_tpa=ip_dst
                    ) 
                #src switch flow entry
                actions = [ofp_parser.OFPActionOutput(final_out)]
                self.en_clear_flow_entry=True
                #src switch flow entry
                self.add_flow(src_sw_dp, 32768, match_ip, actions)
                self.add_flow(src_sw_dp, 1, match_arp, actions)
                #First switch in path
                dst_sw_dp = self.datapath_list[key_val[0]]
                final_out = single_path[key_val[0]][0]
                ofp = src_sw_dp.ofproto
                ofp_parser = dst_sw_dp.ofproto_parser
                match_ip = ofp_parser.OFPMatch(
                        eth_type=0x0800, 
                        ipv4_src=ip_dst, 
                        ipv4_dst=ip_src
                    )
                match_arp = ofp_parser.OFPMatch(
                        eth_type=0x0806, 
                        arp_spa=ip_dst, 
                        arp_tpa=ip_src
                    ) 
                #src switch flow entry
                actions = [ofp_parser.OFPActionOutput(final_out)]      
                self.en_clear_flow_entry=True
                #src switch flow entry
                self.add_flow(dst_sw_dp, 32768, match_ip, actions)
                self.add_flow(dst_sw_dp, 1, match_arp, actions)
            else:
                src_sw_dp = self.datapath_list[key_val[j]]
                final_out= self.adjacency[key_val[j]][key_val[j+1]]
                ofp = src_sw_dp.ofproto
                ofp_parser = src_sw_dp.ofproto_parser
                match_ip = ofp_parser.OFPMatch(
                        eth_type=0x0800, 
                        ipv4_src=ip_src, 
                        ipv4_dst=ip_dst
                    )
                match_arp = ofp_parser.OFPMatch(
                        eth_type=0x0806, 
                        arp_spa=ip_src, 
                        arp_tpa=ip_dst
                    )
                #src switch flow entry
                actions = [ofp_parser.OFPActionOutput(final_out)]   
                self.en_clear_flow_entry=True
                #src switch flow entry
                self.add_flow(src_sw_dp, 32768, match_ip, actions)
                self.add_flow(src_sw_dp, 1, match_arp, actions)
        #print( "Path Installation Finished in : ", time.time() - computation_start, "\n")
        return paths_with_ports[0][src_switch][1]

    def add_flow(self, datapath, priority, match, actions, buffer_id=None): #modify flow entry
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            if(self.en_clear_flow_entry):
                mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,idle_timeout=idle_time,#*datapath.id,
                                    instructions=inst)
            else:
                mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            if(self.en_clear_flow_entry):
                mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, idle_timeout=idle_time,#*datapath.id
                                    instructions=inst)
            else:
                mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match,instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER) #create miss flow entry then send it
    def _switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        print ("Switch", datapath.id, "Connected")
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]                               
        self.actions_miss_flow_entry = actions
        self.match_miss_flow_entry = match
        
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        switch = ev.msg.datapath
        for p in ev.msg.body:
            self.bandwidths[switch.id][p.port_no] = p.curr_speed

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)

        # avoid broadcast from LLDP
        if eth.ethertype == 35020:
            return
        if self.disable_packet_in :
            return

        if pkt.get_protocol(ipv4.ipv4):  ##################### inhibit duplicate
            match = parser.OFPMatch(eth_type=eth.ethertype)  
            src_ip = pkt.get_protocol(ipv4.ipv4).src
            dst_ip = pkt.get_protocol(ipv4.ipv4).dst
            dst = eth.dst       #mac address of destination
            src = eth.src       #mac address of source
            dpid = datapath.id
            self.arp_table[src_ip] = src
            h1 = self.hosts[src]        #(dpid, in_port)
            h2 = self.hosts[dst]        #(dpid, in_port)
            out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip)            
            return

        if pkt.get_protocol(ipv6.ipv6):  # Drop the IPV6 Packets.
            match = parser.OFPMatch(eth_type=eth.ethertype)
            actions = []
            self.en_clear_flow_entry=False
            self.add_flow(datapath, 1, match, actions)
            return None

        dst = eth.dst       #mac address of destination
        src = eth.src       #mac address of source
        dpid = datapath.id
        
        if src not in self.hosts:
            self.hosts[src] = (dpid, in_port)
            self.input_port = in_port

        out_port = ofproto.OFPP_FLOOD

        if arp_pkt:
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip
            if arp_pkt.opcode == arp.ARP_REPLY: # IF REPLY IS RECEIVED.
                self.arp_table[src_ip] = src
                #key of arp_table is ip, value is src_mac
                h1 = self.hosts[src]        #(dpid, in_port)
                h2 = self.hosts[dst]        #(dpid, in_port)
                out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip)
            elif arp_pkt.opcode == arp.ARP_REQUEST: #IF REQUEST IS GOING TO INITIATED.
                if dst_ip in self.arp_table:
                    self.arp_table[src_ip] = src
                    dst_mac = self.arp_table[dst_ip]
                    h1 = self.hosts[src]
                    h2 = self.hosts[dst_mac]
                    out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip)
                    
        actions = [parser.OFPActionOutput(out_port)]

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, event):  
        switch = event.switch.dp
        ofp_parser = switch.ofproto_parser

        if switch.id not in self.switches:
            self.switches.append(switch.id)
            self.datapath_list[switch.id] = switch

            req = ofp_parser.OFPPortDescStatsRequest(switch)
            switch.send_msg(req)

    @set_ev_cls(event.EventSwitchLeave, MAIN_DISPATCHER)
    def switch_leave_handler(self, event):
        switch = event.switch.dp.id
        if switch in self.switches:
            del self.switches[switch]
            del self.datapath_list[switch]
            del self.adjacency[switch]      

    @set_ev_cls(event.EventLinkDelete, MAIN_DISPATCHER)
    def link_delete_handler(self, event):
        del self.adjacency[event.link.src.dpid][event.link.dst.dpid]
        new_dic=self.adjacency
        key_val= [key_val for key_val in new_dic.keys()]
        self.send_miss_flow_entry_again()
        return
    
    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER) 
    def link_add_handler(self, event):
        s1 = event.link.src
        s2 = event.link.dst
        self.adjacency[s1.dpid][s2.dpid] = s1.port_no
        self.adjacency[s2.dpid][s1.dpid] = s2.port_no
        self.send_miss_flow_entry_again()  
        
    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]    

    def send_miss_flow_entry_again(self): 
            for datapath in self.datapaths.values():
                [self.remove_flows(datapath, n) for n in [0, 1]]    
            for datapath in self.datapaths.values():
                en_clear_flow_entry =  False
                self.add_flow(datapath, 0, self.match_miss_flow_entry, 
                              self.actions_miss_flow_entry) 

    def remove_flows(self, datapath, table_id):
        """Removing all flow entries."""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        empty_match = parser.OFPMatch()
        instructions = []
        flow_mod = self.remove_table_flows(datapath, table_id,
                                        empty_match, instructions)
        #print ("deleting all flow entries in table ", table_id)
        datapath.send_msg(flow_mod)
    
    def remove_table_flows(self, datapath, table_id, match, instructions):
        """Create OFP flow mod message to remove flows from table."""
        ofproto = datapath.ofproto
        flow_mod = datapath.ofproto_parser.OFPFlowMod(datapath, 0, 0, table_id,
                                                      ofproto.OFPFC_DELETE, 0, 0,
                                                      1,
                                                      ofproto.OFPCML_NO_BUFFER,
                                                      ofproto.OFPP_ANY,
                                                      OFPG_ANY, 0,
                                                      match, instructions)
        return flow_mod           