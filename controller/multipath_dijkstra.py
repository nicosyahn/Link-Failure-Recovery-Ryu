from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import in_proto
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import icmp
from ryu.lib.packet import ether_types
from ryu.lib import mac
from ryu.lib import hub

from ryu.topology import event
from ryu.topology import switches
from collections import defaultdict
from operator import itemgetter

import time
import copy
import random

# switches
switches = []

# mymac[srcmac]->(switch, port)
mymac = {}

# adjacency map [sw1][sw2]->port from sw1 to sw2
adjacency = defaultdict(lambda: defaultdict(lambda: None))


def minimum_distance(distance, Q):
    min = float('inf')
    node = 0
    for v in Q:
        if distance[v] < min:
            min = distance[v]
            node = v
    return node

def path(previous, node_start, node_end):
    r=[]
    p=node_end
    r.append(p)
    q=previous[p]
    while q is not None:
        if q == node_start:
            r.append(q)
            break
        p=q
        r.append(p)
        q=previous[p]
 
    r.reverse()
    if node_start==node_end:
        path=[node_start]
    else:
        path=r
    return r
 
def dijkstra(graph,node_start, node_end=None):
    print("=== Running Multipath Dijkstra algorithm ===")
    computation_start = time.time()
    #print("Source : ", node_start, "destination : ", node_end)
    distances = {}     
    previous = {}  
   
    distances = defaultdict(lambda: float('Inf'))
    previous = defaultdict(lambda: None)
    
    i = 0
    
    distances[node_start]=0
    Q=set(switches)
   
    while len(Q)>0:
        u = minimum_distance(distances, Q)
        Q.remove(u)  
        
        for p in switches:
            if adjacency[u][p] != None:
                w = 1
                if distances[u] + w < distances[p]:
                    distances[p] = distances[u] + w
                    previous[p] = u
            i = i + 1

    print("iterasi : ", i)
    print("Path Execution Time : ", time.time() - computation_start)
    if node_end:
        return {'cost': distances[node_end],
                'path': path(previous, node_start, node_end)}
    else:
        return (distances, previous)
    
def get_path(src,dst,first_port,final_port,max_k=2):
    #print("YenKSP is called")
    computation_start = time.time()
    print("src=",src," dst=",dst)
    adjacency2 = defaultdict(lambda:defaultdict(lambda:None))
    
    distances, previous = dijkstra(adjacency,src)
    A = [{'cost': distances[dst],
            'path': path(previous, src, dst)}]
    B = []
    #print "distances=", distances
    #print  "previous=", previous
    #print "A=", A
    
    if not A[0]['path']: return A
    
    try:
        for k in range(1, max_k):
            adjacency2=copy.deepcopy(adjacency)
            #print "k=", k, " adjacency2=", adjacency2
            for i in range(0, len(A[-1]['path']) - 1):
                node_spur = A[-1]['path'][i]
                path_root = A[-1]['path'][:i+1]
            #print "node_spur=", node_spur, " path_root=", path_root
        
                for path_k in A:
                    curr_path = path_k['path']
                    #print "curr_path=", curr_path, " i=", i
                    if len(curr_path) > i and path_root == curr_path[:i+1]:
                        adjacency2[curr_path[i]][curr_path[i+1]]=None
                        #print "link[", curr_path[i],"][", curr_path[i+1], "] is removed"
            
                path_spur = dijkstra(adjacency2, node_spur, dst)
                #print "path_spur=", path_spur
    
                if path_spur['path']:
                    path_total = path_root[:-1] + path_spur['path']
                    #print "path_total=", path_total
                    dist_total = distances[node_spur] + path_spur['cost']
                    #print ("dist_total=", path_total)
                    potential_k = {'cost': dist_total, 'path': path_total}
                    #print "potential_k=", potential_k
    
                    if not (potential_k in B):
                        B.append(potential_k)
                        #print "B=", B
    
                if len(B):
                    B = sorted(B, key=itemgetter('cost'))
                    #print("after sorting, B=", B)
                    A.append(B[0])
                    B.pop(0)
                    #print "after poping out the first element, B=", B, " A=", A
                else:
                    break
    except:
        pass
 
    tmp=[]
    #print("YenKSP->")
    for path_k in A:
        #print(path_k)
        tmp.append(path_k)
 
    min_path = min(tmp, key=lambda x: x['cost'])
    for tmp in min_path:
        print("Chosen Path=", min_path)
    
    chosen_path = min_path['path']
    # Now add the ports
    r = []
    in_port = first_port
    for s1, s2 in zip(chosen_path[:-1], chosen_path[1:]):
        out_port = adjacency[s1][s2]
        r.append((s1, in_port, out_port))
        in_port = adjacency[s2][s1]
    r.append((dst, in_port, final_port))
    print("Path installation finished : ", time.time() - computation_start)
    return r, distances[dst]


class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProjectController, self).__init__(*args, **kwargs)

        # maps a mac to its port in switch
        self.mac_to_port = {}

        # ryu datapath object of switch
        self.datapath_list = {}

        # Maps an IP address to the corresponding MAC address
        self.arp_table = {}

        self.replied = []

    def ping_packet_handler(self, pkt):
        '''
            Handler function when ping packet arrives.
            Extracts the data from the packet and calculates the latency.
        '''
        icmp_packet = pkt.get_protocol(icmp.icmp)
        echo_payload = icmp_packet.data
        payload = echo_payload.data
        info = payload.split(';')
        s1 = info[0]
        s2 = info[1]
        latency = (time.time() - float(info[2])) * 1000  # in ms
        # print "s%s to s%s latency = %f ms" % (s1, s2, latency)
        delay[int(s1)][int(s2)] = latency

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=0, instructions=inst)
        datapath.send_msg(mod)

    def install_path(self, ev, p, src_ip, dst_ip):
        '''
            Install openflow rules using IP addresses for routing
        '''
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser

        for sw, in_port, out_port in p:
            # print src_ip, "->", dst_ip, "via ", sw, " out_port=", out_port
            match_ip = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=src_ip,
                ipv4_dst=dst_ip
            )
            match_arp = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_ARP,
                arp_spa=src_ip,
                arp_tpa=dst_ip
            )
            actions = [parser.OFPActionOutput(out_port)]
            datapath = self.datapath_list[int(sw)]
            self.add_flow(datapath, 1, match_ip, actions)
            self.add_flow(datapath, 1, match_arp, actions)

    def send_arp(self, datapath, eth_dst, eth_src, dst_ip, src_ip, opcode, port):
        ''' Send ARP Packet. '''
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(port)]
        arp_packet = packet.Packet()

        arp_packet.add_protocol(ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_ARP,
            dst=eth_dst,
            src=eth_src))
        arp_packet.add_protocol(arp.arp(
            opcode=opcode,
            src_mac=eth_src,
            src_ip=src_ip,
            dst_mac=eth_dst,
            dst_ip=dst_ip))

        arp_packet.serialize()

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions, data=arp_packet.data)
        datapath.send_msg(out)

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
        ipv6_pkt = pkt.get_protocol(ipv6.ipv6)

        # avoid broadcast from LLDP
        if eth.ethertype == 35020:
            return

        # print pkt
        if ipv6_pkt:  # Drop the IPV6 Packets.
            match = parser.OFPMatch(eth_type=eth.ethertype)
            self.add_flow(datapath, 1, match, [])
            return None

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})

        self.mac_to_port[dpid][src] = in_port

        if src not in list(mymac.keys()):
            mymac[src] = (dpid, in_port)

        out_port = ofproto.OFPP_FLOOD

        if arp_pkt:
            # print dpid, pkt
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip
            if arp_pkt.opcode == arp.ARP_REPLY:
                self.arp_table[src_ip] = src
                path, d = get_path(mymac[src][0], mymac[dst][
                                0], mymac[src][1], mymac[dst][1])
                reverse, d = get_path(mymac[dst][0], mymac[src][
                                    0], mymac[dst][1], mymac[src][1])
                self.install_path(ev, path, src_ip, dst_ip)
                self.install_path(ev, reverse, dst_ip, src_ip)
                out_port = path[0][2]
            elif arp_pkt.opcode == arp.ARP_REQUEST:
                if dst_ip in self.arp_table:
                    dst_mac = self.arp_table[dst_ip]
                        # always try to reply arp requests first
                    path, d = get_path(mymac[src][0], mymac[dst_mac][
                                0], mymac[src][1], mymac[dst_mac][1])
                    reverse, d = get_path(mymac[dst_mac][0], mymac[src][
                                        0], mymac[dst_mac][1], mymac[src][1])
                    self.install_path(ev, path, src_ip, dst_ip)
                    self.install_path(ev, reverse, dst_ip, src_ip)
                    out_port = path[0][2]

        actions = [parser.OFPActionOutput(out_port)]

        # print pkt

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(event.EventSwitchEnter, MAIN_DISPATCHER)
    def _switch_enter_handler(self, ev):
        switch = ev.switch.dp
        if switch.id not in switches:
            switches.append(switch.id)
            self.datapath_list[switch.id] = switch

    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def _link_add_handler(self, ev):
        s1 = ev.link.src
        s2 = ev.link.dst
        adjacency[s1.dpid][s2.dpid] = s1.port_no
        adjacency[s2.dpid][s1.dpid] = s2.port_no
        # print s1.dpid, s2.dpid
