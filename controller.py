import hashlib
from typing import Dict, List, Tuple

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.controller import Datapath
from ryu.controller.handler import CONFIG_DISPATCHER, DEAD_DISPATCHER, HANDSHAKE_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib.packet import arp, ether_types, ethernet, in_proto, ipv4, packet, tcp
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto.ofproto_v1_3_parser import OFPAction, OFPMatch
from ryu.utils import hex_array
from scapy.layers.l2 import ARP, Ether

from tcp_util import format_tcp, TcpConn, TcpEndpoint


class ControllerApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.datapaths: Dict[str, Datapath] = {}

        self.mac_to_port: Dict[str, Dict[str, int]] = {}
        self.arp_table = {
            "10.0.0.1": "00:00:00:00:00:01",
            "10.0.0.2": "00:00:00:00:00:02"
        }
        self.tcp_connections: Dict[Tuple[str, int, str, int], TcpConn] = {}

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath

        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug(f'register datapath: {datapath.id:016x}')
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug(f'unregister datapath: {datapath.id:016x}')
                del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPErrorMsg,
                [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        self.logger.error(f'OFPErrorMsg received: type={ev.msg.type} code={ev.msg.code} '
                          f'message={hex_array(ev.msg.data)}')

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install the table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, table_id=0, priority=0, match=match, actions=actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.warn(f'packet truncated: only {ev.msg.msg_len} of {ev.msg.total_len} bytes')

        datapath: Datapath = ev.msg.datapath
        dpid: str = datapath.id
        # dpid = format(datapath.id, "d").zfill(16)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port: int = ev.msg.match['in_port']

        pkt = packet.Packet(ev.msg.data)
        pkt_eth: ethernet.ethernet = pkt.get_protocol(ethernet.ethernet)

        # ignore lldp packet
        if pkt_eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        # ignore ipv6 packet
        if pkt_eth.ethertype == ether_types.ETH_TYPE_IPV6:
            return

        self.logger.info(f'packet_in dpid={datapath.id} src={pkt_eth.src} dst={pkt_eth.dst} in_port={in_port}')

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][pkt_eth.src] = in_port

        if pkt_eth.dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][pkt_eth.dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        pkt_arp: arp.arp = pkt.get_protocol(arp.arp)
        if pkt_arp and pkt_arp.opcode == arp.ARP_REQUEST:
            self.logger.info(f'ARP request dpid={dpid} src={pkt_arp.src_ip} dst={pkt_arp.dst_ip}')
            self.arp_respond(datapath, in_port=in_port, pkt_arp=pkt_arp)
            return

        pkt_ipv4: ipv4.ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_tcp: tcp.tcp = pkt.get_protocol(tcp.tcp)

        if pkt_ipv4 and pkt_tcp:
            tcp_id = (pkt_ipv4.dst, pkt_tcp.dst_port, pkt_ipv4.src, pkt_tcp.src_port)
            tcp_reverse_id = (pkt_ipv4.src, pkt_tcp.src_port, pkt_ipv4.dst, pkt_tcp.dst_port)

            self.logger.info(f'Packet in {format_tcp(pkt)}')

            if tcp_id in self.tcp_connections:
                tcp_conn = self.tcp_connections[tcp_id]

                # first data packet from client: add flow and extract
                if pkt_tcp.bits == tcp.TCP_PSH | tcp.TCP_ACK and pkt_tcp.seq == tcp_conn.src_isn + 1:
                    self.logger.info('PSH/ACK received...')
                    # ignore duplicate packets to avoid client side retransmission
                    # if tcp_conn.last_received_seq == pkt_tcp.seq:
                    #     return
                    # tcp_conn.last_received_seq = pkt_tcp.seq
                    self.logger.info('Sending out PSH/ACK...')

                    match: OFPMatch = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                      ipv4_src=pkt_ipv4.src,
                                                      ipv4_dst=pkt_ipv4.dst,
                                                      ip_proto=in_proto.IPPROTO_TCP,
                                                      tcp_src=pkt_tcp.src_port,
                                                      tcp_dst=pkt_tcp.dst_port)

                    actions = [parser.OFPActionOutput(port=out_port)]
                    self.add_flow(datapath, table_id=0, priority=10, match=match, actions=actions)

                    self.send_packet_out(datapath, in_port=in_port, out_port=out_port, pkt=pkt)
                    return

            elif tcp_reverse_id in self.tcp_connections:
                tcp_conn = self.tcp_connections[tcp_reverse_id]

                # SYN-ACK from server: record ISN and forward
                if pkt_tcp.bits == tcp.TCP_SYN | tcp.TCP_ACK:
                    tcp_conn.dst_isn = pkt_tcp.seq

                    self.send_packet_out(datapath, in_port=in_port, out_port=out_port, pkt=pkt)
                    return

                # first data packet from server: add flow and compare
                elif pkt_tcp.bits == tcp.TCP_PSH | tcp.TCP_ACK and pkt_tcp.seq == tcp_conn.dst_isn + 1:
                    match: OFPMatch = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                      ipv4_src=pkt_ipv4.src,
                                                      ipv4_dst=pkt_ipv4.dst,
                                                      ip_proto=in_proto.IPPROTO_TCP,
                                                      tcp_src=pkt_tcp.src_port,
                                                      tcp_dst=pkt_tcp.dst_port)

                    actions = [parser.OFPActionOutput(port=out_port)]
                    self.add_flow(datapath, table_id=0, priority=10, match=match, actions=actions)

                    tcp_payload = pkt.protocols[-1]
                    tcp_payload_digest = hashlib.sha256(tcp_payload).hexdigest()
                    self.logger.info(f'server TCP payload size: {len(tcp_payload)}')
                    if dpid == 2:
                        self.logger.info(f'saving server payload digest: {tcp_payload_digest}')
                        tcp_conn.server_digest = tcp_payload_digest
                    elif dpid == 1:
                        tcp_payload_match = tcp_conn.server_digest == tcp_payload_digest
                        self.logger.info(f'TCP server payload match: {tcp_payload_match}')
                    else:
                        self.logger.warn(f'unknown dpid: {dpid}')

                    self.send_packet_out(datapath, in_port=in_port, out_port=out_port, pkt=pkt)
                    return

            else:
                # SYN from client: initialize TcpConn and forward
                if pkt_tcp.bits == tcp.TCP_SYN:
                    tcp_conn = TcpConn(dst=TcpEndpoint(pkt_eth.dst, pkt_ipv4.dst, pkt_tcp.dst_port),
                                       src=TcpEndpoint(pkt_eth.src, pkt_ipv4.src, pkt_tcp.src_port),
                                       src_isn=pkt_tcp.seq)

                    self.tcp_connections[tcp_id] = tcp_conn

                    self.send_packet_out(datapath, in_port=in_port, out_port=out_port, pkt=pkt)
                    return

        # other protocol
        self.send_packet_out(datapath, in_port=in_port, out_port=out_port, pkt=pkt, buffer_id=ev.msg.buffer_id)
        self.logger.info("other packets")

    def arp_respond(self, datapath: Datapath, in_port: int, pkt_arp: arp.arp):
        mac = self.arp_table.get(pkt_arp.dst_ip)
        if not mac:
            self.logger.info(f'ARP: no match for {pkt_arp.dst_ip}')
            return

        self.logger.info(f'ARP: got {mac} for {pkt_arp.dst_ip}')

        res_eth = Ether(dst=pkt_arp.src_mac, src=mac)
        res_arp = ARP(op=arp.ARP_REPLY, hwsrc=mac, psrc=pkt_arp.dst_ip, hwdst=pkt_arp.src_mac, pdst=pkt_arp.src_ip)
        res = res_eth / res_arp
        res = res.build()

        self.send_packet_out(datapath, out_port=in_port, pkt=res)

    def send_packet_out(self, datapath: Datapath, buffer_id: int = None, in_port: int = None,
                        actions: List[OFPAction] = None, out_port: int = None, pkt=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if buffer_id is None:
            buffer_id = ofproto.OFP_NO_BUFFER
        if in_port is None:
            in_port = ofproto.OFPP_CONTROLLER
        if actions is None:
            actions = [parser.OFPActionOutput(port=out_port)]

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id, in_port=in_port,
                                  actions=actions, data=pkt)

        self.logger.info(f'Packet out dpid={datapath.id} in_port={in_port} actions={actions} '
                         f'buffer_id={buffer_id}')
        return datapath.send_msg(out)

    def add_flow(self, datapath: Datapath, table_id: int, priority: int, match: OFPMatch,
                 actions: List[OFPAction], buffer_id: int = None, **kwargs):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if buffer_id is None:
            buffer_id = ofproto.OFP_NO_BUFFER

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(datapath=datapath,
                                table_id=table_id,
                                buffer_id=buffer_id,
                                priority=priority,
                                match=match,
                                instructions=inst,
                                **kwargs)

        self.logger.info(f'Add flow dpid={datapath.id} priority={priority} match={match} '
                         f'actions={actions} buffer_id={buffer_id} {kwargs}')
        return datapath.send_msg(mod)

    def delete_flow(self, datapath: Datapath, priority: int, match: OFPMatch, **kwargs):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(datapath=datapath,
                                priority=priority,
                                match=match,
                                out_port=ofproto.OFPP_ANY,
                                out_group=ofproto.OFPG_ANY,
                                command=ofproto.OFPFC_DELETE,
                                **kwargs)

        self.logger.info(f'Delete flow dpid={datapath.id} priority={priority} match={match} '
                         f'{kwargs}')
        return datapath.send_msg(mod)
