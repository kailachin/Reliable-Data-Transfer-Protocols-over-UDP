
from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from os_ken.controller.handler import set_ev_cls
from os_ken.ofproto import ofproto_v1_4
from os_ken.lib.packet import packet
from os_ken.lib.packet import ethernet
from os_ken.lib.packet import in_proto
from os_ken.lib.packet import arp
from os_ken.lib.packet import ipv4
from os_ken.lib.packet import tcp
from os_ken.lib.packet.tcp import TCP_SYN
from os_ken.lib.packet.tcp import TCP_FIN
from os_ken.lib.packet.tcp import TCP_RST
from os_ken.lib.packet.tcp import TCP_ACK
from os_ken.lib.packet.ether_types import ETH_TYPE_IP, ETH_TYPE_ARP
import datetime

class Nat(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Nat, self).__init__(*args, **kwargs)
        self.lmac = '00:00:00:00:00:10'
        self.emac = '00:00:00:00:00:20'
        self.hostmacs = {
                '10.0.1.100': '00:00:00:00:00:01',
                '10.0.2.100': '00:00:00:00:00:02',
                '10.0.2.101': '00:00:00:00:00:03',
                }
        self.nat_table = {}
        self.rev_nat_table = {}
        self.timeout = 10
        self.current_time = datetime.datetime.now()
        self.next_port = 1

    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        return out

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def features_handler(self, ev):
        dp = ev.msg.datapath
        ofp, psr = (dp.ofproto, dp.ofproto_parser)
        acts = [psr.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, psr.OFPMatch(), acts)

    def add_flow(self, dp, prio, match, acts, buffer_id=None, delete=False):
        ofp, psr = (dp.ofproto, dp.ofproto_parser)
        bid = buffer_id if buffer_id is not None else ofp.OFP_NO_BUFFER
        if delete:
            mod = psr.OFPFlowMod(datapath=dp, command=dp.ofproto.OFPFC_DELETE,
                    out_port=dp.ofproto.OFPP_ANY, out_group=dp.ofproto.OFPG_ANY,
                    match=match)
        else:
            ins = [psr.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, acts)]
            mod = psr.OFPFlowMod(datapath=dp, buffer_id=bid, priority=prio,
                                match=match, instructions=ins)
        dp.send_msg(mod)

        #print(f"Flow added: OUT {iph.src}:{tcph.src_port} → {iph.dst}:{tcph.dst_port}")
        #print(f"Flow added: IN {iph.dst}:{tcph.dst_port} → {iph.src}:{tcph.src_port}")

        #print(f"Installing flow, current NAT table: {self.nat_table}")

    def remove_expired_entries(self):
        current_time = datetime.datetime.now()
        expired_entry = None

        # Check for expired entries in nat_table
        for (priv_ip, priv_port), (pub_ip, pub_port, timestamp) in list(self.nat_table.items()):
            if (current_time - timestamp).total_seconds() > self.timeout:
                expired_entry = (priv_ip, priv_port)
                break
    
        # Remove expired entries
        if expired_entry:
            pub_ip, pub_port, _ = self.nat_table.pop(expired_entry)
            self.rev_nat_table.pop((pub_ip, pub_port), None)
            return pub_port

        return None

        #print(f"NAT table after removing expired entries: {self.nat_table}")

        #for (priv_ip, priv_port), (pub_ip, pub_port, timestamp) in list(self.nat_table.items()):
            #if (current_time - timestamp).seconds > self.timeout:
                #expired_entry = (priv_ip, priv_port)
                
                #pub_ip, pub_port, _ = self.nat_table.pop(expired_entry, (None, None, None))
                #if pub_ip and pub_port:
                    #self.rev_nat_table.pop((pub_ip, pub_port), None)
                    #break
        #if expired_entry:
            #pub_ip, pub_port, _ = self.nat_table[expired_entry]
            #del self.nat_table[expired_entry]
            #del self.rev_nat_table[(pub_ip, pub_port)]


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        in_port, pkt = (msg.match['in_port'], packet.Packet(msg.data))
        dp = msg.datapath
        ofp, psr, did = (dp.ofproto, dp.ofproto_parser, format(dp.id, '016d'))
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ETH_TYPE_ARP:
            ah = pkt.get_protocols(arp.arp)[0]
            if ah.opcode == arp.ARP_REQUEST:
                print('ARP', pkt)
                ar = packet.Packet()
                ar.add_protocol(ethernet.ethernet(ethertype=eth.ethertype,
                    dst=eth.src,
                    src=self.emac if in_port == 1 else self.lmac))
                ar.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                    src_mac=self.emac if in_port == 1 else self.lmac,
                    dst_mac=ah.src_mac, src_ip=ah.dst_ip, dst_ip=ah.src_ip))
                out = self._send_packet(dp, in_port, ar)
                print('ARP Rep', ar)
                dp.send_msg(out)
            return
 

        if eth.ethertype == ETH_TYPE_IP:
            iph = pkt.get_protocol(ipv4.ipv4)
            tcph = pkt.get_protocol(tcp.tcp)
            if not tcph:
                return

            #handle packets from private network
            if in_port != 1:
                priv_key = (iph.src, tcph.src_port)
                pub_ip = "10.0.1.100"  

                #check if need to create a new NAT entry
                if priv_key not in self.nat_table:
                    freed_port = self.remove_expired_entries()
                    
                    if freed_port:
                        pub_port = freed_port
                    else:
                        while self.next_port <= 65535:
                            if (pub_ip, self.next_port) not in self.rev_nat_table:
                                pub_port = self.next_port
                                self.next_port += 1
                                break
                            self.next_port += 1
                        else:
                            #no ports available
                            self.send_rst(dp, iph, tcph, in_port)
                            return

                    #new NAT entry
                    self.nat_table[priv_key] = (pub_ip, pub_port, datetime.datetime.now())
                    self.rev_nat_table[(pub_ip, pub_port)] = priv_key
                    print(f"NAT entry created: {priv_key} → {pub_ip}:{pub_port}")


                pub_ip, pub_port, _ = self.nat_table[priv_key]

                #flow(private -> public)
                match_out = psr.OFPMatch(
                    in_port=in_port,
                    eth_type=ETH_TYPE_IP,
                    ipv4_src=iph.src,
                    ipv4_dst=iph.dst,
                    ip_proto=in_proto.IPPROTO_TCP,
                    tcp_src=tcph.src_port,
                    tcp_dst=tcph.dst_port
                )
                actions_out = [
                    psr.OFPActionSetField(ipv4_src=pub_ip),
                    psr.OFPActionSetField(tcp_src=pub_port),
                    psr.OFPActionOutput(1)  
                ]
                self.add_flow(dp, 1, match_out, actions_out)

                #flow for incoming packets (public -> private)
                match_in = psr.OFPMatch(
                    in_port=1,  
                    eth_type=ETH_TYPE_IP,
                    ipv4_src=iph.dst,
                    ipv4_dst=pub_ip,
                    ip_proto=in_proto.IPPROTO_TCP,
                    tcp_src=tcph.dst_port,
                    tcp_dst=pub_port
                )
                actions_in = [
                    psr.OFPActionSetField(ipv4_dst=iph.src),
                    psr.OFPActionSetField(tcp_dst=tcph.src_port),
                    psr.OFPActionOutput(in_port)  
                ]
                self.add_flow(dp, 1, match_in, actions_in)

                # Debugging prints for match conditions
                print(f"Match Out: {match_out}")
                print(f"Match In: {match_in}")


                #send the packet with NAT translation
                #new_pkt = packet.Packet()
                #new_pkt.add_protocol(ethernet.ethernet(
                #    ethertype=eth.ethertype,
                #    dst=eth.dst,
                #    src=self.emac))
                #new_pkt.add_protocol(ipv4.ipv4(
                #    src=pub_ip,
                #    dst=iph.dst,
                #    proto=iph.proto))
                #new_pkt.add_protocol(tcp.tcp(
                #    src_port=pub_port,
                #    dst_port=tcph.dst_port,
                #    seq=tcph.seq,
                #    ack=tcph.ack,
                #    bits=tcph.bits))
                #dp.send_msg(self._send_packet(dp, 1, new_pkt))

                out = psr.OFPPacketOut(
                    datapath = dp,
                    buffer_id=ofp.OFP_NO_BUFFER,
                    in_port=in_port,
                    actions=actions_out,  
                    data=msg.data 
                    )
                
                
                dp.send_msg(out)
                return

            #handle packets from public network (h1)
            else:
                pub_key = (iph.dst, tcph.dst_port)
                if pub_key in self.rev_nat_table:
                    priv_ip, priv_port = self.rev_nat_table[pub_key]
                    
                    #print(f"Reverse NAT hit: {pub_key} → {priv_ip}:{priv_port}")

                    # Update NAT entry timestamp
                    self.nat_table[(priv_ip, priv_port)] = (pub_key[0], pub_key[1], datetime.datetime.now())
                    
                    # Send packet to private host
                    #new_pkt = packet.Packet()
                    #new_pkt.add_protocol(ethernet.ethernet(
                    #    ethertype=eth.ethertype,
                    #    dst=self.hostmacs.get(priv_ip, 'ff:ff:ff:ff:ff:ff'),
                    #    src=self.lmac))
                    #new_pkt.add_protocol(ipv4.ipv4(
                    #    src=iph.src,
                    #    dst=priv_ip,
                    #    proto=iph.proto))
                    #new_pkt.add_protocol(tcp.tcp(
                    #    src_port=tcph.src_port,
                    #    dst_port=priv_port,
                    #    seq=tcph.seq,
                    #    ack=tcph.ack,
                    #    bits=tcph.bits))
                    
                    #find the correct private host
                    out_port = 2 if priv_ip == '10.0.2.100' else 3  #port 2 for h2, port 3 for h3
                    out = psr.OFPPacketOut(
                        datapath=dp,
                        buffer_id=ofp.OFP_NO_BUFFER,
                        in_port=in_port,
                        actions=[psr.OFPActionOutput(out_port)],
                        data=msg.data  
                    )
                    #dp.send_msg(self._send_packet(dp, out_port, new_pkt))
                    dp.send_msg(self._send_packet(dp, out_port, msg.data))
                    return

        #if packet doesn't match any rules
        #actions = [psr.OFPActionOutput(ofp.OFPPC_NO_FWD)]
        drop_match = psr.OFPMatch(in_port=in_port, eth_type=ETH_TYPE_IP)
        self.add_flow(dp, 0, drop_match, []) 
        actions = [psr.OFPActionOutput(ofp.OFPP_CONTROLLER)]
        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        out = psr.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                              in_port=in_port, actions=actions, data=data)
        dp.send_msg(out)


 
    def send_rst(self, dp, iph, tcph, in_port):
        rst_pkt = packet.Packet()
        rst_pkt.add_protocol(ethernet.ethernet(
            ethertype=ETH_TYPE_IP,
            src=self.lmac,
            dst=self.hostmacs.get(iph.src)))
        rst_pkt.add_protocol(ipv4.ipv4(
            src=iph.dst,
            dst=iph.src,
            proto=6))
        rst_pkt.add_protocol(tcp.tcp(
            src_port=tcph.dst_port,
            dst_port=tcph.src_port,
            bits=TCP_RST | TCP_ACK,
            seq=0,
            ack=tcph.seq + 1))
        out = self._send_packet(dp, in_port, rst_pkt)
        dp.send_msg(out)