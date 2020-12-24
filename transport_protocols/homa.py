#!/usr/bin/env python2

from scapy.all import *
from nanoPU_sim import * # Note the cyclic dependency here!
from headers import *
from sim_utils import *
import operator
from heapq import *

HOMA_PROTO = 0x98

def count_ones(num):
    """ Count the number of ones in the binary representation of num
    """
    result = 0
    while num != 0:
        if num & 1:
            result += 1
        num = num >> 1
    return result

class HOMA(Packet):
    name = "HOMA"
    fields_desc = [
        FlagsField("flags", 0, 8, ["DATA", "ACK", "GRANT",
                                   "F1", "F2", "F3", "F4", "F5"]),
        ShortField("src_context", 0),
        ShortField("dst_context", 0),
        ShortField("tx_msg_id", 0),
        ShortField("msg_len", 0),
        ShortField("pkt_offset", 0), # or should this be byte offset? Or should the header include both?
        ShortField("prio", 0),
        ShortField("grant_offset", 0),
        ShortField("grant_prio", 0),
        XBitField("_pading",0,13*8)
    ]

bind_layers(IP, HOMA, proto=HOMA_PROTO)

class ScheduledMsg(object):
    def __init__(self, remaining_pkts, msg_len_pkts, msg_len, src_ip,
                 src_context, dst_context, tx_msg_id):
        self.last_grant_offset = Simulator.rtt_pkts
        self.remaining_pkts = remaining_pkts
        self.msg_len_pkts = msg_len_pkts
        self.msg_len = msg_len
        self.src_ip = src_ip
        self.src_context = src_context
        self.dst_context = dst_context
        self.tx_msg_id = tx_msg_id

    def __lt__(self, other):
        """Highest priority element is the one with the fewest remaining pkts"""
        return self.remaining_pkts < other.remaining_pkts

#####
# Programmable Elements
#####

class IngressPipe(object):
    """P4 programmable ingress pipeline"""
    def __init__(self, net_queue, assemble_queue):
        self.env = Simulator.env
        self.logger = Logger()
        self.net_queue = net_queue
        self.assemble_queue = assemble_queue

        # TODO(sibanez): define state variables
        # received_bitmap:
        # - used to track which pkts have already been received for each msg
        # - {rx_msg_id => pkt_bitmap}
        self.received_bitmap = {}
        # scheduled_msg_pqs:
        # - used to store priority queue (per sender) that sorts
        #   scheduled msgs based on remaining pkt count
        # - {src_ip => priority queue}
        self.scheduled_msg_pqs = {}
        # scheduled_msgs:
        # - used to store reference to each scheduled msg in the pqs
        # - {rx_msg_id => scheduled msg reference}
        self.scheduled_msgs = {}

        self.env.process(self.start())

    @staticmethod
    def init_params():
        pass

    def log(self, msg):
        self.logger.log("IngressPipe: {}".format(msg))

    ########
    # Methods to wire up events/externs
    ########

    def init_getRxMsgInfo(self, getRxMsgInfo):
        self.getRxMsgInfo = getRxMsgInfo

    def init_deliveredEvent(self, deliveredEvent):
        self.deliveredEvent = deliveredEvent

    def init_creditToBtxEvent(self, creditToBtxEvent):
        self.creditToBtxEvent = creditToBtxEvent

    def init_ctrlPktEvent(self, ctrlPktEvent):
        self.ctrlPktEvent = ctrlPktEvent

    def grantMsg(self, rx_msg_id, is_new_msg, remaining_pkts, msg_len_pkts, msg_len,
                 src_ip, src_context, dst_context, tx_msg_id):
        """
        Performs the following:
        - Inserts entry to scheduled_msgs PQs if this is a new msg
        - Updates entry with new remaining_pkts if msg already in a PQ
          - Updates order of PQ entries
        - Determines which msg to grant:
          - Find the highest priority msg for which (max_grantable_offset - last_grant_offset > 0)
            && (last_grant_offset < msg_len_pkts)
          - It could be that the current msg is active
          - Or it could be that the msg has already been fully granted,
            so we need to grant a different one
        - Updates the entry of the chosen msg with the new grant offset
        - Removes the msg from the PQ if this is the last grant that must be sent
        - Returns the info needed to generate GRANT for selected msg
        """
        # self.scheduled_msg_pqs is a dict mapping src_ip => PQ sorting ScheduledMsg objects
        # self.scheduled_msgs is a dict mapping rx_msg_id => a ScheduledMsg object
        if is_new_msg:
            # Create new ScheduledMsg and add it to both self.scheduled_msg_pqs and self.scheduled_msgs
            msg = ScheduledMsg(remaining_pkts, msg_len_pkts, msg_len, src_ip,
                               src_context, dst_context, tx_msg_id)
            if src_ip not in self.scheduled_msg_pqs:
                self.scheduled_msg_pqs[src_ip] = []
            heappush(self.scheduled_msg_pqs[src_ip], msg)
            self.scheduled_msgs[rx_msg_id] = msg
        else:
           # Try to update remaining_pkt count for the given msg.
           # The msg might not be here if it has been fully granted
           if rx_msg_id in self.scheduled_msgs:
               self.scheduled_msgs[rx_msg_id].remaining_pkts = remaining_pkts
               # Sort the appropriate PQ
               heapify(self.scheduled_msg_pqs[src_ip])

        # Determine which msg to generate GRANT for (if any)
        candidate_msgs = []
        for src_ip, pq in self.scheduled_msg_pqs.items():
            if len(pq) > 0:
                heappush(candidate_msgs, pq[0])
        genGRANT = False
        g_dst_ip = None
        g_dst_context = None
        g_src_context = None
        g_tx_msg_id = None
        g_msg_len = None
        g_offset = None
        g_prio = None
        # Consider at most MAX_ACTIVE_MSGS msgs for GRANT generation
        for i in range(min(len(candidate_msgs), MAX_ACTIVE_MSGS)):
            msg = heappop(candidate_msgs)
            next_grant_offset = msg.msg_len_pkts - msg.remaining_pkts + Simulator.rtt_pkts
            is_grantable = (next_grant_offset > msg.last_grant_offset) and \
                           (msg.last_grant_offset < msg.msg_len_pkts)
            if is_grantable:
                genGRANT = True
                g_dst_ip = msg.src_ip
                g_dst_context = msg.src_context
                g_src_context = msg.dst_context
                g_tx_msg_id = msg.tx_msg_id
                g_msg_len = msg.msg_len
                g_offset = next_grant_offset
                g_prio = i + NUM_UNSCHEDULED_PRIOS
                # Update grant offset msg state
                msg.last_grant_offset = next_grant_offset
                # Remove msg from scheduled_msg_pqs and scheduled_msgs if this is the
                # last GRANT that needs to be sent.
                is_last_grant = grant_offset >= msg.msg_len_pkts
                if is_last_grant:
                    heappop(self.scheduled_msg_pqs[msg.src_ip])
                    del self.scheduled_msgs[msg.rx_msg_id]
                break

        return genGRANT, g_dst_ip, g_dst_context, g_src_context, g_tx_msg_id, g_msg_len, g_offset, g_prio

    def start(self):
        """Receive and process packets from the network
        """
        while not Simulator.complete:
            # wait for a pkt from the network
            pkt = yield self.net_queue.get()

            # defaults
            tx_msg_id = pkt[Homa].tx_msg_id
            pkt_offset = pkt[Homa].pkt_offset
            msg_len = pkt[Homa].msg_len
            msg_len_pkts = compute_num_pkts(msg_len)

            if pkt[Homa].flags.DATA:
                rx_msg_id, is_new_msg = self.getRxMsgInfo(pkt[IP].src,
                                                          pkt[Homa].src_context,
                                                          pkt[Homa].tx_msg_id,
                                                          pkt[Homa].msg_len,
                                                          pkt[Homa].pkt_offset)

                genACK = True
                grant_data = (False,) # default

                ####
                # Generate appropriate GRANT pkt, if any
                ####

                if msg_len_pkts > Simulator.rtt_pkts:
                    # This is a scheduled msg
                    # Compute remaining pkt count
                    if is_new_msg:
                        # allocate bitmap for new msg
                        self.received_bitmap[rx_msg_id] = (1 << pkt_offset)
                    else:
                        assert rx_msg_id in self.received_bitmap, "IngressPipe: rx_msg_id ({}) not in received_bitmap".format(rx_msg_id)
                        # mark pkt as received
                        self.received_bitmap[rx_msg_id] = self.received_bitmap[rx_msg_id] | (1 << pkt_offset)
                    remaining_pkts = msg_len_pkts - count_ones(self.received_bitmap[rx_msg_id])                     

                    # Find msg to GRANT (if any)
                    grant_data = self.grantMsg(rx_msg_id,
                                               is_new_msg,
                                               remaining_pkts,
                                               msg_len_pkts,
                                               msg_len,
                                               pkt[IP].src,
                                               pkt[Homa].src_context,
                                               pkt[Homa].dst_context,
                                               pkt[Homa].tx_msg_id)

                # For unscheduled msgs, just send an ACK for each DATA pkt
                self.ctrlPktEvent(genACK, dst_ip, dst_context, src_context,
                                  tx_msg_id, msg_len, pkt_offset,
                                  *grant_data)

                # Send pkt to Reassembly module
                data = (ReassembleMeta(rx_msg_id,
                                       pkt[IP].src,
                                       pkt[Homa].src_context,
                                       pkt[Homa].tx_msg_id,
                                       pkt[Homa].msg_len,
                                       pkt[Homa].pkt_offset),
                        pkt[Homa].payload)
                self.assemble_queue.put(data)

            else: # Either an ACK and/or GRANT
                if pkt[Homa].flags.ACK:
                    self.deliveredEvent(tx_msg_id, pkt_offset, msg_len)
                if pkt[Homa].flags.GRANT:
                    credit = pkt[Homa].grant_offset
                    prio = pkt[Homa].grant_prio
                    self.creditToBtxEvent(tx_msg_id, meta=prio, new_credit=credit,
                                          opCode='write', compVal=credit,
                                          relOp=operator.gt)

class EgressPipe(object):
    """P4 programmable egress pipeline"""
    def __init__(self, net_queue, arbiter_queue):
        self.env = Simulator.env
        self.logger = Logger()
        self.net_queue = net_queue
        self.arbiter_queue = arbiter_queue
        self.env.process(self.start())

        # Table to assign priorities for unscheduled pkts.
        # - all unscheduled pkts belonging to a msg of a given size
        #   are assigned the same priority. TODO: is this right?
        # - {msg len pkts => priority}
        # TODO: this should probably be based on msg len in bytes
        self.unsched_priorities = {1:0, 2:1, 3:2, 4:3}

    @staticmethod
    def init_params():
        pass

    def log(self, msg):
        self.logger.log('EgressPipe: {}'.format(msg))

    def start(self):
        """Receive and process packets
        """
        while not Simulator.complete:
            # wait for a pkt from the arbiter
            (meta, pkt) = yield self.arbiter_queue.get()
            eth = Ether(dst=SWITCH_MAC, src=NIC_MAC)
            ip = IP(dst=meta.dst_ip, src=NIC_IP_TX)
            if meta.is_data:
                self.log('Processing data pkt')

                # Get priority to assign to DATA pkt
                prio = None
                if meta.pkt_offset < Simulator.rtt_pkts:
                    # This is unscheduled data
                    msg_len_pkts = compute_num_pkts(meta.msg_len)
                    prio = self.unsched_priorities.get(msg_len_pkts, NUM_UNSCHEDULED_PRIOS - 1)
                else:
                    # This is scheduled data
                    prio = meta.custom

                # add Ethernet/IP/NDP headers
                pkt = eth/ip/Homa(flags="DATA",
                                  src_context=meta.src_context,
                                  dst_context=meta.dst_context,
                                  tx_msg_id=meta.tx_msg_id,
                                  msg_len=meta.msg_len,
                                  pkt_offset=meta.pkt_offset,
                                  prio=prio)/pkt
            else:
                self.log('Processing control pkt: {}'.format(pkt[HOMA].flags))
                # add Ethernet/IP headers to control pkts
                pkt = eth/ip/pkt

            packetization_delay = len(pkt)*8/Simulator.tx_link_rate
            yield self.env.timeout(packetization_delay)
            # send pkt into network
            self.net_queue.put(pkt)

class PktGen(object):
    """Generate control packets"""
    def __init__(self, arbiter_queue):
        self.env = Simulator.env
        self.logger = Logger()
        self.arbiter_queue = arbiter_queue

    @staticmethod
    def init_params():
        pass

    def log(self, msg):
        self.logger.log('PktGen: {}'.format(msg))

    def ctrlPktEvent(self, genACK, dst_ip, dst_context, src_context,
                     tx_msg_id, msg_len, pkt_offset,
                     genGRANT, g_dst_ip=None, g_dst_context=None, g_src_context=None,
                     g_tx_msg_id=None, g_msg_len,=None grant_offset=None, grant_prio=None):
        self.log('Processing ctrlPktEvent')
        # generate control pkt
        if genACK:
            meta = EgressMeta(is_data=False, dst_ip=dst_ip)
            homa = HOMA(flags="ACK",
                        src_context=src_context,
                        dst_context=dst_context,
                        tx_msg_id=tx_msg_id,
                        msg_len=msg_len,
                        pkt_offset=pkt_offset,
                        prio=0)
            self.arbiter_queue.put((meta, homa))
        else if genGRANT:
            meta = EgressMeta(is_data=False, dst_ip=g_dst_ip)
            homa = HOMA(flags="GRANT",
                        src_context=g_src_context,
                        dst_context=g_dst_context,
                        tx_msg_id=g_tx_msg_id,
                        msg_len=g_msg_len,
                        prio=0,
                        grant_offset=grant_offset,
                        grant_prio=grant_prio)
            self.arbiter_queue.put((meta, homa))

class NetworkPkt(object):
    """A small wrapper class around scapy pkts to add priority"""
    def __init__(self, pkt, priority):
        self.pkt = pkt
        self.priority = priority

    def __lt__(self, other):
        """Highest priority element is the one with the smallest priority value"""
        return self.priority < other.priority

class Network(object):
    """The network delays each pkt. It may also drop or trim data pkts.
    """
    def __init__(self, rx_queue, tx_queue):
        self.env = Simulator.env
        self.logger = Logger()
        # rxQueue is used to receive pkts (EgressPipe output)
        self.rx_queue = rx_queue
        # txQueue is where to put outgoing pkts (IngressPipe input)
        self.tx_queue = tx_queue
        # TOR queue
        self.tor_queue = simpy.PriorityStore(self.env)

        self.env.process(self.start_rx())
        self.env.process(self.start_tx())

    @staticmethod
    def init_params():
        Network.data_pkt_delay_dist = DistGenerator('data_pkt_delay')
        Network.ctrl_pkt_delay_dist = DistGenerator('ctrl_pkt_delay')
        Network.data_pkt_drop_prob = Simulator.config['data_pkt_drop_prob'].next()

    def log(self, msg):
        self.logger.log('Network: {}'.format(msg))

    def forward_data(self, pkt):
        delay = Network.data_pkt_delay_dist.next()
        self.log('Forwarding pkt ({}) with delay {}'.format(pkt[HOMA].flags,
                                                            delay))
        yield self.env.timeout(delay)
        self.tor_queue.put(NetworkPkt(pkt, priority=pkt[HOMA].prio))

    def forward_ctrl(self, pkt):
        delay = Network.ctrl_pkt_delay_dist.next()
        self.log('Forwarding pkt ({}) with delay {}'.format(pkt[HOMA].flags,
                                                            delay))
        yield self.env.timeout(delay)
        self.tor_queue.put(NetworkPkt(pkt, priority=0))

    def start_rx(self):
        """Start receiving messages"""
        while not Simulator.complete:
            # Wait to receive a pkt
            pkt = yield self.rx_queue.get()
            self.log('Received pkt: src={} dst={} flags={} prio={}'.format(pkt[IP].src,
              pkt[IP].dst,
              pkt[HOMA].flags,
              pkt[HOMA].prio))
            # TODO: We may consider dropping packet not only randomly, but
            #       by simulating a limited buffer capacity and overflows.
            if random.random() < Network.data_pkt_drop_prob:
                self.log('Dropping the pkt')
            else:
                if pkt[HOMA].opCode.DATA or pkt[HOMA].opCode.ALL_DATA:
                    self.env.process(self.forward_data(pkt))
                else:
                    self.env.process(self.forward_ctrl(pkt))

    def start_tx(self):
        """Start transmitting pkts from the TOR queue to the TX queue"""
        while not Simulator.complete:
            net_pkt = yield self.tor_queue.get()
            pkt = net_pkt.pkt

            # delay based on pkt length and link rate
            delay = len(pkt)*8/Simulator.rx_link_rate
            yield self.env.timeout(delay)

            self.tx_queue.put(pkt)
