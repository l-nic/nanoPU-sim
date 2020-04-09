#!/usr/bin/env python2

# import simpy
from nanoPU_sim import * # Note the cyclic dependency here!
from headers import *
from sim_utils import *
import operator

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

        # Programmer-defined state to track credit for each message {rx_msg_id => credit}
        self.credit = {} #Credit is the Pull Offset in NDP

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

    def start(self):
        """Receive and process packets from the network
        """
        while not Simulator.complete:
            # wait for a pkt from the network
            pkt = yield self.net_queue.get()

            # defaults
            tx_msg_id = pkt[NDP].tx_msg_id
            pkt_offset = pkt[NDP].pkt_offset
            msg_len = pkt[NDP].msg_len

            if pkt[NDP].flags.DATA:
                self.log('Processing data pkt')
                # defaults for generating control pkts
                genACK = False
                genNACK = False
                genPULL = False
                dst_ip = pkt[IP].src
                dst_context = pkt[NDP].src_context
                src_context = pkt[NDP].dst_context
                rx_msg_id, ack_no, isNewMsg, isNewPkt = self.getRxMsgInfo(pkt[IP].src,
                                                                          pkt[NDP].src_context,
                                                                          pkt[NDP].tx_msg_id,
                                                                          pkt[NDP].msg_len,
                                                                          pkt[NDP].pkt_offset)
                # NOTE: ack_no is the current acknowledgement number before
                #       processing this incoming data packet because this
                #       packet has not updated the received_bitmap in the
                #       assembly buffer yet.
                pull_offset_diff = 0
                if pkt[NDP].flags.CHOP:
                    self.log('Processing chopped data pkt')
                    # send NACK and PULL
                    genNACK = True
                    genPULL = True

                else:
                    # process DATA pkt
                    genACK = True
                    # TODO: No need to generate new PULL pkt if this was the
                    #       last packet of the msg
                    #       (ie, if ack_no > compute_num_pkts(msg_len))
                    genPULL = True

                    data = (ReassembleMeta(rx_msg_id,
                                           pkt[IP].src,
                                           pkt[NDP].src_context,
                                           pkt[NDP].tx_msg_id,
                                           pkt[NDP].msg_len,
                                           pkt[NDP].pkt_offset),
                            pkt[NDP].payload)
                    self.assemble_queue.put(data)
                    pull_offset_diff = 1

                # compute pull_offset with a PRAW extern
                if isNewMsg:
                    self.credit[rx_msg_id] = Simulator.rtt_pkts + pull_offset_diff
                    pull_offset = self.credit[rx_msg_id]
                else:
                    self.credit[rx_msg_id] += pull_offset_diff
                    pull_offset = self.credit[rx_msg_id]

                # fire event to generate control pkt(s)
                # TODO: Instead of providing some arguments to the packet
                #       generator, we should provide the exact transport layer
                #       header because we want the fixed function packet generator
                #       to be able to generate packets for any transport protocol
                #       that programmer deploys.
                self.ctrlPktEvent(genACK, genNACK, genPULL, dst_ip,
                                  dst_context, src_context, tx_msg_id,
                                  msg_len, pkt_offset, pull_offset)
            else:
                self.log('Processing {} for tx_msg_id: {}, pkt {}'.format(pkt[NDP].flags, tx_msg_id, pkt[NDP].pkt_offset))
                # control pkt for msg being transmitted
                if pkt[NDP].flags.ACK:
                    # fire event to mark pkt as delivered
                    self.deliveredEvent(tx_msg_id, pkt_offset, msg_len)
                if pkt[NDP].flags.PULL or pkt[NDP].flags.NACK:
                    # mark pkt for rtx for NACK
                    rtx_pkt = pkt_offset if pkt[NDP].flags.NACK else None
                    # update credit for PULL
                    credit = pkt[NDP].pkt_offset if pkt[NDP].flags.PULL else None
                    self.creditToBtxEvent(tx_msg_id, rtx_pkt = rtx_pkt, new_credit = credit,
                                          opCode = 'write', compVal = credit,
                                          relOp = operator.gt)

class EgressPipe(object):
    """P4 programmable egress pipeline"""
    def __init__(self, net_queue, arbiter_queue):
        self.env = Simulator.env
        self.logger = Logger()
        self.net_queue = net_queue
        self.arbiter_queue = arbiter_queue
        self.env.process(self.start())

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
                # add Ethernet/IP/NDP headers
                pkt = eth/ip/NDP(flags="DATA",
                                 src_context=meta.src_context,
                                 dst_context=meta.dst_context,
                                 tx_msg_id=meta.tx_msg_id,
                                 msg_len=meta.msg_len,
                                 pkt_offset=meta.pkt_offset)/pkt
            else:
                self.log('Processing control pkt: {}'.format(pkt[NDP].flags))
                # add Ethernet/IP headers to control pkts
                pkt = eth/ip/pkt
            # send pkt into network
            self.net_queue.put(pkt)
            # # TODO: Serialization should be accounted for in TX as well (?)
            #         The code below breaks the priority logic in the network
            #         at the moment
            # delay = len(pkt)*8/Simulator.tx_link_rate
            # yield self.env.timeout(delay)
