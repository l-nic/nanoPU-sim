#!/usr/bin/env python2

from scapy.all import *
from nanoPU_sim import * # Note the cyclic dependency here!
from headers import *
from sim_utils import *
import operator

HOMA_PROTO = 0x98

class HOMA(Packet):
    name = "HOMA"
    fields_desc = [
        # FlagsField("incast", 0, 2, ["NO_INCAST", "INCAST"]), # This part is not specified in RAMCloud implementation
        FlagsField("op_code", 0, 8, ["ALL_DATA", "DATA", "GRANT",
                                     "LOG_TIME_TRACE", "RESEND",
                                     "BUSY", "ABORT", "BOGUS"]),
        ShortField("rpc_id", 0), # should be unique for every RPC
        FlagsField("flags", 0, 4, ["FROM_SERVER", # Using as FROM_RECEIVER
                                   "FROM_CLIENT", # Using as FROM_SENDER
                                   "RETRANSMISSION",
                                   "RESTART"]),
        ShortField("msg_len", 0),
        ShortField("pkt_offset", 0), # or should this be byte offset? Or should the header include both?
        ShortField("unscheduled_pkts", 0), # or should this be in bytes? Or should the header include both?
        ShortField("prio",8),
        ShortField("tx_msg_id", 0) # originally not in Homa definition, but required for NanoTransport architecture
    ]

bind_layers(IP, HOMA, proto=HOMA_PROTO)

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

        # Programmer-defined state to track priority distribution
        # Each element determines the maximum msg length that would
        # result in the priority that is equal to the index of that element
        # TODO: Priorities should be assigned dynamically wrt remaining msg size
        self.priorities = [2, 5, 7, Simulator.rtt_pkts] # Lowest priority is for scheduled packets

        # Programmer-defined state to track credit and activeness for each
        # incoming message (Each element carries (rx_msg_id, msg_len, grant_offset))
        self.scheduled_msgs = [[], [], [], []]
        # Programmer-defined state to track credit for each message {rx_msg_id => credit}
        self.credit = {} #Credit is the Grant Offset in Homa

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

    def getPriority(self,msg_len):
        if msg_len <= self.priorities[0]:
            prio = 0
        elif msg_len <= self.priorities[1]:
            prio = 1
        elif msg_len <= self.priorities[2]:
            prio = 2
        elif msg_len <= self.priorities[3]:
            prio = 3
        else:
            prio = 4
        # TODO: Update incoming message length distribution for future reference
        return prio

    def start(self):
        """Receive and process packets from the network
        """
        while not Simulator.complete:
            # wait for a pkt from the network
            pkt = yield self.net_queue.get()

            # defaults
            tx_msg_id = pkt[HOMA].tx_msg_id
            pkt_offset = pkt[HOMA].pkt_offset
            msg_len = pkt[HOMA].msg_len

            if pkt[HOMA].op_code.DATA \
               or pkt[HOMA].op_code.ALL_DATA \
               or ( pkt[HOMA].flags.FROM_CLIENT and pkt[HOMA].op_code.RESEND ):

                self.log('Processing {} - {}, pkt {}'.format(pkt[HOMA].op_code,
                                                             pkt[HOMA].flags,
                                                             pkt[HOMA].pkt_offset))
                # defaults for generating control pkts
                dst_ip = pkt[IP].src
                rpc_id = pkt[HOMA].rpc_id
                rx_msg_id, ack_no, isNewMsg, isNewPkt = self.getRxMsgInfo(pkt[IP].src,
                                                                          pkt[HOMA].rpc_id,
                                                                          pkt[HOMA].tx_msg_id,
                                                                          pkt[HOMA].msg_len,
                                                                          pkt[HOMA].pkt_offset)

                # NOTE: ack_no is the current acknowledgement number before
                #       processing this incoming data packet because this
                #       packet has not updated the received_bitmap in the
                #       assembly buffer yet.
                ack_no = ack_no + 1 if ack_no == pkt_offset else ack_no
                # compute grant_offset
                self.credit[rx_msg_id] = ack_no + Simulator.rtt_pkts
                grant_offset = self.credit[rx_msg_id]

                # determine priority of this message
                prio = sef.getPriority(msg_len)

                # NOTE: I am not sure if the operations below are feasible
                #       Maybe we can define something like Read-Modify-(Delete/Write)?
                act_msg_id, _ = self.scheduled_msgs[prio][0]
                if act_msg_id == None or act_msg_id == rx_msg_id:
                    # Msg of the received pkt is the active one for this prio

                    # fire event to generate control pkt(s)
                    # TODO: Instead of providing some arguments to the packet
                    #       generator, we should provide the exact transport layer
                    #       header because we want the fixed function packet generator
                    #       to be able to generate packets for any transport protocol
                    #       that programmer deploys.
                    self.ctrlPktEvent(genGRANT=True, genBUSY=False, dst_ip,
                                      rpc_id, tx_msg_id, msg_len, prio,
                                      pkt_offset, grant_offset)

                    if act_msg_id != None and grant_offset > msg_len:
                        # This msg has already been fully granted, so we can
                        # unschedule it from active messages list
                        # TODO: Then how do we make sure fully granted messages
                        #       complete in the future? Should have timers for
                        #       every grants sent.
                        self.scheduled_msgs[prio].pop(0)
                else:
                    self.ctrlPktEvent(genGRANT=False, genBUSY=True, dst_ip,
                                      rpc_id, tx_msg_id, msg_len, prio,
                                      pkt_offset, grant_offset)

                if (act_msg_id == None or isNewMsg) and grant_offset <= msg_len:
                    self.scheduled_msgs[prio].append((rx_msg_id, msg_len))
                # End of Read-Modify-(Delete/Write)

                data = (ReassembleMeta(rx_msg_id,
                                       pkt[IP].src,
                                       pkt[HOMA].rpc_id,
                                       pkt[HOMA].tx_msg_id,
                                       pkt[HOMA].msg_len,
                                       pkt[HOMA].pkt_offset),
                        pkt[HOMA].payload)
                self.assemble_queue.put(data)

            else:
                self.log('Processing {} for tx_msg_id: {}, pkt {}'.format(pkt[HOMA].op_code,
                                                                          tx_msg_id,
                                                                          pkt[HOMA].pkt_offset))
                # control pkt for msg being transmitted
                isInterval = True
                ack_no = pkt_offset - Simulator.rtt_pkts
                if pkt[HOMA].op_code.GRANT \
                    or (pkt[HOMA].flags.FROM_SERVER and pkt[HOMA].op_code.RESEND):
                    # fire event to mark pkt as delivered
                    # NOTE: A single GRANT packet triggers 2 events
                    # TODO: Is this possible on hardware?
                    self.deliveredEvent(tx_msg_id, (1<<ack_no)-1,
                                        isInterval, msg_len)
                    self.creditToBtxEvent(tx_msg_id, rtx_pkt = None,
                                          new_credit = pkt_offset,
                                          opCode = 'write',
                                          compVal = pkt_offset,
                                          relOp = operator.gt)

                elif (pkt[HOMA].flags.FROM_SERVER and pkt[HOMA].op_code.BUSY):
                    # fire event to mark pkt as delivered
                    self.deliveredEvent(tx_msg_id, (1<<ack_no)-1,
                                        isInterval, msg_len)

                elif pkt[HOMA].flags.FROM_CLIENT and pkt[HOMA].op_code.BUSY:
                    pass
                    # TODO: Make sure the corresponding message is not active
                    #       Maybe we shouldn't allow this to happen in the first
                    #       place.

class EgressPipe(object):
    """P4 programmable egress pipeline"""
    def __init__(self, net_queue, arbiter_queue):
        self.env = Simulator.env
        self.logger = Logger()
        self.net_queue = net_queue
        self.arbiter_queue = arbiter_queue
        self.env.process(self.start())

        # Programmer-defined state to track priority distribution
        # Each element determines the maximum msg length that would
        # result in the priority that is equal to the index of that element
        # TODO: Priorities should be assigned dynamically wrt remaining msg size
        self.priorities = [2, 5, 7, Simulator.rtt_pkts] # Lowest priority is for scheduled packets

    @staticmethod
    def init_params():
        pass

    def log(self, msg):
        self.logger.log('EgressPipe: {}'.format(msg))

    def getPriority(self,msg_len):
        if msg_len <= self.priorities[0]:
            prio = 0
        elif msg_len <= self.priorities[1]:
            prio = 1
        elif msg_len <= self.priorities[2]:
            prio = 2
        elif msg_len <= self.priorities[3]:
            prio = 3
        else:
            prio = 4
        # TODO: Update incoming message length distribution for future reference
        return prio

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
                pkt = eth/ip/HOMA(op_code="DATA",
                                  rpc_id=meta.src_context, # TODO: Make sure CPU provides correct contect values (unique rpcId)
                                  flags="FROM_CLIENT", # TODO: Currently we don't distinguish RPC server or client
                                  msg_len=meta.msg_len,
                                  pkt_offset=meta.pkt_offset,
                                  unscheduled_pkts=Simulator.rtt_pkts,
                                  prio=sef.getPriority(meta.msg_len),
                                  tx_msg_id=meta.tx_msg_id)/pkt
            else:
                self.log('Processing control pkt: {} - {}'.format(pkt[HOMA].op_code,
                                                                  pkt[HOMA].flags))
                # add Ethernet/IP headers to control pkts
                pkt = eth/ip/pkt
            # send pkt into network
            self.net_queue.put(pkt)
            # # TODO: Serialization should be accounted for TX as well (?)
            #         The code below breaks the priority logic in the network
            #         at the moment
            # delay = len(pkt)*8/Simulator.tx_link_rate
            # yield self.env.timeout(delay)

class PktGen(object):
    """Generate control packets"""
    def __init__(self, arbiter_queue):
        self.env = Simulator.env
        self.logger = Logger()
        self.arbiter_queue = arbiter_queue
        self.pacer_queue = simpy.Store(self.env)
        self.pacer_lastTxTime = - Simulator.max_pkt_len*8/Simulator.rx_link_rate
        self.env.process(self.start_pacer())

    @staticmethod
    def init_params():
        pass

    def log(self, msg):
        self.logger.log('PktGen: {}'.format(msg))

    def ctrlPktEvent(self, genGRANT, genBUSY, dst_ip, rpc_id, tx_msg_id,
                           msg_len, prio, pkt_offset, grant_offset):
        self.log('Processing ctrlPktEvent, genGRANT: {}'.format(genGRANT))
        # generate control pkt
        meta = EgressMeta(is_data=False, dst_ip=dst_ip)
        if genGRANT:
            homa = HOMA(op_code="GRANT",
                        rpc_id=rpc_id,
                        flags="FROM_SERVER", # TODO: Currently we don't distinguish RPC server or client
                        msg_len=msg_len,
                        pkt_offset=grant_offset,
                        unscheduled_pkts=Simulator.rtt_pkts,
                        prio=prio,
                        tx_msg_id=tx_msg_id
                       )
        elif genBUSY:
            homa = HOMA(op_code="BUSY",
                        rpc_id=rpc_id,
                        flags="FROM_SERVER", # TODO: Currently we don't distinguish RPC server or client
                        msg_len=msg_len,
                        pkt_offset=pkt_offset,
                        unscheduled_pkts=Simulator.rtt_pkts,
                        prio=prio,
                        tx_msg_id=tx_msg_id
                       )
        self.arbiter_queue.put((meta, homa))

    def start_pacer(self):
        """Start pacing generated pkts (Homa doesn't use this!)
        """
        while not Simulator.complete:
            meta, pkt, delay = yield self.pacer_queue.get()
            data = (meta, pkt)

            txTime = self.pacer_lastTxTime + delay
            now = self.env.now
            if( now < txTime ):
                yield self.env.timeout(txTime - now)
                self.pacer_lastTxTime = txTime
            else:
                self.pacer_lastTxTime = now

            self.log('Pacer is releasing a pkt')
            self.arbiter_queue.put(data)

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
        self.log('Forwarding {} pkt ({}) with delay {}'.format(pkt[HOMA].op_code,
                                                               pkt[HOMA].flags,
                                                               delay))
        yield self.env.timeout(delay)
        self.tor_queue.put(NetworkPkt(pkt, priority=pkt[HOMA].prio))

    def forward_ctrl(self, pkt):
        delay = Network.ctrl_pkt_delay_dist.next()
        self.log('Forwarding {} pkt ({}) with delay {}'.format(pkt[HOMA].op_code,
                                                               pkt[HOMA].flags,
                                                               delay))
        yield self.env.timeout(delay)
        self.tor_queue.put(NetworkPkt(pkt, priority=0)) # The priority value in the Homa header is to be used for data packets

    def start_rx(self):
        """Start receiving messages"""
        while not Simulator.complete:
            # Wait to receive a pkt
            pkt = yield self.rx_queue.get()
            self.log('Received pkt: src={} dst={} rpc_id={} pkt_offset={} op_code={} flags={} prio={}'.format(pkt[IP].src,
                                                                                                               pkt[IP].dst,
                                                                                                               pkt[HOMA].rpc_id,
                                                                                                               pkt[HOMA].pkt_offset,
                                                                                                               pkt[HOMA].op_code,
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
            self.log('Received pkt: src={} dst={} rpc_id={} pkt_offset={} op_code={} flags={} prio={}'.format(pkt[IP].src,
                                                                                                               pkt[IP].dst,
                                                                                                               pkt[HOMA].rpc_id,
                                                                                                               pkt[HOMA].pkt_offset,
                                                                                                               pkt[HOMA].op_code,
                                                                                                               pkt[HOMA].flags,
                                                                                                               pkt[HOMA].prio))
            self.tx_queue.put(pkt)
            # delay based on pkt length and link rate
            delay = len(pkt)*8/Simulator.rx_link_rate
            yield self.env.timeout(delay)
