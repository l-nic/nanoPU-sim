#!/usr/bin/env python2

import simpy
import sys, os
import random
from headers import *
from sim_utils import *
import math

SWITCH_MAC = "08:55:66:77:88:08"
NIC_MAC = "08:11:22:33:44:08"
NIC_IP_TX = "10.0.0.1"
NIC_IP_RX = "10.0.0.2"

SRC_CONTEXT=[0] # Every new message will add a new src_context to this list
DST_CONTEXT=99

####
# Helper functions / classes
####

class Logger(object):
    def __init__(self, debug=True):
        self.env = Simulator.env
        self.debug = debug

    @staticmethod
    def init_params():
        pass

    def log(self, s):
        if self.debug:
            print '{}: {}'.format(self.env.now, s)

def DistGenerator(varname):
    dist = Simulator.config[varname].next()
    # initialize variable params
    kwargs = {}
    if dist == 'uniform':
        kwargs['min'] = Simulator.config['{}_min'.format(varname)].next()
        kwargs['max'] = Simulator.config['{}_max'.format(varname)].next()
    elif dist == 'normal':
        kwargs['mean']   = Simulator.config['{}_mean'.format(varname)].next()
        kwargs['stddev'] = Simulator.config['{}_stddev'.format(varname)].next()
    elif dist == 'poisson':
        kwargs['lambda'] = Simulator.config['{}_lambda'.format(varname)].next()
    elif dist == 'lognormal':
        kwargs['mean'] = Simulator.config['{}_mean'.format(varname)].next()
        kwargs['sigma'] = Simulator.config['{}_sigma'.format(varname)].next()
    elif dist == 'exponential':
        kwargs['lambda'] = Simulator.config['{}_lambda'.format(varname)].next()
    elif dist == 'fixed':
        kwargs['value'] = Simulator.config['{}_value'.format(varname)].next()
    elif dist == 'bimodal':
        kwargs['lower_mean']    = Simulator.config['{}_lower_mean'.format(varname)].next()
        kwargs['lower_stddev']  = Simulator.config['{}_lower_stddev'.format(varname)].next()
        kwargs['lower_samples'] = Simulator.config['{}_lower_samples'.format(varname)].next()
        kwargs['upper_mean']    = Simulator.config['{}_upper_mean'.format(varname)].next()
        kwargs['upper_stddev']  = Simulator.config['{}_upper_stddev'.format(varname)].next()
        kwargs['upper_samples'] = Simulator.config['{}_upper_samples'.format(varname)].next()
    elif dist == 'custom':
        kwargs['csv'] = Simulator.config['{}_csv'.format(varname)].next()

    if dist == 'bimodal':
        bimodal_samples = map(int, list(np.random.normal(kwargs['lower_mean'], kwargs['lower_stddev'], kwargs['lower_samples']))
                                   + list(np.random.normal(kwargs['upper_mean'], kwargs['upper_stddev'], kwargs['upper_samples'])))
    elif dist == 'custom':
        custom_samples = pd.read_csv(kwargs['csv'])['samples']

    while True:
        if dist == 'uniform':
            yield random.randint(kwargs['min'], kwargs['max'])
        elif dist == 'normal':
            yield int(np.random.normal(kwargs['mean'], kwargs['stddev']))
        elif dist == 'poisson':
            yield np.random.poisson(kwargs['lambda'])
        elif dist == 'lognormal':
            yield int(np.random.lognormal(kwargs['mean'], kwargs['sigma']))
        elif dist == 'exponential':
            yield int(np.random.exponential(kwargs['lambda']))
        elif dist == 'fixed':
            yield kwargs['value']
        elif dist == 'bimodal':
            yield random.choice(bimodal_samples)
        elif dist == 'custom':
            yield random.choice(custom_samples)
        else:
            print 'ERROR: Unsupported distrbution: {}'.format(dist)
            sys.exit(1)

def compute_num_pkts(msg_len):
    return msg_len/Simulator.max_pkt_len if (msg_len % Simulator.max_pkt_len == 0) else msg_len/Simulator.max_pkt_len + 1

def find_first_one(bitmap):
    """Find the first set bit in the provided bitmap.
       NOTE: this may not work as expected when doing: find_first_one(~value) if value is all 1's
    """
    if bitmap == 0:
        return None
    # Prevent twos complement sign issue.
    return int(math.log(bitmap & -bitmap, 2))

#####
# Architecture Elements
#####

class ReassembleMeta:
    def __init__(self, rx_msg_id, src_ip, src_context, tx_msg_id, msg_len, pkt_offset):
        self.rx_msg_id = rx_msg_id
        self.src_ip = src_ip
        self.src_context = src_context
        self.tx_msg_id = tx_msg_id
        self.msg_len = msg_len
        self.pkt_offset = pkt_offset

class Reassemble(object):
    """Reassemble packets into messages and feed to CPU"""
    def __init__(self, assemble_queue, cpu_queue):
        self.env = Simulator.env
        self.logger = Logger()
        self.assemble_queue = assemble_queue
        self.cpu_queue = cpu_queue

        ####
        # initialize state
        ####
        self.rx_msg_id_freelist = [i for i in range(Reassemble.max_messages)]
        # table that maps {src_ip, src_port, tx_msg_id => rx_msg_id}
        self.rx_msg_id_table = {}
        # message reassembly buffers, {rx_msg_id => ["pkt_0_data", ..., "pkt_N_data"]}
        self.buffers = {}
        # bitmap to determine when all pkts have arrived, {rx_msg_id => bitmap}
        self.received_bitmap = {}

        self.env.process(self.start())

    @staticmethod
    def init_params():
        Reassemble.max_messages = Simulator.config['reassemble_max_messages'].next()

    def log(self, msg):
        self.logger.log('Reassemble: {}'.format(msg))

    def getRxMsgInfo(self, src_ip, src_context, tx_msg_id, msg_len, pkt_offset):
        """Obtain the rx_msg_id for the indicated message, or try to assign one.
        """
        key = (src_ip, src_context, tx_msg_id)
        isNewMsg = False
        isNewPkt = False
        self.log('Processing getRxMsgInfo extern call for: {}'.format(key))
        # check if this msg has already been allocated an rx_msg_id
        if key in self.rx_msg_id_table:
            rx_msg_id = self.rx_msg_id_table[key]
            self.log('Found rx_msg_id: {}'.format(rx_msg_id))
            # compute the beginning of the inflight window
            ack_no = find_first_one(~self.received_bitmap[rx_msg_id])
            if ack_no is None:
                self.log('Message {} has already been fully received'.format(rx_msg_id))
                ack_no = compute_num_pkts(msg_len) + 1
            isNewPkt = ( self.received_bitmap[rx_msg_id] & (1<<pkt_offset)-1 ) == 0
            return rx_msg_id, ack_no, isNewMsg, isNewPkt
        # try to allocate an rx_msg_id
        if len(self.rx_msg_id_freelist) > 0:
            rx_msg_id = self.rx_msg_id_freelist.pop(0)
            self.log('Allocating rx_msg_id {} for: {}'.format(rx_msg_id, key))
            # add table entry
            self.rx_msg_id_table[key] = rx_msg_id
            # allocate buffer to reassemble the message
            num_pkts = compute_num_pkts(msg_len)
            self.buffers[rx_msg_id] = ["" for i in range(num_pkts)]
            self.received_bitmap[rx_msg_id] = 0
            ack_no = 0
            isNewMsg = True
            isNewPkt = True
            return rx_msg_id, ack_no, isNewMsg, isNewPkt
        self.log('ERROR: failed to allocate rx_msg_id for: {}'.format(key))
        return -1, -1, -1, -1

    def start(self):
        """Receive pkts and reassemble into messages
        """
        while not Simulator.complete:
            # wait for a data pkt to arrive: (AssembleMeta, data_pkt)
            (meta, pkt) = yield self.assemble_queue.get()
            self.log('Processing pkt {} for msg {}'.format(meta.pkt_offset,
                                                           meta.rx_msg_id))
            # record pkt data in buffer
            self.buffers[meta.rx_msg_id][meta.pkt_offset] = str(pkt)
            # mark the pkt as received
            # NOTE: received_bitmap must have 2 write ports: here and in getRxMsgInfo()
            self.received_bitmap[meta.rx_msg_id] = self.received_bitmap[meta.rx_msg_id] | (1 << meta.pkt_offset)
            # check if all pkts have been received
            num_pkts = compute_num_pkts(meta.msg_len)
            if self.received_bitmap[meta.rx_msg_id] == (1<<num_pkts)-1:
                self.log('All pkts have been received for msg {}'.format(meta.rx_msg_id))
                # push the reassembled msg to the CPU
                msg_data = ''.join(self.buffers[meta.rx_msg_id])
                app_msg = App(ipv4_addr=meta.src_ip, context_id=meta.src_context, msg_len=meta.msg_len)/SimMessage(msg_data)
                self.cpu_queue.put(app_msg)
                # free the rx_msg_id
                # NOTE: the rx_msg_id_table must have 2 write ports: here and in getRxMsgInfo()
                del self.rx_msg_id_table[(meta.src_ip, meta.src_context, meta.tx_msg_id)]
                self.rx_msg_id_freelist.append(meta.rx_msg_id)

class Packetize(object):
    """Packetize messages into data packets"""
    def __init__(self, cpu_queue):
        self.env = Simulator.env
        self.logger = Logger()
        self.cpu_queue = cpu_queue

        ####
        # initialize state for tx messages
        ####
        # freelist of tx msg ids
        self.tx_msg_id_freelist = [i for i in range(Packetize.max_messages)]
        # FIFO queue of pkts to TX
        self.scheduled_pkts_fifo = simpy.Store(self.env)
        # Flip flop state to track msg and pkts currently being transmitted
        self.active_tx_msg_id = 0
        self.active_tx_pkts = 0
        # state to track which pkts have been delivered {tx_msg_id => bitmap}
        self.delivered = {}
        # state to track credit for each message {tx_msg_id => credit}
        self.credit = {}
        # state to track pkts to transmit {tx_msg_id => bitmap}
        self.toBtx = {}
        # buffers to store msgs that are being transmitted {tx_msg_id => ["pkt_0_data", ..., "pkt_N_data"]}
        self.buffers = {}
        # state to store application header {tx_msg_id => App()}
        self.app_header = {}
        # state to keep track of max pkt offset transmitted so far
        self.max_tx_pkt_offset = {}
        # state to track # of time a msg times out {tx_msg_id => timeout_count}
        self.timeout_count = {}

        self.env.process(self.start())

    @staticmethod
    def init_params():
        Packetize.max_messages = Simulator.config['packetize_max_messages'].next()

    def log(self, msg):
        self.logger.log('Packetize: {}'.format(msg))

    ####
    # Event Methods
    ####

    def deliveredEvent(self, tx_msg_id, pkt_offset, isInterval, msg_len):
        """Mark a packet as delivered
        """
        if isInterval:
            self.log("Processing deliveredEvent for msg {}, pkt bitmap {:b}".format(tx_msg_id,
                                                                                    pkt_offset))
        else:
            self.log("Processing deliveredEvent for msg {}, pkt {}".format(tx_msg_id,
                                                                           pkt_offset))
        if tx_msg_id in self.delivered:
            if isInterval:
                self.log("Marking pkt bitmap {:b} as delivered".format(pkt_offset))
                self.delivered[tx_msg_id] |= pkt_offset
            else:
                self.log("Marking pkt {} as delivered".format(pkt_offset))
                self.delivered[tx_msg_id] |= (1<<pkt_offset)

            # check if the whole message has been delivered
            num_pkts = compute_num_pkts(msg_len)
            if self.delivered[tx_msg_id] == (1<<num_pkts)-1:
                self.log("The whole msg was delivered!")
                # cancel the timer for this msg
                self.cancelTimerEvent(tx_msg_id)
                # free the tx_msg_id
                self.tx_msg_id_freelist.append(tx_msg_id)
                # message_cnt increases when message is fully ACKed
                Simulator.message_cnt += 1
                # check if simulation is complete
                Simulator.check_done()
        else:
            self.log("ERROR: deliveredEvent was triggered for unknown tx_msg_id: {}".format(tx_msg_id))

    # NOTE: credit state update is implemented as a PRAW atom.
    #       https://github.com/NetFPGA/P4-NetFPGA-public/wiki/PRAW-Extern-Function
    def creditToBtxEvent(self, tx_msg_id, rtx_pkt = None, new_credit = None,
                         opCode = None, compVal = None, relOp = None):
        self.log('Processing creditToBtxEvent for tx_msg_id {}'.format(tx_msg_id))
        # Read-Modify-Write to update toBtx state variable
        if (tx_msg_id in self.toBtx) and (rtx_pkt is not None):
            self.log('Marking tx_msg_id {}, pkt {} for retransmission'.format(tx_msg_id, rtx_pkt))
            self.toBtx[tx_msg_id] |= 1<<rtx_pkt

        # Read-Modify-Write to update credit state variable
        if (tx_msg_id in self.credit) and new_credit is not None:
            cur_credit = self.credit[tx_msg_id]
            if relOp == None:
                self.log('ERROR: creditEvent was triggered without a relOp value!')
            elif compVal == None:
                self.log('ERROR: creditEvent was triggered without a compVal value!')
            elif opCode == None:
                self.log('ERROR: creditEvent was triggered without a opCode value!')
            elif opCode == 'write':
                if relOp(compVal, cur_credit):
                    self.log('Changing credit for msg {} from {} to {}'.format(tx_msg_id, cur_credit, new_credit))
                    self.credit[tx_msg_id] = new_credit
            elif opCode == 'add':
                if relOp(compVal, cur_credit):
                    self.credit[tx_msg_id] += new_credit
                    self.log('Changing credit for msg {} from {} to {}'.format(tx_msg_id, cur_credit, self.credit[tx_msg_id]))
            elif opCode == 'shift_right':
                if relOp(compVal, cur_credit):
                    self.credit[tx_msg_id] >>= new_credit
                    self.log('Changing credit for msg {} from {} to {}'.format(tx_msg_id, cur_credit, self.credit[tx_msg_id]))
            else:
                self.log('ERROR: creditEvent was triggered for unknown opCode: {}'.format(opCode))

            # NOTE: here's another Read-Modify-Write to update toBtx state, which
            #   should be combined with the above operation in the actual HW implementation
            tx_pkts = self.toBtx[tx_msg_id] & (1<<self.credit[tx_msg_id])-1
            if tx_pkts != 0:
                # schedule the pkts for transmission
                self.scheduled_pkts_fifo.put((tx_msg_id, tx_pkts))
                # mark scheduled pkts as no longer needing transmission (clear bits in toBtx)
                self.toBtx[tx_msg_id] ^= tx_pkts

        if (tx_msg_id not in self.credit):
            self.log('ERROR: creditEvent was triggered for unknown tx_msg_id: {}'.format(tx_msg_id))

    def timeoutEvent(self, tx_msg_id, rtx_offset):
        self.log('Processing timeoutEvent for msg {}'.format(tx_msg_id))
        if self.timeout_count[tx_msg_id] >= Simulator.max_num_timeouts:
            self.log('ERROR: tx_msg_id {} expired'.format(tx_msg_id))
            # free the tx_msg_id
            self.tx_msg_id_freelist.append(tx_msg_id)
            Simulator.message_cnt += 1
            # check if simulation is complete
            Simulator.check_done()
        else:
            # Mark all undelivered the pkts before the specified offset for retransmission
            delivered_bitmap = self.delivered[tx_msg_id]
            rtx_pkts_mask = (1<<rtx_offset)-1
            rtx_pkts = ~delivered_bitmap & rtx_pkts_mask
            self.log('Pkts to retransmit: {:b}'.format(rtx_pkts))
            # reschedule timer for this msg
            self.rescheduleTimerEvent(tx_msg_id, self.max_tx_pkt_offset[tx_msg_id])
            if rtx_pkts != 0:
                # schedule the pkts for transmission
                self.scheduled_pkts_fifo.put((tx_msg_id, rtx_pkts))
                # increase timeout counter
                self.timeout_count[tx_msg_id] += 1
                # NOTE: The operation is logically required, but it seems that
                #       it is not needed in practice because the rtx_pkts are
                #       most probably 0 in toBtx already.
                # # mark scheduled pkts as no longer needing transmission (clear bits in toBtx)
                # self.toBtx[tx_msg_id] &= ~tx_pkts

    def init_scheduleTimerEvent(self, scheduleTimerEvent):
        self.scheduleTimerEvent = scheduleTimerEvent

    def init_rescheduleTimerEvent(self, rescheduleTimerEvent):
        self.rescheduleTimerEvent = rescheduleTimerEvent

    def init_cancelTimerEvent(self, cancelTimerEvent):
        self.cancelTimerEvent = cancelTimerEvent

    def start(self):
        """Receive messages from CPU and write into packet buffers
        """
        while not Simulator.complete:
            # wait for an application message to arrive
            app_msg = yield self.cpu_queue.get()
            self.log('Received msg from CPU')
            msg = str(app_msg[App].payload)
            # try to allocate a tx_msg_id
            if len(self.tx_msg_id_freelist) > 0:
                tx_msg_id = self.tx_msg_id_freelist.pop(0)
                self.log('Msg allocated tx_msg_id: {}'.format(tx_msg_id))
                # record App header
                self.app_header[tx_msg_id] = app_msg[App]
                # fill out the msg buffer
                self.buffers[tx_msg_id] = []
                num_pkts = compute_num_pkts(app_msg[App].msg_len)
                for i in range(num_pkts-1):
                    self.buffers[tx_msg_id].append(msg[i*Simulator.max_pkt_len:(i+1)*Simulator.max_pkt_len])
                self.buffers[tx_msg_id].append(msg[(num_pkts-1)*Simulator.max_pkt_len:])
                # initialize other state
                self.delivered[tx_msg_id] = 0
                self.credit[tx_msg_id] = Simulator.rtt_pkts
                self.toBtx[tx_msg_id] = (1<<num_pkts)-1 # every pkt must be transmitted
                self.max_tx_pkt_offset[tx_msg_id] = 0
                self.timeout_count[tx_msg_id] = 0
                # schedule a timer for this msg
                self.scheduleTimerEvent(tx_msg_id, 0)
                # schedule the first pkts of the msg for transmission
                tx_pkts = self.toBtx[tx_msg_id] & (1<<self.credit[tx_msg_id])-1
                self.scheduled_pkts_fifo.put((tx_msg_id, tx_pkts))
                # mark scheduled pkts as no longer needing transmission (clear bits in toBtx)
                self.toBtx[tx_msg_id] ^= tx_pkts
            else:
                self.log('ERROR: dropping message due to lack of an available tx_msg_id')

    def dequeue(self):
        """Send a data pkt to the arbiter. The arbiter invokes this method when it decides to
           schedule a data pkt.
        """
        # check if we've finished sending all the currently active pkts
        if self.active_tx_pkts == 0:
            wait_scheduled_pkts_event = self.scheduled_pkts_fifo.get()
            try:
                # wait for pkts to be scheduled
                (tx_msg_id, tx_pkts) = yield wait_scheduled_pkts_event
                self.active_tx_msg_id = tx_msg_id
                self.active_tx_pkts = tx_pkts
            except simpy.Interrupt as i:
                wait_scheduled_pkts_event.cancel()
                self.env.exit(None)

        # use priority encoder to pick pkt to send
        pkt_offset = find_first_one(self.active_tx_pkts)
        tx_msg_id = self.active_tx_msg_id
        if pkt_offset is not None:
            self.log('Transmiting pkt {} from msg {}'.format(pkt_offset, tx_msg_id))

            # Check if we have correct SRC_CONTEXT available
            if len(SRC_CONTEXT) <= tx_msg_id:
                SRC_CONTEXT.append(len(SRC_CONTEXT))

            pkt_data = self.buffers[tx_msg_id][pkt_offset]
            app_hdr = self.app_header[tx_msg_id]
            meta = EgressMeta(is_data=True,
                              dst_ip=app_hdr.ipv4_addr,
                              src_context=SRC_CONTEXT[tx_msg_id],
                              dst_context=app_hdr.context_id,
                              tx_msg_id=tx_msg_id,
                              msg_len=app_hdr.msg_len,
                              pkt_offset=pkt_offset)
            # clear this pkt in the active_tx_pkts flip-flop
            self.active_tx_pkts ^= (1<<pkt_offset)
            # TODO: maybe we should move this state update to the creditToBtxEvent?
            # update max_tx_pkt_offset state
            if pkt_offset > self.max_tx_pkt_offset[tx_msg_id]:
                self.max_tx_pkt_offset[tx_msg_id] = pkt_offset
            # give pkt to arbiter
            self.env.exit((meta, pkt_data))
        else:
            self.log('ERROR: could not find pkt to dequeue')

class TimerModule(object):
    """Maintain one timer per message to enable reliable delivery"""
    def __init__(self):
        self.env = Simulator.env
        self.logger = Logger()

        ####
        # Initialize state
        ####

        # state that maps {tx_msg_id => meta}
        self.timer_meta = {}
        # state that maps {tx_msg_id => timer_event}
        self.timer_events = {}

    @staticmethod
    def init_params():
        TimerModule.timeout_ns = Simulator.config['timeout_ns'].next()

    def log(self, msg):
        self.logger.log('TimerModule: {}'.format(msg))

    ####
    # Events
    ####

    def init_timeoutEvent(self, timeoutEvent):
        self.timeoutEvent = timeoutEvent

    def scheduleTimerEvent(self, tx_msg_id, meta):
        self.log('Processing scheduleTimerEvent for tx_msg_id: {}'.format(tx_msg_id))
        self.timer_meta[tx_msg_id] = meta
        self.timer_events[tx_msg_id] = self.env.process(self.invokeTimeoutEvent(tx_msg_id))

    def rescheduleTimerEvent(self, tx_msg_id, meta):
        self.log('Processing rescheduleTimerEvent for tx_msg_id: {}'.format(tx_msg_id))
        self.timer_meta[tx_msg_id] = meta
        self.timer_events[tx_msg_id] = self.env.process(self.invokeTimeoutEvent(tx_msg_id))

    def invokeTimeoutEvent(self, tx_msg_id):
        try:
            # wait for timeout
            yield self.env.timeout(TimerModule.timeout_ns)
            self.timeoutEvent(tx_msg_id, self.timer_meta[tx_msg_id])
            self.log('Timeout occured for msg {}'.format(tx_msg_id))
        except simpy.Interrupt as i:
            self.log('Timer cancelled for msg {} inside invokeTimeoutEvent'.format(tx_msg_id))

    def cancelTimerEvent(self, tx_msg_id):
        try:
            self.timer_events[tx_msg_id].interrupt('Timer Cancelled!')
            self.log('Timer cancelled for msg {}'.format(tx_msg_id))
        except:
            self.log("Trying to cancel timer for msg {} which doesn't exist".format(tx_msg_id))

class EgressMeta:
    def __init__(self, is_data, dst_ip, src_context=0, dst_context=0, tx_msg_id=0, msg_len=0, pkt_offset=0):
        self.is_data = is_data
        self.dst_ip = dst_ip
        self.src_context = src_context
        self.dst_context = dst_context
        self.tx_msg_id = tx_msg_id
        self.msg_len = msg_len
        self.pkt_offset = pkt_offset

class Arbiter(object):
    """Schedule pkts between PktGen and Packetize modules into EgressPipe"""
    def __init__(self, egress_queue, pktgen_queue, pktize_module):
        self.env = Simulator.env
        self.logger = Logger()
        self.egress_queue = egress_queue
        self.pktgen_queue = pktgen_queue
        self.pktize_module = pktize_module

        self.env.process(self.start())

    @staticmethod
    def init_params():
        pass

    def log(self, msg):
        self.logger.log('Arbiter: {}'.format(msg))

    def start(self):
        """Pull pkts from pktize and pktgen modules and push to egress pipeline
        """
        while not Simulator.complete:
            pktgen_deq = self.pktgen_queue.get()
            pktize_deq = self.env.process(self.pktize_module.dequeue())
            # wait for either the pktize module or the pktgen module to
            # have a pkt ready
            result = yield pktize_deq | pktgen_deq
            if pktgen_deq in result:
                self.log('Scheduling control pkt')
                data = result[pktgen_deq]
                self.egress_queue.put(data)
            else:
                pktgen_deq.cancel()

            if pktize_deq in result:
                self.log('Scheduling data pkt')
                data = result[pktize_deq]
                self.egress_queue.put(data)
            else:
                pktize_deq.interrupt()

class CPU(object):
    """The CPU generates and consumes messasges
    """
    def __init__(self, tx_queue, rx_queue):
        self.env = Simulator.env
        self.logger = Logger()
        # txQueue is used to send out messages
        self.tx_queue = tx_queue
        # rxQueue is used to receive messages
        self.rx_queue = rx_queue

        # start receiving thread
        self.env.process(self.start_rx())

    @staticmethod
    def init_params():
        # generate distributions
        CPU.message_size_dist = DistGenerator('message_size')

        # rate at which messages are written to tx queue
        CPU.tx_rate = Simulator.config['cpu_tx_rate'].next() # Gbps

    def log(self, msg):
        self.logger.log('CPU: {}'.format(msg))

    def start_rx(self):
        """Start receiving messages"""
        while not Simulator.complete:
            # Wait to receive a message
            msg = yield self.rx_queue.get()
            self.log('Received message')
            # record received msg
            Simulator.rx_msgs.append(msg[App].payload) # no App header
            # update stats
            Simulator.message_stats['completion_times'].append(self.env.now - msg.send_time) # ns

    def start_tx(self):
        """Start generating messages"""
        for i in range(Simulator.num_messages):
            self.log('Generating message')
            # generate and record message length
            message_size = CPU.message_size_dist.next()
            if (message_size < Simulator.min_message_size):
                message_size = Simulator.min_message_size
            if (message_size > Simulator.max_message_size):
                message_size = Simulator.max_message_size
            Simulator.message_stats['message_sizes'].append(message_size)
            # construct the message from random bytes
            payload = ''.join([chr(random.randint(97, 122)) for i in range(message_size-len(SimMessage()))])
            msg = App(ipv4_addr=NIC_IP_RX, context_id=DST_CONTEXT, msg_len=message_size)/SimMessage(send_time=self.env.now)/payload
            # record tx msg
            Simulator.tx_msgs.append(msg[App].payload) # no App header
            # send message
            self.tx_queue.put(msg)
            # compute the delay for this message based on the rate and message size
            delay = (message_size*8)/CPU.tx_rate # ns
            yield self.env.timeout(delay)

class Simulator(object):
    """This class controls the simulation"""
    env = None
    config = {} # user specified input
    out_dir = 'out'
    out_run_dir = 'out/run-0'
    # run local variables
    complete = False
    finish_time = 0
    message_cnt = 0
    def __init__(self, protocolModule):
        self.env = Simulator.env
        # initialize params
        Simulator.sample_period = Simulator.config['sample_period'].next()
        Simulator.num_messages = Simulator.config['num_messages'].next()
        Simulator.max_pkt_len = Simulator.config['max_pkt_len'].next()
        Simulator.min_message_size = Simulator.config['min_message_size'].next()
        Simulator.max_message_size = Simulator.config['max_message_size'].next()
        Simulator.rx_link_rate = Simulator.config['rx_link_rate'].next()
        Simulator.tx_link_rate = Simulator.config['tx_link_rate'].next()
        Simulator.rtt_pkts = Simulator.config['rtt_pkts'].next()
        Simulator.max_num_timeouts = Simulator.config['max_num_timeouts'].next()

        # initialize stats
        Simulator.message_stats = {'message_sizes':[],
                                   'completion_times':[]}

        Simulator.network_stats = {'time': [],
                                   'tor_queue_size':[]}

        Simulator.network_pkts = []

        # TODO(sibanez): add more stats

        # initialize tx/rx message log
        Simulator.tx_msgs = []
        Simulator.rx_msgs = []

        self.logger = Logger()

        # create queues
        # TODO: Add capacity to those queues for realistic simulations
        ingress_net_queue = simpy.Store(self.env)
        egress_net_queue = simpy.Store(self.env)
        assemble_queue = simpy.Store(self.env)
        cpu_rx_queue = simpy.Store(self.env)
        cpu_tx_queue = simpy.Store(self.env)
        pktgen_arbiter_queue = simpy.Store(self.env)
        egress_arbiter_queue = simpy.Store(self.env)

        # instantiate modules
        self.ingress = protocolModule.IngressPipe(ingress_net_queue, assemble_queue)
        self.reassemble = Reassemble(assemble_queue, cpu_rx_queue)
        self.packetize = Packetize(cpu_tx_queue)
        self.timer = TimerModule()
        self.pktgen = protocolModule.PktGen(pktgen_arbiter_queue)
        self.egress = protocolModule.EgressPipe(egress_net_queue, egress_arbiter_queue)
        self.arbiter = Arbiter(egress_arbiter_queue, pktgen_arbiter_queue, self.packetize)
        self.cpu = CPU(cpu_tx_queue, cpu_rx_queue)
        self.network = protocolModule.Network(egress_net_queue, ingress_net_queue)

        # wire up events/externs
        self.ingress.init_getRxMsgInfo(self.reassemble.getRxMsgInfo)
        self.ingress.init_deliveredEvent(self.packetize.deliveredEvent)
        self.ingress.init_creditToBtxEvent(self.packetize.creditToBtxEvent)
        self.ingress.init_ctrlPktEvent(self.pktgen.ctrlPktEvent)
        self.packetize.init_scheduleTimerEvent(self.timer.scheduleTimerEvent)
        self.packetize.init_rescheduleTimerEvent(self.timer.rescheduleTimerEvent)
        self.packetize.init_cancelTimerEvent(self.timer.cancelTimerEvent)
        self.timer.init_timeoutEvent(self.packetize.timeoutEvent)

        self.init_sim()

    def init_sim(self):
        Simulator.complete = False
        Simulator.message_cnt = 0
        Simulator.finish_time = 0
        # start generating messages
        self.env.process(self.cpu.start_tx())
        # start logging
        if Simulator.sample_period > 0:
            self.env.process(self.sample_network())

    def sample_network(self):
        """Sample network stats"""
        while not Simulator.complete:
            Simulator.network_stats['time'].append(self.env.now)
            Simulator.network_stats['tor_queue_size'].append(len(self.network.tor_queue.items)) # pkts
            yield self.env.timeout(Simulator.sample_period)

    @staticmethod
    def check_done():
        if Simulator.message_cnt == Simulator.num_messages:
            Simulator.complete = True
            Simulator.finish_time = Simulator.env.now
            Simulator.check_rx_tx_messages()

    @staticmethod
    def check_rx_tx_messages():
        """Check that all transmitted messages were indeed received
        """
        for msg in Simulator.tx_msgs:
            if msg in Simulator.rx_msgs:
                Simulator.rx_msgs.remove(msg)
            else:
                print "ERROR: msg was transmitted but not received"
                msg.show()
                hexdump(msg)
        if len(Simulator.rx_msgs) > 0:
            print "ERROR: msgs were received but not transmitted:"
            for i in range(len(Simulator.rx_msgs)):
                print "msg {}:".format(i)
                Simulator.rx_msgs[i].show()
                hexdump(Simulator.rx_msgs[i])
        else:
            print "SUCCESS: all msgs were successfully delivered!"

    def dump_run_logs(self):
        """Dump any logs recorded during this run of the simulation"""
        out_dir = os.path.join(os.getcwd(), Simulator.out_run_dir)
        if not os.path.exists(out_dir):
            os.makedirs(out_dir)

        # log the message stats
        df = pd.DataFrame({k: pd.Series(l) for k, l in Simulator.message_stats.items()}, dtype=float)
        write_csv(df, os.path.join(Simulator.out_run_dir, 'message_stats.csv'))

        # log the network stats
        df = pd.DataFrame({k: pd.Series(l) for k, l in Simulator.network_stats.items()}, dtype=float)
        write_csv(df, os.path.join(Simulator.out_run_dir, 'network_stats.csv'))

        # log summary of the pkts received by the network
        with open(os.path.join(Simulator.out_run_dir, 'network_pkts.txt'), 'w') as f:
            for p in Simulator.network_pkts:
                f.write('{} -- ({} bytes)\n'.format(p.summary(), len(p)))
