#!/usr/bin/env python2

import argparse
import simpy
import pandas as pd
import numpy as np
import sys, os
import abc
import random
import json
from collections import OrderedDict
from headers import NDP

from sim_utils import *

SWITCH_MAC = "08:55:66:77:88:08"
NIC_MAC = "08:11:22:33:44:08"
NIP_IP = "10.0.0.1"

SRC_CONTEXT=0
DST_CONTEXT=0

# default cmdline args
cmd_parser = argparse.ArgumentParser()
cmd_parser.add_argument('--config', type=str, help='JSON config file to control the simulations', required=True)

####
# Helper functions
####

def compute_num_pkts(msg_len):
    return msg_len/Simulator.max_pkt_len if (msg_len % Simulator.max_pkt_len == 0) else msg_len/Simulator.max_pkt_len + 1

def priority_encoder(bitmap):
    """Find the first set bit in the provided bitmap
    """
    if bitmap == 0:
        return None
    assert bitmap > 0, "ERROR: bitmap must be positive"
    bits = bin(bitmap)[2:][::-1]
    return bits.find('1')

#####
# Architecture Elements
#####

class IngressPipe(object):
    """P4 programmable ingress pipeline"""
    def __init__(self, net_queue, assemble_queue):
        self.env = Simulator.env
        self.logger = Logger() 
        self.net_queue = net_queue
        self.assemble_queue = assemble_queue
        self.env.process(self.start())

    @staticmethod
    def init_params():
        pass

    def log(self, msg):
        self.logger.log("IngressPipe: {}".format(msg))

    ########
    # Methods to wire up events/externs
    ########

    def init_getRxMsgID(self, getRxMsgID):
        self.getRxMsgID = getRxMsgID

    def init_deliveredEvent(self, deliveredEvent):
        self.deliveredEvent = deliveredEvent

    def init_creditEvent(self, creditEvent):
        self.creditEvent = creditEvent

    def init_ctrlPktEvent(self, ctrlPktEvent):
        self.ctrlPktEvent = ctrlPktEvent

    def start(self):
        """Receive and process packets from the network
        """
        while not Simulator.complete:
            # wait for a pkt from the network
            pkt = yield self.net_queue.get()
            if pkt[NDP].flags.DATA:
                self.log('Processing data pkt')
                # defaults for generating control pkts
                genACK = False
                genNACK = False
                genPULL = False
                dst_ip = pkt[IP].src
                dst_context = pkt[NDP].src_context
                src_context = pkt[NDP].dst_context
                tx_msg_id = pkt[NDP].tx_msg_id
                msg_len = pkt[NDP].msg_len
                pkt_offset = pkt[NDP].pkt_offset
                pull_offset = 0
                if pkt[NDP].flags.CHOP:
                    self.log('Processing chopped data pkt')
                    # send NACK
                    genNACK = True
                else:
                    # process DATA pkt
                    genACK = True
                    genPULL = True
                    rx_msg_id = self.getRxMsgID(pkt[IP].src, pkt[NDP].src_context, pkt[NDP].tx_msg_id, pkt[NDP].msg_len)
                    # compute pull_offset
                    # TODO: this is not how NDP computes pull_offset, but just to get something running ...
                    pull_offset = pkt[NDP].pkt_offset + Simulator.rtt_pkts
                    data = (ReassembleMeta(rx_msg_id, pkt[IP].src, pkt[NDP].src_context, pkt[NDP].tx_msg_id, pkt[NDP].msg_len, pkt[NDP].pkt_offset), pkt[NDP].payload)
                    self.assemble_queue.put(data)
                # fire event to generate control pkt(s)
                self.ctrlPktEvent(genACK, genNACK, genPULL, dst_ip, dst_context, src_context, tx_msg_id, msg_len, pkt_offset, pull_offset)
            else:
                self.log('Processing control pkt')
                # control pkt for msg being transmitted
                # defaults
                tx_msg_id = pkt[NDP].tx_msg_id
                pkt_offset = pkt[NDP].pkt_offset
                msg_len = pkt[NDP].msg_len
                if pkt[NDP].flags.ACK or pkt[NDP].flags.NACK:
                    was_delivered = pkt[NDP].flags.ACK
                    self.log('msg: {}, pkt: {}, was_delivered: {}'.format(tx_msg_id, pkt_offset, was_delivered))
                    # fire event to update state in packetization module
                    self.deliveredEvent(tx_msg_id, pkt_offset, msg_len, was_delivered)
                if pkt[NDP].flags.PULL:
                    self.log('Received PULL pkt for msg {}, pull offset: {}'.format(tx_msg_id, pkt[NDP].pkt_offset))
                    # increase credit
                    # TODO: this is not how NDP updates credit, but just to get something running ...
                    credit = pkt[NDP].pkt_offset
                    self.creditEvent(tx_msg_id, credit)

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

    def getRxMsgID(self, src_ip, src_context, tx_msg_id, msg_len):
        """Obtain the rx_msg_id for the indicated message, or try to assign one.
        """
        key = (src_ip, src_context, tx_msg_id)
        self.log('Processing getRxMsgID extern call for: {}'.format(key))
        # check if this msg has already been allocated an rx_msg_id
        if key in self.rx_msg_id_table:
            self.log('Found rx_msg_id: {}'.format(self.rx_msg_id_table[key]))
            return self.rx_msg_id_table[key]
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
            return rx_msg_id
        self.log('ERROR: failed to allocate rx_msg_id for: {}'.format(key))
        return -1

    def start(self):
        """Receive pkts and reassemble into messages
        """
        while not Simulator.complete:
            # wait for a data pkt to arrive: (AssembleMeta, data_pkt)
            (meta, pkt) = yield self.assemble_queue.get()
            self.log('Processing pkt {} for msg {}'.format(meta.pkt_offset, meta.rx_msg_id))
            # record pkt data in buffer
            self.buffers[meta.rx_msg_id][meta.pkt_offset] = str(pkt)
            # mark the pkt as received
            # NOTE: received_bitmap must have 2 write ports
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
                # NOTE: the rx_msg_id_table must have 2 write ports: here and in getRxMsgID()
                del self.rx_msg_id_table[(meta.src_ip, meta.src_context, meta.tx_msg_id)]
                self.rx_msg_id_freelist.append(meta.rx_msg_id)

class Packetize(object):
    """Packetize messages into data packets"""
    def __init__(self, cpu_queue):
        self.env = Simulator.env
        self.logger = Logger()
        self.cpu_queue = cpu_queue

        ####
        # initialize state
        ####
        # freelist of tx msg ids
        self.tx_msg_id_freelist = [i for i in range(Packetize.max_messages)]
        # FIFO queue of active message IDs
        self.active_messages_fifo = simpy.Store(self.env)
        # bitmap to track which messages are currently active
        self.active_messages_bitmap = 0
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

        self.env.process(self.start())


    @staticmethod
    def init_params():
        Packetize.max_messages = Simulator.config['packetize_max_messages'].next()

    def log(self, msg):
        self.logger.log('Packetize: {}'.format(msg))

    ####
    # Event Methods
    ####

    def deliveredEvent(self, tx_msg_id, pkt_offset, msg_len, was_delivered):
        """Mark a packet as either having been delivered or dropped
        """
        self.log("Processing deliveredEvent for msg {}".format(tx_msg_id))
        if (tx_msg_id in self.delivered) and (tx_msg_id in self.toBtx):
            if was_delivered:
                self.log("Marking pkt as delivered")
                delivered_bitmap = self.delivered[tx_msg_id]
                self.delivered[tx_msg_id] = delivered_bitmap | (1<<pkt_offset)
                # check if the whole message has been delivered
                num_pkts = compute_num_pkts(msg_len)
                if delivered_bitmap == (1<<num_pkts)-1:
                    self.log("The whole msg was delivered!")
                    # cancel the timer for this msg
                    self.cancelTimerEvent(tx_msg_id)
                    # free the tx_msg_id
                    self.tx_msg_id_freelist.append(tx_msg_id)                
            else:
                self.log("Marking the pkt for retransmission")
                toBtx_bitmap = self.toBtx[tx_msg_id]
                self.toBtx[tx_msg_id] = toBtx_bitmap | (1<<pkt_offset)
                # make the message active
                self.enq_active_messages_fifo(tx_msg_id)
        else:
            self.log("ERROR: deliveredEvent was triggered for unknown tx_msg_id: {}".format(tx_msg_id))

    # TODO(sibanez): what is the best way to expose the credit state to the ingress pipeline?
    def creditEvent(self, tx_msg_id, credit):
        self.log('Processing creditEvent for msg {}, credit = {}'.format(tx_msg_id, credit))
        # set the credit for the specified msg
        if (tx_msg_id in self.credit):
            if credit > self.credit[tx_msg_id]:
                self.log('Increasing credit for msg {} from {} to {}'.format(tx_msg_id, self.credit[tx_msg_id], credit))
                self.credit[tx_msg_id] = credit
                # make the message active
                self.enq_active_messages_fifo(tx_msg_id)
        else:
            self.log('ERROR: creditEvent was triggered for unknown tx_msg_id: {}'.format(tx_msg_id))

    def timeoutEvent(self, tx_msg_id, rtx_offset):
        self.log('Processing timeoutEvent for msg {}'.format(tx_msg_id))
        # Mark all undelivered the pkts before the specified offset for retransmission
        delivered_bitmap = self.delivered[tx_msg_id]
        rtx_pkts_mask = (1<<rtx_offset)-1
        rtx_pkts = ~delivered_bitmap & rtx_pkts_mask
        self.log('Pkts to retransmit: {:b}'.format(rtx_pkts))
        toBtx_bitmap = self.toBtx[tx_msg_id]
        self.toBtx[tx_msg_id] = toBtx_bitmap | rtx_pkts
        # reschedule timer for this msg
        self.rescheduleTimerEvent(tx_msg_id, self.max_tx_pkt_offset[tx_msg_id])
        if rtx_pkts != 0:
            # make the message active
            self.enq_active_messages_fifo(tx_msg_id)

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
                # schedule a timer for this msg
                self.scheduleTimerEvent(tx_msg_id, 0)
                # make this message active
                self.enq_active_messages_fifo(tx_msg_id)
            else:
                self.log('ERROR: dropping message due to lack of an available tx_msg_id')

    def enq_active_messages_fifo(self, tx_msg_id):
        # make sure msg is not already active
        if self.active_messages_bitmap & (1<<tx_msg_id) == 0:
            self.log('Enqueueing msg {} into active_messages_fifo')
            self.active_messages_fifo.put(tx_msg_id)
            # mark as active (flip bit)
            self.active_messages_bitmap = self.active_messages_bitmap ^ (1<<tx_msg_id)
        else:
            self.log('Msg {} is already active')

    def dequeue(self):
        """Send a data pkt to the arbiter. The arbiter invokes this method when it decides to
           schedule a data pkt.
        """
        wait_active_msg_event = self.active_messages_fifo.get()
        try:
            # wait for a msg to become active
            tx_msg_id = yield wait_active_msg_event
        except simpy.Interrupt as i:
            wait_active_msg_event.cancel()
            self.log('dequeue() interrupted')
            self.env.exit(None)

        self.log('Transmiting pkt from msg {}'.format(tx_msg_id))
        # mark msg as inactive (flip bit)
        self.active_messages_bitmap = self.active_messages_bitmap ^ (1<<tx_msg_id)
        # lookup which pkts of this msg need to be transmitted
        toBtx_bitmap = self.toBtx[tx_msg_id]
        credit = self.credit[tx_msg_id]
        credit_bitmap = (1<<credit)-1
        # the only pkts that are eligible are the ones at an index < credit
        eligible_pkts_bitmap = toBtx_bitmap & credit_bitmap
        # use priority encoder to pick pkt to send
        pkt_offset = priority_encoder(eligible_pkts_bitmap)
        if pkt_offset is not None:
            self.log('Transmiting pkt {} from msg {}'.format(pkt_offset, tx_msg_id))
            pkt_data = self.buffers[tx_msg_id][pkt_offset]
            app_hdr = self.app_header[tx_msg_id]
            meta = EgressMeta(is_data=True,
                              dst_ip=app_hdr.ipv4_addr,
                              src_context=SRC_CONTEXT,
                              dst_context=app_hdr.context_id,
                              tx_msg_id=tx_msg_id,
                              msg_len=app_hdr.msg_len,
                              pkt_offset=pkt_offset)
            # clear pkt in toBtx state
            self.toBtx[tx_msg_id] = toBtx_bitmap ^ (1<<pkt_offset)
            # check if msg has more pkts to transmit
            if eligible_pkts_bitmap ^ (1<<pkt_offset) != 0:
                self.enq_active_messages_fifo(tx_msg_id)
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
            self.log('Timer cancelled for msg {}'.format(tx_msg_id))

    def cancelTimerEvent(self, tx_msg_id):
        self.timer_events[tx_msg_id].interrupt('Timer Cancelled!')


class PktGen(object):
    """Generate control packets"""
    def __init__(self, arbiter_queue):
        self.env = Simulator.env
        self.logger = Logger()
        self.arbiter_queue = arbiter_queue
        self.pacer_queue = simpy.Store(self.env)
        self.env.process(self.start_pacer())

    @staticmethod
    def init_params():
        pass

    def log(self, msg):
        self.logger.log('PktGen: {}'.format(msg))

    def ctrlPktEvent(self, genACK, genNACK, genPULL, dst_ip, dst_context, src_context, tx_msg_id, msg_len, pkt_offset, pull_offset):
        self.log('Processing ctrlPktEvent, genACK: {}, genNACK: {}, genPULL: {}'.format(genACK, genNACK, genPULL))
        # generate control pkt
        meta = EgressMeta(is_data=False, dst_ip=dst_ip)
        ndp = NDP(src_context=src_context,
                  dst_context=dst_context,
                  tx_msg_id=tx_msg_id,
                  msg_len=msg_len)
        if genACK:
            ndp.flags = "ACK"
            ndp.pkt_offset = pkt_offset
            self.arbiter_queue.put((meta, ndp))
        if genNACK:
            ndp.flags = "NACK"
            ndp.pkt_offset = pkt_offset
            self.arbiter_queue.put((meta, ndp))
        if genPULL:
            ndp.flags = "PULL"
            ndp.pkt_offset = pull_offset
            self.pacer_queue.put((meta, ndp))

    def start_pacer(self):
        """Start pacing generated PULL pkts
        """
        while not Simulator.complete:
            data = yield self.pacer_queue.get()
            # For now, assume that each PULL pkt pulls one max size pkt
            delay = Simulator.max_pkt_len*8/Simulator.rx_link_rate # ns
            yield self.env.timeout(delay)
            self.log('Pacer is releasing a PULL pkt')
            self.arbiter_queue.put(data)

class EgressMeta:
    def __init__(self, is_data, dst_ip, src_context=0, dst_context=0, tx_msg_id=0, msg_len=0, pkt_offset=0):
        self.is_data = is_data
        self.dst_ip = dst_ip
        self.src_context = src_context
        self.dst_context = dst_context
        self.tx_msg_id = tx_msg_id
        self.msg_len = msg_len
        self.pkt_offset = pkt_offset

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
            ip = IP(dst=meta.dst_ip, src=NIC_IP)
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
                self.log('Processing control pkt')
                # add Ethernet/IP headers to control pkts
                pkt = eth/ip/pkt
            # send pkt into network
            self.net_queue.put(pkt)

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
            # wait for either the pktize module or the pktgen module to have a pkt ready
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
            Simulator.message_cnt += 1
            # check if simulation is complete
            Simulator.check_done()

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
            msg = App(ipv4_addr=NIC_IP, context_id=DST_CONTEXT, msg_len=message_size)/SimMessage(send_time=self.env.now)/payload
            # record tx msg
            Simulator.tx_msgs.append(msg[App].payload) # no App header
            # send message
            self.tx_queue.put(msg)
            # compute the delay for this message based on the rate and message size
            delay = (message_size*8)/float(CPU.tx_rate) # ns
            yield self.env.timeout(delay)

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
        Network.data_pkt_trim_prob = Simulator.config['data_pkt_trim_prob'].next()

    def log(self, msg):
        self.logger.log('Network: {}'.format(msg))

    def forward_data(self, pkt):
        delay = Network.data_pkt_delay_dist.next()
        self.log('Forwarding data pkt with delay {}'.format(delay))
        yield self.env.timeout(delay)
        self.tor_queue.put(NetworkPkt(pkt, priority=1))

    def forward_ctrl(self, pkt):
        delay = Network.ctrl_pkt_delay_dist.next()
        self.log('Forwarding control pkt with delay {}'.format(delay))
        yield self.env.timeout(delay)
        self.tor_queue.put(NetworkPkt(pkt, priority=0))

    def start_rx(self):
        """Start receiving messages"""
        while not Simulator.complete:
            # Wait to receive a pkt
            pkt = yield self.rx_queue.get()
            self.log('Received pkt')
            if pkt[NDP].flags.DATA:
                if random.random() < Network.data_pkt_trim_prob:
                    self.log('Trimming data pkt')
                    # trim pkt
                    pkt[NDP].flags.CHOP = True
                    if len(pkt) > 64:
                        pkt = Ether(str(pkt)[0:64])
                    self.env.process(self.forward_ctrl(pkt))
                else:
                    self.env.process(self.forward_data(pkt))
            else:
                self.env.process(self.forward_ctrl(pkt))

    def start_tx(self):
        """Start transmitting pkts from the TOR queue to the TX queue"""
        while not Simulator.complete:
            net_pkt = yield self.tor_queue.get()
            self.log('Transmitting pkt to IngressPipe')
            pkt = net_pkt.pkt
            self.tx_queue.put(pkt)
            # delay based on pkt length and link rate
            delay = len(pkt)*8/Simulator.rx_link_rate
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
    def __init__(self):
        self.env = Simulator.env
        # initialize params
        Simulator.sample_period = Simulator.config['sample_period'].next()
        Simulator.num_messages = Simulator.config['num_messages'].next()
        Simulator.max_pkt_len = Simulator.config['max_pkt_len'].next()
        Simulator.min_message_size = Simulator.config['min_message_size'].next()
        Simulator.max_message_size = Simulator.config['max_message_size'].next()
        Simulator.rx_link_rate = Simulator.config['rx_link_rate'].next()
        Simulator.rtt_pkts = Simulator.config['rtt_pkts'].next()

        # initialize message_stats
        Simulator.message_stats = {'message_sizes':[],
                                   'completion_times':[]}

        Simulator.network_stats = {'time': [],
                                   'tor_queue_size':[]}

        # TODO(sibanez): add more stats

        # initialize tx/rx message log
        Simulator.tx_msgs = []
        Simulator.rx_msgs = []

        self.logger = Logger()

        # create queues
        ingress_net_queue = simpy.Store(self.env)
        egress_net_queue = simpy.Store(self.env)
        assemble_queue = simpy.Store(self.env)
        cpu_rx_queue = simpy.Store(self.env)
        cpu_tx_queue = simpy.Store(self.env)
        pktgen_arbiter_queue = simpy.Store(self.env)
        egress_arbiter_queue = simpy.Store(self.env)

        # instantiate modules
        self.ingress = IngressPipe(ingress_net_queue, assemble_queue)
        self.reassemble = Reassemble(assemble_queue, cpu_rx_queue)
        self.packetize = Packetize(cpu_tx_queue)
        self.timer = TimerModule()
        self.pktgen = PktGen(pktgen_arbiter_queue)
        self.egress = EgressPipe(egress_net_queue, egress_arbiter_queue)
        self.arbiter = Arbiter(egress_arbiter_queue, pktgen_arbiter_queue, self.packetize)
        self.cpu = CPU(cpu_tx_queue, cpu_rx_queue)
        self.network = Network(egress_net_queue, ingress_net_queue)

        # wire up events/externs
        self.ingress.init_getRxMsgID(self.reassemble.getRxMsgID)
        self.ingress.init_deliveredEvent(self.packetize.deliveredEvent)
        self.ingress.init_creditEvent(self.packetize.creditEvent)
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
        if len(Simulator.rx_msgs) > 0:
            print "ERROR: msgs were received but not transmitted:"
            for i in range(len(Simulator.rx_msgs)):
                print "msg {}:".format(i)
                Simulator.rx_msgs[i].show()
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


def run_sim(cmdline_args, *args):
    Simulator.config = parse_config(cmdline_args.config)
    # make sure output directory exists
    Simulator.out_dir = Simulator.config['out_dir'].next()
    out_dir = os.path.join(os.getcwd(), Simulator.out_dir)
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)
    # copy config file into output directory
    os.system('cp {} {}'.format(cmdline_args.config, out_dir))
    # run the simulations
    run_cnt = 0
    try:
        while True:
            print 'Running simulation {} ...'.format(run_cnt)
            # initialize random seed
            random.seed(1)
            np.random.seed(1)
            # init params for this run on all classes
            IngressPipe.init_params()
            Reassemble.init_params()
            Packetize.init_params()
            TimerModule.init_params()
            PktGen.init_params()
            EgressPipe.init_params()
            Arbiter.init_params()
            CPU.init_params()
            Network.init_params()
            Simulator.out_run_dir = os.path.join(Simulator.out_dir, 'run-{}'.format(run_cnt))
            run_cnt += 1
            env = simpy.Environment()
            Simulator.env = env
            s = Simulator(*args)
            env.run()
            s.dump_run_logs()
    except StopIteration:
        print 'All Simulations Complete!'

def main():
    args = cmd_parser.parse_args()
    # Run the simulation
    run_sim(args)

if __name__ == '__main__':
    main()

