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

# default cmdline args
cmd_parser = argparse.ArgumentParser()
cmd_parser.add_argument('--config', type=str, help='JSON config file to control the simulations', required=True)

####
# Helper functions
####

def compute_num_pkts(msg_len):
    return msg_len/Simulator.max_pkt_len if (msg_len % Simulator.max_pkt_len == 0) else msg_len/Simulator.max_pkt_len + 1

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

    @staticmethod
    def init_params():
        pass

    def log(self, msg):
        self.logger.log("IngressPipe: {}".format(msg))

    def start(self):
        """Receive and process packets from the network queue
        """
        while not Simulator.complete:
            # wait for a pkt from the network
            pkt = yield self.net_queue.get()
            self.log('Received network pkt')
            # TODO(sibanez): do we want to simulate ingress processing latency?
            if pkt[NDP].flags.DATA:
                # Data pkt for msg being received
                rx_msg_id = self.getRxMsgID(pkt[IP].src, pkt[NDP].src_context, pkt[NDP].tx_msg_id, pkt[NDP].msg_len)
                # TODO(sibanez): use rxMsgID to update state generate control pkts
                self.ctrlPktEvent(...)
                data = (AssembleMeta(rx_msg_id, pkt[IP].src, pkt[NDP].src_context, pkt[NDP].msg_len, pkt[NDP].pkt_offset), pkt[NDP].payload)
                self.assemble_queue.put(data)
            else:
                # control pkt for msg being transmitted
                if pkt[NDP].flags.ACK:
                if pkt[NDP].flags.NACK:
                if pkt[NDP].flags.PULL:
                self.deliveredEvent(...)
                self.creditEvent(...)

class AssembleMeta:
    def __init__(self, rx_msg_id, src_ip, src_context, msg_len, pkt_offset):
        self.rx_msg_id = rx_msg_id
        self.src_ip = src_ip
        self.src_context = src_context
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
        self.logger.log(msg)

    def getRxMsgID(self, src_ip, src_port, tx_msg_id, msg_len):
        """
        Obtain the rxMsgID for the indicated message, or try to assign one.
        """
        key = (src_ip, src_port, tx_msg_id)
        # check if this msg has already been allocated an rxMsgID
        if key in self.rx_msg_id_table:
            return self.rx_msg_id_table[key]
        # try to allocate an rxMsgID
        if len(self.rx_msg_id_freelist) > 0:
            rx_msg_id = self.rx_msg_id_freelist.pop(0)
            # add table entry
            self.rx_msg_id_table[key] = rx_msg_id
            # allocate buffer to reassemble the message
            num_pkts = compute_num_pkts(msg_len)
            self.buffers[rx_msg_id] = ["" for i in range(num_pkts)]
            self.received_bitmap[rx_msg_id] = 0
            return rx_msg_id
        return -1

    def start(self):
        """Receive pkts and reassemble into messages
        """
        while not Simulator.complete:
            # wait for a data pkt to arrive: (AssembleMeta, data_pkt)
            data = yield self.assemble_queue.get()
            meta = data[0]
            pkt = data[1]
            # record pkt data in buffer
            self.buffers[meta.rx_msg_id][meta.pkt_offset] = str(pkt)
            # mark the pkt as received
            self.received_bitmap[meta.rx_msg_id] = self.received_bitmap[meta.rx_msg_id] | (1 << meta.pkt_offset)
            # check if all pkts have been received
            num_pkts = compute_num_pkts(meta.msg_len)
            if self.received_bitmap[meta.rx_msg_id] == (1<<num_pkts)-1:
                # push the reassembled msg to the CPU
                msg_data = ''.join(self.buffers[meta.rx_msg_id])
                msg = App(...)/msg_data
                # free the rx_msg_id
                del self.rx_msg_id_table[(...)]
                self.rx_msg_id_freelist.append(meta.rx_msg_id)

class Packetize(object):
    """Packetize messages into data packets and schedule those data packets"""
    def __init__(self):
        self.env = Simulator.env
        self.logger = Logger()
        self.cpu_queue = simpy.Store(env)
        self.env.process(self.start())

    @staticmethod
    def init_params():
        pass

    def log(self, msg):
        self.logger.log(msg)

    def start(self):
        """Receive and process packets
        """
        while not Simulator.complete:
            pass

class Timer(object):
    """Maintain one timer per message to enable reliable delivery"""
    def __init__(self):
        self.env = Simulator.env
        self.logger = Logger()
        self.queue = simpy.Store(env)
        self.env.process(self.start())

    @staticmethod
    def init_params():
        pass

    def log(self, msg):
        self.logger.log(msg)

    def start(self):
        """Receive and process packets
        """
        while not Simulator.complete:
            pass

class PktGen(object):
    """Generate control packets"""
    def __init__(self):
        self.env = Simulator.env
        self.logger = Logger()
        self.queue = simpy.Store(env)
        self.env.process(self.start())

    @staticmethod
    def init_params():
        pass

    def log(self, msg):
        self.logger.log(msg)

    def start(self):
        """Receive and process packets
        """
        while not Simulator.complete:
            pass

# TODO(sibanez): make this an abstract base class
class EgressPipe(object):
    """P4 programmable egress pipeline"""
    def __init__(self):
        self.env = Simulator.env
        self.logger = Logger()
        self.queue = simpy.Store(env)
        self.env.process(self.start())

    @staticmethod
    def init_params():
        pass

    def log(self, msg):
        self.logger.log(msg)

    def start(self):
        """Receive and process packets
        """
        while not Simulator.complete:
            pass

class Arbiter(object):
    """Schedule pkts between PktGen and Packetize modules into EgressPipe"""
    def __init__(self):
        self.env = Simulator.env
        self.logger = Logger()
        self.queue = simpy.Store(env)
        self.env.process(self.start())

    @staticmethod
    def init_params():
        pass

    def log(self, msg):
        self.logger.log(msg)

    def start(self):
        """Receive and process packets
        """
        while not Simulator.complete:
            pass

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
        CPU.message_arrival_gap_dist = DistGenerator('message_arrival_gap')
        CPU.message_size_dist = DistGenerator('message_size')

        # rate at which messages are written to tx queue
        CPU.tx_rate = Simulator.config['tx_rate'].next() # Gbps

    def log(self, msg):
        self.logger.log('CPU: {}'.format(msg))

    def start_rx(self):
        """Start receiving messages"""
        while not Simulator.complete:
            # Wait to receive a message
            msg = yield self.rx_queue.get()
            # record received msg
            Simulator.rx_msgs.append(msg) # includes App header
            # check if simulation is complete
            self.log('Received message')
            # update stats
            Simulator.message_stats['completion_times'].append(self.env.now - msg.send_time) # ns
            Simulator.message_cnt += 1
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
            msg = App(ipv4_addr="10.0.0.1", lnic_addr=0, msg_len=message_size)/SimMessage(send_time=self.env.now)/payload
            # record tx msg
            Simulator.tx_msgs.append(msg) # includes App header
            # send message
            self.tx_queue.put(msg)
            # compute the delay for this message based on the rate and message size
            delay = (message_size*8)/float(CPU.tx_rate) # ns
            yield self.env.timeout(delay)
            # compute inter message gap
            gap = CPU.message_arrival_gap_dist.next() # ns
            Simulator.message_stats['message_arrival_gap'].append(gap)
            yield self.env.timeout(gap)

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
        Simulator.sample_period = Simulator.config['sample_period'].next()
        Simulator.num_messages = Simulator.config['num_messages'].next()
        Simulator.max_pkt_len = Simulator.config['max_pkt_len'].next()
        Simulator.min_message_size = Simulator.config['min_message_size'].next()
        Simulator.max_message_size = Simulator.config['max_message_size'].next()

        # initialize message_stats
        Simulator.message_stats = {'service_times':[],
                                      'message_sizes':[],
                                      'completion_times':[]}
        # initialize buffer_stats
        Simulator.buffer_stats = {'time':[],
                                     'allocation':[],
                                     'utilization':[]}
        # initialize drop stats
        Simulator.drop_stats = {'time':[],
                                   'allocation':[],
                                   'utilization':[],
                                   'message_size':[]}

        # initialize tx/rx message log
        Simulator.tx_msgs = []
        Simulator.rx_msgs = []

        self.logger = Logger()
        self.msg_buffer = MessageBuffer(self.env, self.logger)
        self.msg_generator = MessageGenerator(self.env, self.logger, self.msg_buffer.rx_queue, Simulator.msg_rate)
        self.msg_consumer = MessageConsumer(self.env, self.logger, self.msg_buffer)

        Message.count = 0
        
        self.init_sim()

    def init_sim(self):
        Simulator.complete = False
        Simulator.message_cnt = 0
        Simulator.finish_time = 0
        # start generating messages
        self.env.process(self.cpu.start_tx())
        # start logging
        if Simulator.sample_period > 0:
            self.env.process(self.sample_buffer())

    def sample_buffer(self):
        """Sample avg core queue occupancy at every time"""
        while not Simulator.complete:
            Simulator.buffer_stats['time'].append(self.env.now)
            Simulator.buffer_stats['allocation'].append(self.msg_buffer.get_allocation())
            Simulator.buffer_stats['utilization'].append(self.msg_buffer.get_utilization())
            yield self.env.timeout(Simulator.sample_period)

    @staticmethod
    def check_done():
        if Simulator.message_cnt == Simulator.num_messages:
            Simulator.complete = True
            Simulator.finish_time = Simulator.env.now

    def dump_run_logs(self):
        """Dump any logs recorded during this run of the simulation"""
        out_dir = os.path.join(os.getcwd(), Simulator.out_run_dir)
        if not os.path.exists(out_dir):
            os.makedirs(out_dir)

        # log the buffer stats
        df = pd.DataFrame({k: pd.Series(l) for k, l in Simulator.buffer_stats.items()}, dtype=float)
        write_csv(df, os.path.join(Simulator.out_run_dir, 'buffer_stats.csv'))

        # log the message stats
        df = pd.DataFrame({k: pd.Series(l) for k, l in Simulator.message_stats.items()}, dtype=float)
        write_csv(df, os.path.join(Simulator.out_run_dir, 'message_stats.csv'))

        # log the drop stats
        df = pd.DataFrame({k: pd.Series(l) for k, l in Simulator.drop_stats.items()}, dtype=float)
        write_csv(df, os.path.join(Simulator.out_run_dir, 'drop_stats.csv'))

        # log MessageBuffer size classes
        df = pd.DataFrame({'size_classes': MessageBuffer.size_classes})
        write_csv(df, os.path.join(Simulator.out_run_dir, 'size_classes.csv'))


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
            Message.init_params()
            MessageConsumer.init_params()
            MessageBuffer.init_params()
            MessageGenerator.init_params()
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

