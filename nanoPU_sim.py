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

# default cmdline args
cmd_parser = argparse.ArgumentParser()
cmd_parser.add_argument('--config', type=str, help='JSON config file to control the simulations', required=True)

def make_cdf_sum(data, colname):
    """Inputs:
         data - input dataframe
         colname - name of column within data to compute CDF of
       Returns:
         A dataframe containing a column called 'cdf', which is a
         weighted CDF of the data in column colname
    """
    df = pd.DataFrame()
    # NOTE: this is "sum" rather than "count", so it is a weighted CDF
    df['sum'] = data.groupby(colname)[colname].sum()
    df['cumsum'] = df['sum'].cumsum()
    df['cdf'] = df['cumsum']/float(df['sum'].sum())
    return df

def find_closest(df, colname, val):
    """Return the index of the row with the closest value to val in column colname
    """
    return df.iloc[(df[colname]-val).abs().argsort()].head(1).index[0]

class Logger(object):
    debug = False
    def __init__(self, env):
        self.env = env

    @staticmethod
    def init_params():
        pass

    def log(self, s):
        if Logger.debug:
            print '{}: {}'.format(self.env.now, s)


class Message(object):
    """This class represents a message to buffered then processed
    """
    count = 0
    def __init__(self, service_time, size, start_time):
        self.service_time = service_time
        self.size = size
        self.start_time = start_time
        self.ID = Message.count
        Message.count += 1

    @staticmethod
    def init_params():
        pass

    def __str__(self):
        return "Message: service_time={}, size={}, start_time={}".format(self.service_time, self.size, self.start_time)

class MessageConsumer(object):
    """Class that consumes messages"""
    def __init__(self, env, logger, msg_buffer):
        self.env = env
        self.logger = logger
        self.msg_buffer = msg_buffer
        self.queue = simpy.Store(env)
        self.env.process(self.start())

    @staticmethod
    def init_params():
        pass

    def log(self, msg):
        self.logger.log(msg)

    def start(self):
        """Receive and process messages
        """
        while not NicSimulator.complete:
            # wait for an enqueue event
            buf = yield self.msg_buffer.enq_event_queue.get()
            # free the buffer
            self.msg_buffer.free_buf(buf)
            # process the message
            yield self.env.timeout(buf.msg.service_time)
            self.log('Finished processing message')
            # update stats
            NicSimulator.message_stats['completion_times'].append((self.env.now - buf.msg.start_time)*1e-3) # us
            NicSimulator.message_cnt += 1
            NicSimulator.check_done(self.env.now)

class Buffer(object):
    """Simple class representing a buffer containing a single message
    """
    def __init__(self, msg, size):
        self.msg = msg
        self.size = size

class MessageBuffer(object):
    """Class that buffers messages"""
    def __init__(self, env, logger):
        self.env = env
        self.logger = logger

        self.rx_queue = simpy.Store(env)
        self.enq_event_queue = simpy.Store(env)

        #### Initialize buffers ####
        # Generate message size samples
        message_sizes = [MessageGenerator.message_size_dist.next() for x in range(100000)]
        # Compute cumulative fraction of all bytes CDF
        cdf_df = make_cdf_sum(pd.DataFrame({'message_sizes': message_sizes}), 'message_sizes')
        # Compute size classes by looking at the CDF
        MessageBuffer.size_classes = []
        for val in np.linspace(0.0, 1.0, MessageBuffer.num_size_classes+1)[1:]:
            bound = find_closest(cdf_df, 'cdf', val)
            MessageBuffer.size_classes.append(int(bound))
#        MessageBuffer.size_classes.append(NicSimulator.max_message_size)
        # Allocate buffers to each size class
        bytes_per_class = MessageBuffer.buffer_size/MessageBuffer.num_size_classes
        self.buffers = OrderedDict()
        print 'Buffer Allocations:'
        for buf_size in MessageBuffer.size_classes:
            num_bufs = bytes_per_class/buf_size
            self.buffers[buf_size] = num_bufs
            print '{} bytes = {} buffers ({} total bytes)'.format(buf_size, num_bufs, buf_size*num_bufs)
        self.allocated_bytes = 0
        self.utilized_bytes = 0

        self.env.process(self.start())

    @staticmethod
    def init_params():
        MessageBuffer.buffer_size = NicSimulator.config['buffer_size'].next()
        MessageBuffer.num_size_classes = NicSimulator.config['num_size_classes'].next()
        MessageBuffer.allocation_policy = NicSimulator.config['allocation_policy'].next()

    def enq_msg_flexible(self, msg):
        """Allocate a buffer for the given message. Drop the message if there are no
           available buffers that are large enough to store the message.
        """
        # Find the smallest possible buffer that can hold the message
        for buf_size, num_bufs in self.buffers.items():
            if (buf_size >= msg.size and num_bufs > 0):
                self.buffers[buf_size] -= 1
                self.allocated_bytes += buf_size
                self.utilized_bytes += msg.size
                return Buffer(msg, buf_size)
        return None

    def enq_msg_strict(self, msg):
        """Allocate a buffer for the given message. Drop the message if there are no
           available buffers for this message's size class.
        """
        for buf_size, num_bufs in self.buffers.items():
            if (buf_size >= msg.size and num_bufs > 0):
                self.buffers[buf_size] -= 1
                self.allocated_bytes += buf_size
                self.utilized_bytes += msg.size
                return Buffer(msg, buf_size)
            else:
                return None
        return None

    def free_buf(self, buf):
        """Free the given buffer and make it available for future messages
        """
        self.buffers[buf.size] += 1
        self.allocated_bytes -= buf.size
        self.utilized_bytes -= buf.msg.size

    def get_allocation(self):
        return float(self.allocated_bytes)/MessageBuffer.buffer_size

    def get_utilization(self):
        return float(self.utilized_bytes)/MessageBuffer.buffer_size

    def start(self):
        """Start receiving messages and buffering them
        """
        while not NicSimulator.complete:
            # wait for a message to arrive
            msg = yield self.rx_queue.get()
            # enqueue message into buffer
            if (MessageBuffer.allocation_policy == "flexible"):
                buf = self.enq_msg_flexible(msg)
            elif (MessageBuffer.allocation_policy == "strict"):
                buf = self.enq_msg_strict(msg)
            else:
                sys.exit('Unsupported allocation policy: {}'.format(MessageBuffer.allocation_policy))
            # fire an enqueue event
            if buf is not None:
                self.enq_event_queue.put(buf)
            else:
                # message was dropped
                NicSimulator.drop_stats['time'].append(self.env.now)
                NicSimulator.drop_stats['allocation'].append(self.get_allocation())
                NicSimulator.drop_stats['utilization'].append(self.get_utilization())
                NicSimulator.drop_stats['message_size'].append(msg.size)
                # update message stats
                NicSimulator.message_stats['completion_times'].append(None) # None means message was dropped
                NicSimulator.message_cnt += 1
                NicSimulator.check_done(self.env.now)

def DistGenerator(varname):
    dist = NicSimulator.config[varname].next()
    # initialize variable params
    kwargs = {}
    if dist == 'uniform':
        kwargs['min'] = NicSimulator.config['{}_min'.format(varname)].next()
        kwargs['max'] = NicSimulator.config['{}_max'.format(varname)].next()
    elif dist == 'normal':
        kwargs['mean']   = NicSimulator.config['{}_mean'.format(varname)].next()
        kwargs['stddev'] = NicSimulator.config['{}_stddev'.format(varname)].next()
    elif dist == 'poisson':
        kwargs['lambda'] = NicSimulator.config['{}_lambda'.format(varname)].next()
    elif dist == 'lognormal':
        kwargs['mean'] = NicSimulator.config['{}_mean'.format(varname)].next()
        kwargs['sigma'] = NicSimulator.config['{}_sigma'.format(varname)].next()
    elif dist == 'exponential':
        kwargs['lambda'] = NicSimulator.config['{}_lambda'.format(varname)].next()
    elif dist == 'fixed':
        kwargs['value'] = NicSimulator.config['{}_value'.format(varname)].next()
    elif dist == 'bimodal':
        kwargs['lower_mean']    = NicSimulator.config['{}_lower_mean'.format(varname)].next()
        kwargs['lower_stddev']  = NicSimulator.config['{}_lower_stddev'.format(varname)].next()
        kwargs['lower_samples'] = NicSimulator.config['{}_lower_samples'.format(varname)].next()
        kwargs['upper_mean']    = NicSimulator.config['{}_upper_mean'.format(varname)].next()
        kwargs['upper_stddev']  = NicSimulator.config['{}_upper_stddev'.format(varname)].next()
        kwargs['upper_samples'] = NicSimulator.config['{}_upper_samples'.format(varname)].next()
    elif dist == 'custom':
        kwargs['csv'] = NicSimulator.config['{}_csv'.format(varname)].next()

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

class MessageGenerator(object):
    """Class that generates messages
    """
    def __init__(self, env, logger, queue, rate):
        self.env = env
        self.logger = logger
        # this queue will be drained by the message buffer
        self.queue = queue
        # the rate at which messages should be generated
        self.rate = rate # Gbps

    @staticmethod
    def init_params():
        # generate distributions
        MessageGenerator.service_time_dist = DistGenerator('service_time')
        MessageGenerator.message_size_dist = DistGenerator('message_size')

    def log(self, msg):
        self.logger.log(msg)

    def start(self):
        """Start generating messages"""
        for i in range(NicSimulator.num_messages):
            self.log('Generating message')
            # generate and record service time
            service_time = MessageGenerator.service_time_dist.next()
            NicSimulator.message_stats['service_times'].append(service_time*1e-3) # us
            # generate and record message size
            message_size = MessageGenerator.message_size_dist.next()
            if (message_size < NicSimulator.min_message_size):
                message_size = NicSimulator.min_message_size
            if (message_size > NicSimulator.max_message_size):
                message_size = NicSimulator.max_message_size
            NicSimulator.message_stats['message_sizes'].append(message_size)
            # put the message in the queue
            self.queue.put(Message(service_time, message_size, self.env.now))
            # compute the delay for this message based on the rate and message size
            delay = (message_size*8)/float(self.rate) # ns
            yield self.env.timeout(delay)


class NicSimulator(object):
    """This class controls the simulation"""
    config = {} # user specified input
    out_dir = 'out'
    out_run_dir = 'out/run-0'
    # run local variables
    complete = False
    finish_time = 0
    message_cnt = 0
    def __init__(self, env):
        self.env = env
        NicSimulator.sample_period = NicSimulator.config['sample_period'].next()
        NicSimulator.num_messages = NicSimulator.config['num_messages'].next()
        NicSimulator.msg_rate = NicSimulator.config['message_rate'].next()
        NicSimulator.min_message_size = NicSimulator.config['min_message_size'].next()
        NicSimulator.max_message_size = NicSimulator.config['max_message_size'].next()

        # initialize message_stats
        NicSimulator.message_stats = {'service_times':[],
                                      'message_sizes':[],
                                      'completion_times':[]}
        # initialize buffer_stats
        NicSimulator.buffer_stats = {'time':[],
                                     'allocation':[],
                                     'utilization':[]}
        # initialize drop stats
        NicSimulator.drop_stats = {'time':[],
                                   'allocation':[],
                                   'utilization':[],
                                   'message_size':[]}

        self.logger = Logger(env)
        self.msg_buffer = MessageBuffer(self.env, self.logger)
        self.msg_generator = MessageGenerator(self.env, self.logger, self.msg_buffer.rx_queue, NicSimulator.msg_rate)
        self.msg_consumer = MessageConsumer(self.env, self.logger, self.msg_buffer)

        Message.count = 0
        
        self.init_sim()

    def init_sim(self):
        NicSimulator.complete = False
        NicSimulator.message_cnt = 0
        NicSimulator.finish_time = 0
        # start generating requests
        self.env.process(self.msg_generator.start())
        # start logging
        if NicSimulator.sample_period > 0:
            self.env.process(self.sample_buffer())

    def sample_buffer(self):
        """Sample avg core queue occupancy at every time"""
        while not NicSimulator.complete:
            NicSimulator.buffer_stats['time'].append(self.env.now)
            NicSimulator.buffer_stats['allocation'].append(self.msg_buffer.get_allocation())
            NicSimulator.buffer_stats['utilization'].append(self.msg_buffer.get_utilization())
            yield self.env.timeout(NicSimulator.sample_period)

    @staticmethod
    def check_done(now):
        if NicSimulator.message_cnt == NicSimulator.num_messages:
            NicSimulator.complete = True
            NicSimulator.finish_time = now

    def dump_run_logs(self):
        """Dump any logs recorded during this run of the simulation"""
        out_dir = os.path.join(os.getcwd(), NicSimulator.out_run_dir)
        if not os.path.exists(out_dir):
            os.makedirs(out_dir)

        # log the buffer stats
        df = pd.DataFrame({k: pd.Series(l) for k, l in NicSimulator.buffer_stats.items()}, dtype=float)
        write_csv(df, os.path.join(NicSimulator.out_run_dir, 'buffer_stats.csv'))

        # log the message stats
        df = pd.DataFrame({k: pd.Series(l) for k, l in NicSimulator.message_stats.items()}, dtype=float)
        write_csv(df, os.path.join(NicSimulator.out_run_dir, 'message_stats.csv'))

        # log the drop stats
        df = pd.DataFrame({k: pd.Series(l) for k, l in NicSimulator.drop_stats.items()}, dtype=float)
        write_csv(df, os.path.join(NicSimulator.out_run_dir, 'drop_stats.csv'))

        # log MessageBuffer size classes
        df = pd.DataFrame({'size_classes': MessageBuffer.size_classes})
        write_csv(df, os.path.join(NicSimulator.out_run_dir, 'size_classes.csv'))


def write_csv(df, filename):
    with open(filename, 'w') as f:
            f.write(df.to_csv(index=False))

def param(x):
    while True:
        yield x

def param_list(L):
    for x in L:
        yield x

def parse_config(config_file):
    """ Convert each parameter in the JSON config file into a generator
    """
    with open(config_file) as f:
        config = json.load(f)

    for p, val in config.iteritems():
        if type(val) == list:
            config[p] = param_list(val)
        else:
            config[p] = param(val)

    return config

def run_sim(cmdline_args, *args):
    NicSimulator.config = parse_config(cmdline_args.config)
    # make sure output directory exists
    NicSimulator.out_dir = NicSimulator.config['out_dir'].next()
    out_dir = os.path.join(os.getcwd(), NicSimulator.out_dir)
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
            NicSimulator.out_run_dir = os.path.join(NicSimulator.out_dir, 'run-{}'.format(run_cnt))
            run_cnt += 1
            env = simpy.Environment()
            s = NicSimulator(env, *args)
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

