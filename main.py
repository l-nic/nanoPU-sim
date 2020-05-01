#!/usr/bin/env python2

import argparse
import simpy
import sys, os, importlib
import random
from nanoPU_sim import *
from headers import *
from sim_utils import *

# Include transport protocol directory for P4 pipelines
sys.path.append( os.path.dirname(os.path.realpath(__file__)) + \
                 "/transport_protocols")

# default cmdline args
cmd_parser = argparse.ArgumentParser()
cmd_parser.add_argument('--config', type=str, help='JSON config file to control the simulations', required=True)

def run_sim(cmdline_args, *args):
    Simulator.config = parse_config(cmdline_args.config)
    # make sure output directory exists
    Simulator.out_dir = Simulator.config['out_dir'].next()
    out_dir = os.path.join(os.getcwd(), Simulator.out_dir)
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)
    # copy config file into output directory
    os.system('cp {} {}'.format(cmdline_args.config, out_dir))
    # Import the transport protocol's P4 pipelines
    protocolName = Simulator.config['transport_protocol'].next()
    try:
        protocolModule = importlib.import_module(protocolName)
    except ImportError:
        print("ERROR: Could not import {} pipelines.".format(protocolName))
        sys.exit()

    # run the simulations
    run_cnt = 0
    try:
        while True:
            # initialize random seed
            random.seed(1)
            np.random.seed(1)
            # init params for this run on all classes
            protocolModule.IngressPipe.init_params()
            Reassemble.init_params()
            Packetize.init_params()
            TimerModule.init_params()
            protocolModule.PktGen.init_params()
            protocolModule.EgressPipe.init_params()
            Arbiter.init_params()
            CPU.init_params()
            protocolModule.Network.init_params()
            Simulator.out_run_dir = os.path.join(Simulator.out_dir,
                                                 'run-{}'.format(run_cnt))
            env = simpy.Environment()
            Simulator.env = env
            s = Simulator(protocolModule,*args)

            print 'Running simulation {} ...'.format(run_cnt)
            env.run()
            s.dump_run_logs()
            run_cnt += 1
    except StopIteration:
        print 'All Simulations Complete!'

def main():
    args = cmd_parser.parse_args()
    # Run the simulation
    run_sim(args)

if __name__ == '__main__':
    main()
