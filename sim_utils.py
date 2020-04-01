import simpy
import pandas as pd
import numpy as np
import sys, os
import json

from nanoPU_sim import Simulator

class Logger(object):
    debug = False
    def __init__(self):
        self.env = Simulator.env

    @staticmethod
    def init_params():
        pass

    def log(self, s):
        if Logger.debug:
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

