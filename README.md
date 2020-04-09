
# Overview

This repository contains a SimPy behavioral model of the nanoPU
P4 L-NIC architecture.

# Running the Simulation

```
$ ./main.py --config config.json
```

# Configuration

The simulation parameters are in `config.json`. Here is an example:

```
{
  "out_dir": "out",
  "transport_protocol": "ndp",
  "num_messages": 1,
  "message_size": "fixed",
  "message_size_value": 10,
  "rtt_pkts": 10,
  "data_pkt_trim_prob": [0],
  "max_pkt_len": 100,
  "min_message_size": 10,
  "max_message_size": 10000,
  "rx_link_rate": 100,
  "tx_link_rate": 100,
  "reassemble_max_messages": 100,
  "packetize_max_messages": 100,
  "sample_period": 500,
  "timeout_ns": 10000,
  "max_num_timeouts": 5,
  "cpu_tx_rate": 100,
  "ctrl_pkt_delay": "fixed",
  "ctrl_pkt_delay_value": 1000,
  "data_pkt_delay": "fixed",
  "data_pkt_delay_value": 1000
}
```

At least one parameter value must be a list. Using the above configuration
file will result in 3 simulation runs. Each run will use a different value
for the "data_pkt_trim_prob" parameter. `run-0`, `run-1`, and `run-2` will
use "data_pkt_trim_prob" = 0, 0.2, and 0.4, respectively. Any simulation
logs will be written to directory `out/`.

# NanoPU P4 L-NIC Architecture Implementation

The architecture implementation is in `./nanoPU_sim.py`.
