
from scapy.all import *
import struct

NDP_PROTO = 0x99

class NDP(Packet):
    name = "NDP"
    fields_desc = [
        FlagsField("flags", 0, 8, ["DATA", "ACK", "NACK", "PULL",
                                   "CHOP", "F1", "F2", "F3"]),
        ShortField("src_context", 0),
        ShortField("dst_context", 0),
        ShortField("tx_msg_id", 0),
        ShortField("msg_len", 0),
        ShortField("pkt_offset", 0) # or should this be byte offset? Or should the header include both?
    ]

class HOMA(Packet):
    name = "HOMA"
    fields_desc = [
        FlagsField("op_code", 0, 8, ["ALL_DATA", "DATA", "GRANT",
                                     "LOG_TIME_TRACE", "RESEND",
                                     "BUSY", "ABORT", "BOGUS"]),
        ShortField("rpc_id", 0), # should be unique for every RPC
        FlagsField("flags", 0, 4, ["FROM_SERVER", "FROM_CLIENT",
                                   "RETRANSMISSION", "RESTART"]),
        ShortField("msg_len", 0),
        ShortField("pkt_offset", 0), # or should this be byte offset? Or should the header include both?
        ShortField("unscheduled_pkts", 0), # or should this be in bytes? Or should the header include both?
        ShortField("prio",8),
        ShortField("tx_msg_id", 0) # originally not in Homa definition, but required for NanoTransport architecture
    ]

class App(Packet):
    name = "App"
    fields_desc = [
        IPField("ipv4_addr", "0.0.0.0"),
        ShortField("context_id", 0),
        ShortField("msg_len", 0)
    ]

class SimMessage(Packet):
    name = "SimMessage"
    fields_desc = [
        LongField("send_time", 0)
    ]

bind_layers(IP, NDP, proto=NDP_PROTO)
bind_layers(App, SimMessage)
