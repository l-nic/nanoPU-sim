
from scapy.all import *
import struct

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

bind_layers(App, SimMessage)
