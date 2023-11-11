#!/usr/bin/python3
from scapy.all import *

def print_pkt(pkt):
    return pkt.summary()

pkt = sniff(filter="net 128.230.0.0/16",prn=print_pkt)
print(pkt)

