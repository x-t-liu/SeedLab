#!/usr/bin/python3
from scapy.all import *

def print_pkt(pkt):
    pkt.show()

print(sniff(filter="tcp port 23", prn=print_pkt))

