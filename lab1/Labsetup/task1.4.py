#!/usr/bin/python3
from scapy.all import *

def print_pkt(pkt):
    send(IP(src=pkt[IP].dst, dst=pkt[IP].src)/ICMP(type="echo-reply", code= 0, id=pkt[ICMP].id, seq=pkt[ICMP].seq))

pkt = sniff(filter="icmp[icmptype]==icmp-echo",prn=print_pkt)

