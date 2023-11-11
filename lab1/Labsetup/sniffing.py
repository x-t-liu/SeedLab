#!/usr/bin/env python3
from scapy.all import *
def print_pkt(pkt):
 pkt.show()

str=input("br-... (default no iface):")
if len(str)==0:
 pkt = sniff(filter='icmp', prn=print_pkt)
else:
 pkt = sniff(iface=str,filter='icmp', prn=print_pkt)





'''

'''


#wrpcap("temp.cap",pkts)

#tcp and src host 10.9.0.5 and dst port 23 
#(port23:telnet)
#net 128.230.0.0/16


