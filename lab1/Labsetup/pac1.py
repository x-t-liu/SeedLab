#!/usr/bin/python3
from scapy.all import *

ip = IP()
ip.src = "10.9.0.6"
ip.dst = "10.9.0.5"
tcp = TCP()
tcp.dport = 23
send(ip/tcp)

