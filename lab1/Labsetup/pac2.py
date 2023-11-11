#!/usr/bin/python3
from scapy.all import *

ip = IP()
ip.src = "10.0.2.11"
ip.dst = "128.230.0.1"
tcp = TCP()
tcp.dport = 23
send(ip/tcp)
ip.src = "128.230.0.1"
ip.dst = "10.0.2.11"
send(ip/tcp)

