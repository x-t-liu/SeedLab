#!/usr/bin/python3
from scapy.all import *
import sys


def traceroute(target, minttl=1, maxttl=30, dport=80):
    print("target: %s(port=%s)" % (target, dport))
    ans, unans = sr(IP(dst=target, ttl=(minttl,maxttl),id=RandShort())/TCP(flags=0x2, dport=dport), timeout=10)
    for snd,rcv in ans:
        print(snd.ttl, rcv.src)

if __name__ == '__main__':
    if len(sys.argv) <= 1:
        traceroute("baidu.com")
    else:
        traceroute(sys.argv[1])

