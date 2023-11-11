#!/usr/bin/env python3
from scapy.all import *
print("victim:hostA 10.9.0.5")
strip=input("input your spoofing IP:(default:10.9.0.6 host B)")
if len(strip)==0: 
 strip='10.9.0.6'

a=IP(src=strip)
a.dst='10.9.0.5'
b=ICMP()
c=a/b
c.summary()

for num in range(1,6):
 send(c)

