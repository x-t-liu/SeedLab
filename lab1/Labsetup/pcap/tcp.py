#!/usr/bin/env python3
from scapy.all import*

a=IP()
a.dst='10.9.0.6'
b=TCP()
c=a/b
c.dport=80
c.show()
input("press enter to send c for 10 times")
send(c,count=10)

c.dport=110
c.show()
input("press enter to send c for 10 times")
send(c,count=10)
