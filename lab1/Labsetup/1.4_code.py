#!/usr/bin/env python3
from scapy.all import*
def spoofing(pkt):
 if pkt[ICMP].type==8:
  dst=pkt[IP].dst
  src=pkt[IP].src
  ihll=pkt[IP].ihl
  
  idd=pkt[ICMP].id
  seqq=pkt[ICMP].seq
  load=pkt[Raw].load

  a=IP(src=dst,dst=src,ihl=ihll)
  b=ICMP(type="echo-reply",id=idd,seq=seqq)
  c=load
  ans=(a/b/c)
  send(ans)

pkt=sniff(filter="icmp",prn=spoofing)
