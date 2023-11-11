from scapy.all import *
print()
str=input("input dstIP(defalt:120.232.145.144 baidu.com)")
if len(str)==0:
 str='baidu.com'

a=IP()
a.dst=str
a.ttl=[(1,80)]
pkt=a/ICMP()
ans,uans=sr(pkt)
ans.summary()


