from scapy.all import *

'''try
def print_pkt(pkt):
 pkt.show()


str=input("br-... :")
pkt = sniff(iface=str,filter='icmp', prn=print_pkt)
'''

str=input("input dstIP(defalt:28.0.0.133 baidu.com)")
a=IP()
str.rstrip('\n')
if len(str)==0:
 str='28.0.0.133'
 
print('dstIP:'+str)





a.dst=str
b=ICMP()

for num in range(1,5):
 a.ttl=num
 send(a/b)
 

