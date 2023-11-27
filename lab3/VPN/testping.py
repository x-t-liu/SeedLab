# 导入scapy库
from scapy.all import *

# 定义一个处理ICMP包的函数
def handle_icmp(pkt):
    # 判断是否是ICMP包
    if ICMP in pkt:
        # 打印收到的ICMP包的信息
        print("收到ICMP包：{} -> {}".format(pkt[IP].src, pkt[IP].dst))
        # 构造一个ICMP回复包
        reply = IP(dst=pkt[IP].src, src=pkt[IP].dst)/ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)/pkt[Raw].load
        # 发送ICMP回复包
        send(reply)
        # 打印发送的ICMP回复包的信息
        print("发送ICMP回复包：{} -> {}".format(reply[IP].src, reply[IP].dst))

# 开始监听所有的ICMP包，并调用handle_icmp函数处理
sniff(filter="icmp", prn=handle_icmp)
