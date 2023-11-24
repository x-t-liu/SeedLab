#!/usr/bin/env python3

import fcntl
import struct
import os
import time
from scapy.all import *

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000

# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'xtLiu%d', IFF_TUN | IFF_NO_PI)
ifname_bytes  = fcntl.ioctl(tun, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Interface Name: {}".format(ifname))
os.system("ip addr add 192.168.53.99/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))


while True:
# Get a packet from the tun interface
 packet = os.read(tun, 2048)
 if packet:
  ip = IP(packet)
  print(ip.summary())
  # Check if the packet is an ICMP echo request packet
  if ICMP in ip and ip[ICMP].type == 8: # 8 is the type code for echo request
   # Construct a corresponding echo reply packet
   reply = ip.copy() # Copy the original packet
   reply[IP].src, reply[IP].dst = ip[IP].dst, ip[IP].src # Swap the source and destination IP addresses
   reply[ICMP].type = 0 # 0 is the type code for echo reply
   reply[ICMP].chksum = None 
   reply[IP].chksum = None 
   # Write the echo reply packet to the TUN interface
   
   os.write(tun, bytes(reply)) 
   #os.write(tun, bytes("hello world!!!!!",encoding='utf-8'))
   
   #print("Sent an echo reply packet("+ip[IP].dst+"->"+ip[IP].src+")")
  
  
