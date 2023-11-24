from scapy.all import *
ip = IP(dst="10.9.0.53", src="10.9.0.5")
udp = UDP(dport=53, sport=60232, chksum=0)
Qdsec = DNSQR(qname="aaaaa.example.com")
dns = DNS(id=0xAAAA, qr=0, qdcount=1,qd=Qdsec)
request = ip/udp/dns
# Save the packet data to a file
with open('ip_req.bin', 'wb') as f:
    f.write(bytes(request))

