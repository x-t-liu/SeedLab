from scapy.all import *

a=IP()
a.dst='10.9.0.6'
b=TCP()
a.port=[(90,110)]
send(a/b)
