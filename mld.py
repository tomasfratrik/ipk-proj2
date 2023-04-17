from scapy.all import *

# Define source and destination IPv6 addresses
src = "2001:db8::1"
dst = "ff02::16"

# Build MLD packet
pkt = IPv6(src=src, dst=dst)/ICMPv6MLQuery()

# Send packet
send(pkt)
