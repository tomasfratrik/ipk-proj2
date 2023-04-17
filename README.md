# **Project 2 - ZETA: Network sniffer**

## **Usage**
`Usage: './ipk-sniffer [-i interface | --interface interface] {-p port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}'`
List of iterfaces can be found by running `ipk-sniffer -i` or `ipk-sniffer --interfaces` or 
just `ipk-sniffer`, then you will just choose interface from the list and
run it.(for example: `./ipk-sniffer -i eth0 -p 80 --tcp`)

# **Options:**

# **Code description**
The ipk-sniffer program is used to capture and display network traffic on a specified network interface.Firstly the ipk-sniffer parses arguments (`getopt_long`) and checks all errors that can occur. If none arguments are passed then all are activated. If we ran program without argumets or with specific `-i`, then all available interfaces will be displayed from which we can choose. For next section pcap library is needed. Firstly we use `pcap_lookupnet()` to retrieve the IP address and netmask of the network interface specified by the user. Then we use `pcap_open_live()` to open the specified interface for capturing packets. `pcap_datalink()`  checks that the data link type of the interface is Ethernet. Then we set a filter for the captured packets based on user-specified criteria using `pcap_compile()` and `pcap_setfilter()`. String which we want to filter is being made manualy in funcion `fetch_filter()`.`MLD` and `NDP` are node discovery protocols based on ICMPv6. Thats why there are filtered using `icmpv6`. `TCP` and `UDP` are only protocols using port, if another protocol uses port it will be ignored. After that we can start capturing packets using `pcap_loop()`, with a user-specified maximum number of packets to capture and a callback function (`packet_sniffer()`) to handle each packet. In the callback we set a signal handler for the SIGINT signal and we set the timestamp and print him. Then we check ethernet header and decide it's type, whether it is `IPv4`, `IPv6`, or `ARP`. This is achived by determining `EtherType`. EtherType is a two-octet field in an Ethernet frame. It is used to indicate which protocol is encapsulated in the payload of the frame and is used at the receiving end by the data link layer to determine how the payload is processed. There we set `ip` or `ip6` to point to the `IPv4` or `IPv6` header and we calculate it's size. It uses inet_ntop() to convert the source and destination IP addresses to strings and stores them in ip_src and ip_dst. It prints the source and destination MAC addresses, the frame length, and the source and destination IP addresses to the console. If the packet is an IPv6 packet, it sets bool is_ipv6 to `true` and same for IPv6. Protocol for `IPv4` can be faund in `ip->ip_p` and for `IPv6` we use `ip6->ip6_nxt`. By this and by before set bool we can properly find protocol and display it's packet in `hex` and `ascii` format. In program `ICMP`, `ICMPv6`, `IGMP` are repetetive for optional enhancing of program for future.

## **Tests**
- for testing, I used 'wireshark' and 'tcpreplay'.
- `tcpreplay` allowed me to send packets to the interface and then I could see the output of the program. (but I didn't find NDP and MLD packets so those are not tested)
### **Test 1 - tcp IPv4**
#### **wireshark**
<img src="./tests/tcp_w.png" width=50% height=50%>
- hexdump of packet:
0000   92 75 fe d1 8e 3b 00 00 01 06 00 00 08 00 45 00   .u...;........E.
0010   00 3c 9a 9a 40 00 ff 06 cb 1c 0a 01 01 01 0a 01   .<..@...........
0020   01 02 a2 a2 00 b3 af 3b 93 8f 00 00 00 00 a0 02   .......;........
0030   72 10 c9 41 00 00 02 04 05 b4 04 02 08 0a 07 72   r..A...........r
0040   09 15 00 00 00 00 01 03 03 09                     ..........

#### **ipk-sniffer**
<img src="./tests/tcp_local.png" width=50% height=50%>
- hexdump of packet:
0x0000  92 75 fe d1 8e 3b 00 00 01 06 00 00 08 00 45 00  .u...;.. ......E.
0x0010  00 3c 9a 9a 40 00 ff 06 cb 1c 0a 01 01 01 0a 01  .<..@... ........
0x0020  01 02 a2 a2 00 b3 af 3b 93 8f 00 00 00 00 a0 02  .......; ........
0x0030  72 10 c9 41 00 00 02 04 05 b4 04 02 08 0a 07 72  r..A.... .......r
0x0040  09 15 00 00 00 00 01 03 03 09                    ........ ..


## **References**