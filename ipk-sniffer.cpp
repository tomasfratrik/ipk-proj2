/**
 * @file ipk-sniffer.cpp
 * @author  Tomáš Frátrik (xfratr01)
 */

#include <iostream>
#include <time.h>
#include <getopt.h>
#include <string>
#include <time.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <cstring>
#include <cstdarg>
#include <csignal>

#define PROTO_TCP 6
#define PROTO_UDP 17
#define PROTO_ICMP 1
#define PROTO_IGMP 2
#define PROTO_ICMP6 58
#define BYTES_ROW 16

#define ICMPV6_MLD_QUERY 130
#define ICMPV6_MLD_REPORT 131
#define ICMPV6_MLD_DONE 132

#define ICMPV6_NDP_ROUTER 134
#define ICMPV6_NDP_NEIGHBOR 135
#define ICMPV6_NDP_NEIGHBOR2 135
#define ICMPV6_NDP_REDIRECT 137


#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#define DEFAULT_NUM_PACKETS 1

using namespace std;

char errbuf[PCAP_ERRBUF_SIZE];
pcap_t *handle;

// Structure for arguments
typedef struct {
    string interface;
    bool interface_flag = false;
    int port = -1;
    bool tcp_flag = false;
    bool udp_flag = false;
    bool arp_flag = false;
    bool icmp4_flag = false;
    bool icmp6_flag = false;
    bool igmp_flag = false;
    bool mld_flag = false;
    bool ndp_flag = false;
    int num_packets = DEFAULT_NUM_PACKETS;
} args_t;

// used by getopt_long
struct option long_options[] = {
    {"interface", required_argument, 0, 'i'},
    {"tcp", no_argument, 0, 't'},
    {"udp", no_argument, 0, 'u'},
    {"arp", no_argument, 0, 0},
    {"icmp4", no_argument, 0, 0},
    {"icmp6", no_argument, 0, 0},
    {"igmp", no_argument, 0, 0},
    {"mld", no_argument, 0, 0},
    {"ndp", no_argument, 0,0},
    {0, 0, 0, 0}
};

// exit on error, with dynamic number of strings
void error_exit(const char *format, ... ){
    va_list args;
    va_start(args, format);
    fprintf(stderr, "ERROR: ");
    vfprintf(stderr, format, args);
    fprintf(stderr, "!\n");
    va_end(args);
    std::exit(EXIT_FAILURE);
}
    
// print usage of program
void usage() {
    cout << "Usage: './ipk-sniffer [-i interface | --interface interface] {-p port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}'" << endl;
    cout << "Options:" << endl;
    cout << "\t-i, --interface interface: specify interface to sniff (default: print list of active interfaces)" << endl;
    cout << "\t-p port: filter by TCP/UDP port number" << endl;
    cout << "\t-t, --tcp: display TCP segments" << endl;
    cout << "\t-u, --udp: display UDP datagrams" << endl;
    cout << "\t--arp: display only ARP frames" << endl;
    cout << "\t--icmp4: display only ICMPv4 packets" << endl;
    cout << "\t--icmp6: display only ICMPv6 echo request/response" << endl;
    cout << "\t--igmp: display only IGMP packets" << endl;
    cout << "\t--mld: display only MLD packets" << endl;
    cout << "\t-n num: number of packets to display (default: 1)" << endl;
}

//help function for fetch_filter
//filter -> current filter string
//protocol -> protocol to add to filter
void add_filter(string *filter, string protocol){
    if((*filter).empty() == false) {
        *filter += " or ";
    }
    *filter += protocol;
}

// fetch filter string from arguments
string fetch_filter(args_t arg){
    string filter = "";
    if(arg.tcp_flag == true) {
        if(arg.port != -1) {
            filter += "(tcp and port " + to_string(arg.port) + ")";
        } else {
            filter += "tcp";
        }
    }
    if(arg.udp_flag == true) {
        if(filter.empty() == false) {
            filter += " or ";
        }
        if(arg.port != -1) {
            filter += "(udp and port " + to_string(arg.port) + ")";
        } else {
            filter += "udp";
        }
    }
    if(arg.arp_flag == true) {
        add_filter(&filter, "arp");
    }
    if(arg.icmp4_flag == true) {
        add_filter(&filter, "icmp");
    }
    if(arg.icmp6_flag == true) {
        add_filter(&filter, "icmp6");
    }
    if(arg.igmp_flag == true) {
        add_filter(&filter, "igmp");
    }
    if(arg.mld_flag == true) {
        // add_filter(&filter, "mld");
        if(filter.empty() == false){
            filter += " or ";
        }
        filter += "icmp6 and icmp6[0] == " + to_string(ICMPV6_MLD_QUERY);
        filter += " or icmp6 and icmp6[0] == " + to_string(ICMPV6_MLD_REPORT);
        filter += " or icmp6 and icmp6[0] == " + to_string(ICMPV6_MLD_DONE);
    }
    if(arg.ndp_flag == true){
        if(filter.empty() == false){
            filter += " or ";
        }
        filter += "icmp6 and icmp6[0] == " + to_string(ICMPV6_NDP_ROUTER);
        filter += " or icmp6 and icmp6[0] == " + to_string(ICMPV6_NDP_NEIGHBOR);
        filter += " or icmp6 and icmp6[0] == " + to_string(ICMPV6_NDP_NEIGHBOR2);
        filter += " or icmp6 and icmp6[0] == " + to_string(ICMPV6_NDP_REDIRECT);
    }
    return filter;
}

// print data in hex and ascii
//len -> length of data
void data_print(u_char *data, int len) {
    int i = 0;

    if (len == 0) {
        return;
    }

    printf("\n");
    for (; i < len - BYTES_ROW; i += BYTES_ROW) {
        printf("0x%04x ", i);

        // Print hex values
        printf(" ");
        for (int j = i; j < BYTES_ROW + i; j++) {
            printf("%02x ", data[j]);
        }

        // Print ASCII values
        printf(" ");
        for (int j = i; j < BYTES_ROW + i; j++) {
            if (isprint(data[j])) {
                printf("%c", data[j]);
            } else {
                printf(".");
            }
            if (j % 16 == 7) {
                printf(" ");
            }
        }

        printf("\n");
    }

    // Print last row

    printf("0x%04x ", i);

    // Print hex values
    printf(" ");
    for (int j = i; j < len; j++) {
        printf("%02x ", data[j]);
    }

    // Fill empty  with spaces
    int rest = BYTES_ROW - (len - i) % BYTES_ROW;
    if (rest == BYTES_ROW) rest = 0;
    for (int j = 0; j < rest; j++) {
        printf("   ");
    }

    // ASCII values
    printf(" ");
    for (int j = i; j < len; j++) {
        if (isprint(data[j])) {
            printf("%c", data[j]); //if printable 
        } else {
            printf(".");
        }
        if (j % 16 == 7) {
            printf(" ");
        }
    }

    printf("\n");
}

//close pcap handle on SIGINT
void sigint_handler(int signum) {
    std::cout << "Caught SIGINT, closing pcap handle..." << std::endl;
    pcap_close(handle);
    exit(signum);
}

//callback function for pcap_loop
//prints timestamp, source and destination MAC address, source and destination IP address, source and destination port, protocol and data
//source: https://www.tcpdump.org/pcap.html
//author: Tim Carstens &  Guy Harris
void packet_sniffer(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    signal(SIGINT, sigint_handler);
    
    char timestamp[30];
    struct tm *local_time;
    time_t raw_time = header->ts.tv_sec;

    local_time = localtime(&raw_time);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S%z", local_time); 
    printf("timestamp: %s%03ld\n", timestamp, header->ts.tv_usec / 1000);

    struct ether_header *eth_header;
    const struct tcphdr *tcp;
    const struct udphdr *udp;
    struct ip *ip;
    struct ip6_hdr *ip6;
    u_int size_ip;

    u_char *data;

    string ip_src;
    string ip_dst;

    //ethernet header
    eth_header = (struct ether_header *) packet;

    bool is_ipv4 = false;
    bool is_ipv6 = false;

    u_int8_t next_hdr;

    switch(ntohs(eth_header->ether_type)){
        case ETHERTYPE_IP: // IPv4
            is_ipv4 = true;

            ip = (struct ip*)(packet + sizeof(struct ether_header));
            size_ip = ip->ip_hl*4;

            char ip_src[INET_ADDRSTRLEN];
            char ip_dst[INET_ADDRSTRLEN];

            inet_ntop(AF_INET, &(ip->ip_src), ip_src, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip->ip_dst), ip_dst, INET_ADDRSTRLEN);

            printf("src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_header->ether_shost[0], eth_header->ether_shost[1], eth_header->ether_shost[2], eth_header->ether_shost[3], eth_header->ether_shost[4], eth_header->ether_shost[5]);
            printf("dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_header->ether_dhost[0], eth_header->ether_dhost[1], eth_header->ether_dhost[2], eth_header->ether_dhost[3], eth_header->ether_dhost[4], eth_header->ether_dhost[5]);
            printf("frame length: %d bytes\n", header->len);
            printf("src IP: %s\n", ip_src);
            printf("dst IP: %s\n", ip_dst);

            break;

        case ETHERTYPE_IPV6: // IPv6
            is_ipv6 = true;

            ip6 = (struct ip6_hdr*)(packet + sizeof(struct ether_header));

            char ip6_src[INET6_ADDRSTRLEN];
            char ip6_dst[INET6_ADDRSTRLEN];

            inet_ntop(AF_INET6, &(ip6->ip6_src), ip6_src, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(ip6->ip6_dst), ip6_dst, INET6_ADDRSTRLEN);
            printf("src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_header->ether_shost[0], eth_header->ether_shost[1], eth_header->ether_shost[2], eth_header->ether_shost[3], eth_header->ether_shost[4], eth_header->ether_shost[5]);
            printf("dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_header->ether_dhost[0], eth_header->ether_dhost[1], eth_header->ether_dhost[2], eth_header->ether_dhost[3], eth_header->ether_dhost[4], eth_header->ether_dhost[5]);
            printf("frame length: %d bytes\n", header->len);
            printf("src IP: %s\n", ip6_src);
            printf("dst IP: %s\n", ip6_dst);

            //protocol
            next_hdr = ip6->ip6_nxt;
            break;
        case ETHERTYPE_ARP:
            printf("src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_header->ether_shost[0], eth_header->ether_shost[1], eth_header->ether_shost[2], eth_header->ether_shost[3], eth_header->ether_shost[4], eth_header->ether_shost[5]);
            printf("dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_header->ether_dhost[0], eth_header->ether_dhost[1], eth_header->ether_dhost[2], eth_header->ether_dhost[3], eth_header->ether_dhost[4], eth_header->ether_dhost[5]);
            printf("frame length: %d bytes\n", header->len);
            data = (u_char *)packet;
            printf("\n");
            data_print(data, header->caplen);
            printf("\n");
            break;
    }

    if(is_ipv4 or is_ipv6){
        switch(is_ipv4 ? ip->ip_p : next_hdr){
            case PROTO_TCP:
                if(is_ipv4){
                    tcp = (struct tcphdr*)(packet + sizeof(struct ether_header) + size_ip);
                }
                else{ // IPv6
                    tcp = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
                }
                printf("src port: %d\n", ntohs(tcp->th_sport));
                printf("dst port: %d\n", ntohs(tcp->th_dport));
                data = (u_char *)packet;
                printf("\n");
                data_print(data, header->caplen);
                printf("\n");
                break;

            case PROTO_UDP:
                if(is_ipv4){
                    udp = (struct udphdr*)(packet + sizeof(struct ether_header) + size_ip);
                }
                else{
                    udp = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
                }
                printf("src port: %d\n", ntohs(udp->uh_sport));
                printf("dst port: %d\n", ntohs(udp->uh_dport));
                data = (u_char *)packet;
                printf("\n");
                data_print(data, header->caplen);
                printf("\n");
                break;
            case PROTO_ICMP:
                data = (u_char *)packet;
                printf("\n");
                data_print(data, header->caplen);
                printf("\n");
                break;
            case PROTO_ICMP6:
                data = (u_char *)packet;
                printf("\n");
                data_print(data, header->caplen);
                printf("\n");
                break;
            case PROTO_IGMP:
                data = (u_char *)packet;
                printf("\n");
                data_print(data, header->caplen);
                printf("\n");
                break;
        }
    }
}

int main(int argc, char *argv[]) {
    args_t args;
    bool any_flag = false;
    int option_index = 0;
    int c;

    //parse arguments
    while ((c = getopt_long(argc, argv, ":i:p:tun:", long_options, &option_index)) != -1) {
        switch (c) {
            case 'i':
                args.interface = optarg;
                args.interface_flag = true;
                break;
            case 'p':
                args.port = atoi(optarg);
                break;
            case 't':
                args.tcp_flag = true;
                any_flag = true;
                break;
            case 'u':
                args.udp_flag = true;
                any_flag = true;
                break;
            case 'n':
                args.num_packets = atoi(optarg);
                break;
            case 0:
                if (strcmp(long_options[option_index].name, "arp") == 0) {
                    args.arp_flag = true;
                    any_flag = true;
                } 
                else if (strcmp(long_options[option_index].name, "icmp4") == 0) {
                    args.icmp4_flag = true;
                    any_flag = true;
                } 
                else if (strcmp(long_options[option_index].name, "icmp6") == 0) {
                    args.icmp6_flag = true;
                    any_flag = true;
                } 
                else if (strcmp(long_options[option_index].name, "igmp") == 0) {
                    args.igmp_flag = true;
                    any_flag = true;
                } 
                else if (strcmp(long_options[option_index].name, "mld") == 0) {
                    args.mld_flag = true;
                    any_flag = true;
                }
                else if (strcmp(long_options[option_index].name, "ndp") == 0) {
                    args.ndp_flag = true;
                    any_flag = true;
                }
                break;
            default:
                if(optopt == 'i'){
                    args.interface_flag = true;
                }
                break;
        }
    }

    //if any flag is not set, set all flags
    if (any_flag == false) {
        args.tcp_flag = true;
        args.udp_flag = true;
        args.arp_flag = true;
        args.icmp4_flag = true;
        args.icmp6_flag = true;
        args.igmp_flag = true;
        args.mld_flag = true;
    }

    //if interface has no argument
    if(args.interface.empty() || args.interface_flag == false) {
        pcap_if_t *alldevs, *device_list;

        if(pcap_findalldevs(&alldevs, errbuf) == -1) {
            error_exit("pcap_findalldevs: %s", errbuf);
        }

        printf("\n");
        for(device_list = alldevs; device_list != NULL; device_list = device_list->next){
            printf("%s\n",(*device_list).name);
        }
        printf("\n");
        std::exit(EXIT_SUCCESS);
    }

    if(args.port < 0 || args.port > 65535) {
        usage();
        error_exit("Invalid port number");
    }
    if(args.num_packets < 0) {
        usage();
        error_exit("Invalid number of packets");
    }
    if(args.port != -1 && args.tcp_flag == false && args.udp_flag == false) {
        usage();
        error_exit("Port number is specified but neither TCP nor UDP is specified");
    }

    uint32_t netmask;
    uint32_t ipsrc;

    // get netmask and ip address of interface
    if(pcap_lookupnet(args.interface.c_str(), &ipsrc, &netmask, errbuf) == -1) {
        error_exit("pcap_lookupnet: %s", errbuf);
    }

    // open interface
    pcap_t *handle;
    if((handle = pcap_open_live(args.interface.c_str(), BUFSIZ, 1, 1000, errbuf)) == NULL) {
        error_exit("pcap_open_live: %s", errbuf);
    }
    // check handle
    if(pcap_datalink(handle) != DLT_EN10MB) {
        error_exit("Interface %s is not Ethernet", args.interface.c_str());
    }

    // set filter
    string filter = fetch_filter(args);
    struct bpf_program fp;	
    if(pcap_compile(handle, &fp, filter.c_str(), 0, ipsrc) == -1) {
        error_exit("pcap_compile");
    }
    if(pcap_setfilter(handle, &fp) == -1) {
        error_exit("pcap_setfilter");
    }

    // start sniffing
    struct pcap_pkthdr header;
    const u_char *packet;
    pcap_loop(handle, args.num_packets, packet_sniffer, NULL);

    // close handle
    pcap_close(handle);
    std::exit(EXIT_SUCCESS);
}