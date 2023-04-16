/**
 * @file ipk-sniffer.cpp
 * @author  Tomáš Frátrik (xfratr01)
 */

#include <iostream>
#include <getopt.h>
#include <string>
#include <time.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <cstring>
#include <cstdarg>

#define PROTO_TCP 6
#define PROTO_UDP 17
#define PROTO_ICMP 1
#define PROTO_IGMP 2
#define PROTO_ICMP6 58

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#define DEFAULT_NUM_PACKETS 1

using namespace std;

char errbuf[PCAP_ERRBUF_SIZE];

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
    int num_packets = DEFAULT_NUM_PACKETS;
} args_t;

struct option long_options[] = {
    {"interface", required_argument, 0, 'i'},
    {"tcp", no_argument, 0, 't'},
    {"udp", no_argument, 0, 'u'},
    {"arp", no_argument, 0, 0},
    {"icmp4", no_argument, 0, 0},
    {"icmp6", no_argument, 0, 0},
    {"igmp", no_argument, 0, 0},
    {"mld", no_argument, 0, 0},
    {0, 0, 0, 0}
};

void error_exit(const char *format, ... ){
    va_list args;
    va_start(args, format);
    fprintf(stderr, "ERROR: ");
    vfprintf(stderr, format, args);
    fprintf(stderr, "!\n");
    va_end(args);
    exit(EXIT_FAILURE);
}
    

void usage() {
    cout << "Usage: './ipk-sniffer [-i interface | --interface interface] {-p port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}'" << endl;
}

void add_filter(string *filter, string protocol){
    if((*filter).empty() == false) {
        *filter += " or ";
    }
    *filter += protocol;
}

string fetch_filter(args_t arg){
    string filter = "";
    if(arg.tcp_flag == true) {
        if(arg.port != -1) {
            filter += "(tcp port " + to_string(arg.port) + ")";
        } else {
            filter += "tcp";
        }
    }
    if(arg.udp_flag == true) {
        if(filter.empty() == false) {
            filter += " or ";
        }
        if(arg.port != -1) {
            filter += "(udp port " + to_string(arg.port) + ")";
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
        add_filter(&filter, "mld");
    }
    return filter;
}

// void print_header(const struct pcap_pkthdr *header, struct ether_header *eth_header){
//     // printf("timestamp: %")
//     cout <<"timestamp: "<<header->ts<<endl;
// }
void packet_sniffer(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    (void) args;
    (void ) header;

    struct ether_header *eth_header;
    const struct tcphdr *tcp;
    const struct tcphdr *udp;
    struct ip *ip;
    u_int size_ip;
    u_int size_tcp;
    u_int size_udp;

    string ip_src;
    string ip_dst;

    eth_header = (struct ether_header *) packet;

    switch(ntohs(eth_header->ether_type)){
        case ETHERTYPE_IP:
            ip = (struct ip*)(packet + sizeof(struct ether_header));
            size_ip = ip->ip_hl*4;

            if(size_ip < 20){
                error_exit("Invalid IP header length: %u bytes", size_ip);
            }

            ip_src = inet_ntoa(ip->ip_src);
            ip_dst = inet_ntoa(ip->ip_dst);
            switch(ip->ip_p){
                case PROTO_TCP:

            }
            // cout<< "ip src:" << ip_src << endl;
            // cout<< "ip dst:" << ip_dst << endl;


    }
    /*
    cout <<"Packet length: " << header->len << endl;
    cout << "Captured length: " << header->caplen << endl;
    cout << "Timestamp: " << header->ts.tv_sec << "." << header->ts.tv_usec << endl;
    cout << "Ethernet header" << endl;
    struct ether_header *eth_header = (struct ether_header *) packet;
    cout << "Source MAC: " << ether_ntoa((struct ether_addr *) eth_header->ether_shost) << endl;
    cout << "Destination MAC: " << ether_ntoa((struct ether_addr *) eth_header->ether_dhost) << endl;
    cout << "Type: " << ntohs(eth_header->ether_type) << endl;
    print src mac
    */
    
}

int main(int argc, char *argv[]) {
    args_t args;
    bool any_flag = false;
    int option_index = 0;
    int c;
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
                } else if (strcmp(long_options[option_index].name, "icmp4") == 0) {
                    args.icmp4_flag = true;
                    any_flag = true;
                } else if (strcmp(long_options[option_index].name, "icmp6") == 0) {
                    args.icmp6_flag = true;
                    any_flag = true;
                } else if (strcmp(long_options[option_index].name, "igmp") == 0) {
                    args.igmp_flag = true;
                    any_flag = true;
                } else if (strcmp(long_options[option_index].name, "mld") == 0) {
                    args.mld_flag = true;
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

    if (any_flag == false) {
        args.tcp_flag = true;
        args.udp_flag = true;
        args.arp_flag = true;
        args.icmp4_flag = true;
        args.icmp6_flag = true;
        args.igmp_flag = true;
        args.mld_flag = true;
    }

    if(args.interface_flag == false) {
        usage();
        error_exit("No interface specified");
    }

    //if interface has no argument
    if(args.interface.empty()) {
        pcap_if_t *alldevs, *device_list;

        if(pcap_findalldevs(&alldevs, errbuf) == -1) {
            error_exit("pcap_findalldevs: %s", errbuf);
        }

        printf("\n");
        for(device_list = alldevs; device_list != NULL; device_list = device_list->next){
            printf("%s\n",(*device_list).name);
        }
        printf("\n");
        exit(EXIT_SUCCESS);
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

    string filter = fetch_filter(args);
    struct bpf_program fp;	
    if(pcap_compile(handle, &fp, filter.c_str(), 0, ipsrc) == -1) {
        error_exit("pcap_compile");
    }

    if(pcap_setfilter(handle, &fp) == -1) {
        error_exit("pcap_setfilter");
    }

    struct pcap_pkthdr header;
    const u_char *packet;
    pcap_loop(handle, args.num_packets, packet_sniffer, NULL);

    pcap_close(handle);
    exit(EXIT_SUCCESS);
}

