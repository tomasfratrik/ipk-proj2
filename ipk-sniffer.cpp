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
#include <cstring>


#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#define DEFAULT_NUM_PACKETS 1
using namespace std;

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

void error_exit(string error){
    cerr << "ERROR: " << error << "!" <<  endl;
    exit(EXIT_FAILURE);
}

void usage() {
    cout << "Usage: ./ipk-sniffer [-i interface | --interface interface] {-p port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}" << endl;
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

        char errbuf[PCAP_ERRBUF_SIZE];
        if(pcap_findalldevs(&alldevs, errbuf) == -1) {
            error_exit("pcap_findalldevs");
        }

        printf("\n");
        for(device_list = alldevs; device_list != NULL; device_list = device_list->next){
            printf("%s\n",(*device_list).name);
        }
        printf("\n");
    }

    exit(EXIT_SUCCESS);
}

