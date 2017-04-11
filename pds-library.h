/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   pds-header.h
 * Author: frawless
 *
 * Created on 16. února 2017, 0:17
 */

//inkludované knihovny
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <getopt.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netdb.h> 
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include <netinet/ip6.h>
#include <netinet/if_ether.h>
#include <pcap.h>
#include <netinet/icmp6.h>
	
#include <string>

#ifndef PDS_HEADER_H
#define PDS_HEADER_H

#ifdef __cplusplus
extern "C" {
#endif

#define ERR_VICMAC1 100
#define ERR_VICMAC2 101
#define ERR_VICIP1 102
#define ERR_VICIP2 103
#define ERR_TIME 104
#define ERR_PROT 105
#define ERR_COUNT 106
#define ERR_DEF 150
#define ERR_OK	0
	
#define ETH_ADDR_LEN 6
#define IP_ADDR_LEN 4

#define TARGET_MAC 00
#define PTYPE 0x8000

#define MAXBYTES2CAPTURE 2048 

/* ARP Hlavička, (assuming Ethernet+IPv4)            */ 
#define ARP_REQUEST 1   /* ARP Request             */ 
#define ARP_REPLY 2     /* ARP Reply               */ 
typedef struct arphdr_def { 
    u_int16_t htype;    /* Hardware Type           */ 
    u_int16_t ptype;    /* Protocol Type           */ 
    u_char hlen;        /* Hardware Address Length */ 
    u_char plen;        /* Protocol Address Length */ 
    u_int16_t oper;     /* Operation Code          */ 
    u_char sha[ETH_ADDR_LEN];      /* Sender hardware address */ 
    u_char spa[IP_ADDR_LEN];      /* Sender IP address       */ 
    u_char tha[ETH_ADDR_LEN];      /* Target hardware address */ 
    u_char tpa[IP_ADDR_LEN];      /* Target IP address       */ 
}ARP_HEADER; 
	
// Funkce pro získání informací interface
typedef struct interface_info{
	u_char networkAddress[IP_ADDR_LEN];
	u_char networkMask[IP_ADDR_LEN];
	u_char interfaceAdd[IP_ADDR_LEN];
	u_char interfaceMac[ETH_ADDR_LEN];
	char interfaceAddv6a[INET6_ADDRSTRLEN];
	char interfaceAddv6b[INET6_ADDRSTRLEN];
	char interfaceAddv6c[INET6_ADDRSTRLEN];
	int hosts;
	char interface[255];
} INTERFACE_INFO;


// Define a struct for hop-by-hop header, excluding options.
typedef struct _hop_hdr hop_hdr;
struct _hop_hdr {
  uint8_t nxt_hdr;
  uint8_t hdr_len;
};

#define ETH_HDRLEN 14  // Velikost Ethernetového paketu
#define IP6_HDRLEN 40  // IPv6 header velikost
#define ICMP_HDRLEN 8  // ICMP header velikost


// Define some constants.
#define HOP_HDRLEN 2          // Hop-by-hop header length, excluding options
#define MAX_HBHOPTIONS 2     // Maximum number of extension header options
#define MAX_HBHOPTLEN 256     // Maximum length of a hop-by-hop option (some large value)
#define MAX_ADDRESSES 255     // Maximum number of (full) addresses that can be used in type 3 routing header


/**
 * Funkce pro otevření požadovaného interfacu
 * @param interface jmeno interface
 * @param secondPar
 **/ 
pcap_t* openInterface(char* interface, const char* secondPar);


void openFile(char* file);

/**
 * Funkce pro odchytávání ARP paketů
 * @param descriptor paket deskriptor
 **/ 
void ARPSniffer(pcap_t* descriptor, pcap_handler func);

/**
 * Funkce pro ukončení snifferu
 * @param signo
 **/
//void terminate(int signo);

/**
 * 
 * @param 
 * @param 
 * @param packetptr
 */
void parsePacket(u_char *, struct pcap_pkthdr *, u_char *packetptr);

/**
 * 
 * @param interface
 * @return 
 */
void getInterfaceInfo(INTERFACE_INFO* intInfo, char * interface);

/**
 * 
 * @param ip
 * @return 
 */
char * my_ntoa(unsigned long ip);
uint16_t checksum (uint16_t *addr, int len);
uint16_t icmp6_checksum (struct ip6_hdr iphdr, struct icmp6_hdr icmp6hdr, uint8_t *payload, int payloadlen);
/**
 * 
 * @param intInfo
 * @param arpHdr
 * @param tarAdd
 * @param ptr
 * @param datalen
 * @param sizeofARP
 * @return 
 */
u_char* createARP(INTERFACE_INFO* intInfo,
				ARP_HEADER* arpHdr,
				u_char* ptr,
				ssize_t &datalen);

/**
 * 
 * @param intInfo
 * @param datalen
 * @param packetPtr
 */
void scanNetwork(INTERFACE_INFO* intInfo, ARP_HEADER* arpHdr, struct icmp6_hdr* icmphdr, struct ip6_hdr* iphdr, ssize_t datalen, u_char *packetPtr, pcap_t* descriptor);

void scanIPv4(INTERFACE_INFO* intInfo);
void scanIPv6(INTERFACE_INFO* intInfo, bool malform);

void fillIPv6hdr(INTERFACE_INFO* intInfo,struct ip6_hdr send_iphdr, int datalen);

char *
allocate_strmem (int len);
uint8_t *
allocate_ustrmem (int len);
uint8_t **
allocate_ustrmemp (int len);
int *
allocate_intmem (int len);

void test(struct pcap_pkthdr *pkthdr,const u_char *packetptr);


std::string createAddress(u_char * input);

/**
 * 
 * @param mac
 */
void printMAC(u_char * mac);

/**
 * 
 * @param ip
 */
void printIP(u_char * ip);

#ifdef __cplusplus
}
#endif

#endif /* PDS_HEADER_H */

