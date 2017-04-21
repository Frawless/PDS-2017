/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   types.h
 * Author: frawless
 *
 * Created on 20. dubna 2017, 14:25
 */

#ifndef TYPES_H
#define TYPES_H


	// Definice chybových stavů
#define ERR_VICMAC1 100
#define ERR_VICMAC2 101
#define ERR_VICIP1 102
#define ERR_VICIP2 103
#define ERR_TIME 104
#define ERR_PROT 105
#define ERR_COUNT 106
#define ERR_DEF 150
#define ERR_OK	0

#define TARGET_MAC 00
#define PTYPE 0x8000

#define MAXBYTES2CAPTURE 2048 
	
#define ETH_ADDR_LEN 6		// Velikost MAC adresy
#define IP_ADDR_LEN 4		// Velikost IPv4
#define ETH_HDRLEN 14		// Velikost Ethernetového paketu
#define ARP_HDR_LEN 28
#define IP6_HDRLEN 40		// IPv6 header velikost
#define ICMP_HDRLEN 8		// ICMP header velikost
#define ICMP_NA_LEN 4		// ICMP NA velikost
#define ICMP_NA_OPT_LEN 28	// ICMP link layer velikost
#define HOP_HDRLEN 2        // Hop-by-hop velikost
#define MAX_HBHOPTIONS 2    // Maximální počet HOP-BY-HOP hlaviček
#define MAX_HBHOPTLEN 256   // Maximální velikost HOP by HOP
#define MAX_ADDRESSES 255   // Maximální velikost adresy
#define MALFORMED_SIZE 30	// Velikost porušeného paketu

/* ARP Hlavička*/ 
#define ARP_REQUEST 1   // ARP Request
#define ARP_REPLY 2     // ARP Reply  
typedef struct arphdr_def { 
    u_int16_t htype;    // Hardware Type            
    u_int16_t ptype;    // Protocol Type            
    u_char hlen;        // Hardware Address Length (Délka MAC)
    u_char plen;        // Protocol Address Length  
    u_int16_t oper;     // Operation Code  (Request/Reply) 
    u_char sha[ETH_ADDR_LEN];      // Zdrojová MAC
    u_char spa[IP_ADDR_LEN];       // Zdrojová IP
    u_char tha[ETH_ADDR_LEN];      // Cílová MAC
    u_char tpa[IP_ADDR_LEN];       // Cílová IP
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


// HOP-BY-HOP struktura pro ICMPv6
typedef struct _hop_hdr hop_hdr;
struct _hop_hdr {
  uint8_t nxt_hdr;
  uint8_t hdr_len;
};

// Option hlavička pro advertisement
typedef struct icmpv6_opt{
	u_char flags[4];
	struct in6_addr ip6_src;      
	uint8_t type;
	uint8_t len;
	u_char mac[ETH_ADDR_LEN];      // Zdrojová MAC
} ICMPV6_OPT;

// Struktura pro strom na tvorbu XML
typedef struct T_NODE {
	u_char macAddr[ETH_ALEN];	// Klíč (MAC)  
	u_char ipv4[IP_ADDR_LEN];	// IPv4
	char ip6a[INET6_ADDRSTRLEN];
	char ip6b[INET6_ADDRSTRLEN];
	char ip6c[INET6_ADDRSTRLEN];
	struct T_NODE *leftChild;
	struct T_NODE *rightChild;
} *T_NODE_PTR;

// Struktura pro získání dvou obětí ze stromu
typedef struct T_VICTIMS {
	u_char victim1mac[ETH_ALEN];
	bool firstSet;
	u_char victim2mac[ETH_ALEN];
} T_VICTIMS;

#endif /* TYPES_H */

