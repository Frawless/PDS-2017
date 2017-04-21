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

#include "types.h"
#include "tree.h"

#ifndef PDS_HEADER_H
#define PDS_HEADER_H


/**
 * Funkce pro otevření požadovaného rozhraní
 * @param interface - jmeno interface
 * @param secondPar - filter pro odchytávání
 * @param timeout - timeout interfacu
 **/ 
pcap_t* openInterface(char* interface, const char* secondPar, int timeout);

/**
 * Funkce pro získání potřebných údajů o užívnaém rozhraní - IP adresy, MAC
 * @param intInfo - ukazatel na strukturu pro uložení dat
 * @param interface - název rozhranní
 */
void getInterfaceInfo(INTERFACE_INFO* intInfo, char * interface);

/**
 * Funkce pro otevření výstupního souboru.
 * @param file - název souboru
 */
void openFile(char* file);

/**
 * Funkce pro převod adresy z binární reprezentace na string.
 * @param input - vstupní adresa v u_char
 * @return  - adresa v podobě stringu
 */
std::string createAddress(u_char * input);

std::string macToString(u_char * input);

/**
 * Funkce pro vytvoření ARP paketu pro skenování,
 * @param intInfo - struktura s informacemi o rozhraní
 * @param arpHdr - ukazatel na místo v paměti pro ARP hlavičku
 * @param ptr - ukazatel na paketu
 * @param datalen - délka 
 * @return 
 */
u_char* createARP(INTERFACE_INFO* intInfo,
				ARP_HEADER* arpHdr,
				u_char* ptr,
				ssize_t &datalen);

/**
 * Funkce pro skenování sítě pomocí ARP a ICMPv6. Ve funkci je vytvořen nový proces aby bylo možné odchytávat pakety již během posílání.
 * @param intInfo - struktura s informacemi o rozhraní
 * @param descriptor - ukazatel na paket
 */
void scanNetwork(INTERFACE_INFO* intInfo, pcap_t* descriptor);

/**
 * Funkce pro vytvoření a zaslání všechn ptřebných ARP paketů do sítě. 
 * Ze získané adresy sítě a počtu hostů jsou zasílány pakety všem.
 * @param intInfo - struktura s informacemi o rozhraní
 */
void scanIPv4(INTERFACE_INFO* intInfo);

/**
 * Funkce pro zaslání ping paketů pro sken IPv6 zařízení.
 * Ne všechny zařízení na PING odpoví, proto je zavedena druhá verze paketu s vadným paketem.
 * V případě malform paketu je zaslán poškozený paket, na který odpoví zařízení pomocí ICMPv6.
 * @param intInfo - struktura s informacemi o rozhraní
 * @param malform - příznak, zda paket má být požkozen nebo ne
 */
void scanIPv6(INTERFACE_INFO* intInfo, bool malform);

/**
 * Funkce pro odchytávání ARP paketů pro sken.
 * @param descriptor - ukazatle na paketu
 * @param func - funkce pro zpracování paketů
 **/ 
void packetSniffer(pcap_t* descriptor, pcap_handler func);

/**
 * Funkce pro zpracování paketů.
 * @param 
 * @param 
 * @param packetptr - ukazatel na paket
 */
void parsePacket(u_char *, struct pcap_pkthdr *, u_char *packetptr);

/**
 * Funkce pro vypsání MAC adresy.
 * @param mac - MAC adresa
 */
void printMAC(u_char * mac);

/**
 * Funkce pro vypsání IPv4 adresy.
 * @param ip - IPv4 adresa
 */
void printIP(u_char * ip);

//#################################################################################################################################

/**
 * Funkce pro rozesílání otrávených ARP paketů.
 * @param intInfo - struktura s informacemi o interface
 * @param time - odesílací čas
 * @param mac1 - MAC adresa 1. oběti
 * @param mac2 - MAC adresa 2. oběti
 * @param ip1 - IP adresa 1. oběti
 * @param ip2 - IP adresa 2. oběti
 */
void poisonVictims(INTERFACE_INFO* intInfo, int time, char* mac1, char* mac2, char* ip1, char* ip2, bool arp);

/**
 * Funkce pro odeslání ARP packetů. Jako parametry jsou nastaveny adresy (MAC a IP), které jsou v ARP packetu vyplněny a odeslány.
 * @param srcMac - zdrojová MAC adresa (MAC stanice, která provádí útok)
 * @param srcIp - zdrojová IP (obě B/A)
 * @param dstMac - cílová MAC (obě A/B)
 * @param dstIp - cílová IP (oběť B/A)
 * @param socket - socket
 * @param device - interface pro odeslání
 */
void sendPacketARP(u_char* srcMac,
				char* srcIp,
				char* dstMac,
				char* dstIp,
				int socket,
				struct sockaddr_ll device);

/**
 * Funkce pro konverzi MAC adresy ve formátu char na u_char/uint8_t
 * @param outMac - ukazatel na místo v paměti pro výsledek
 * @param inMac - vstupní MAC adresa (char)
 * @return 
 */
u_char* createMacAdress(uint8_t* newDstMac, char* mac1);

/**
 * Funkce pro konverzi MAC adresy ve formátu char na u_char/uint8_t
 * @param outMac - ukazatel na místo v paměti pro výsledek
 * @param inMac - vstupní MAC adresa (char)
 * @return 
 */
u_char* createMacAdressFromXML(uint8_t* outMac, const xmlChar* inMac);


/**
 * Funkce pro odeslání NDP packetů. Jako parametry jsou nastaveny adresy (MAC a IP), které jsou v ARP packetu vyplněny a odeslány.
 * @param interfaceMac - zdrojová MAC adresa (MAC stanice, která provádí útok)
 * @param srcIp - zdrojová IP (obě B/A)
 * @param dstMac - cílová MAC (obě A/B)
 * @param dstIp - cílová IP (oběť B/A)
 * @param socket - socket
 * @param device - interface pro odeslání
 * @param PACKET_TYPE - typ packetu (NA/NS)
 */
void sendPacketNDP(u_char* interfaceMac,
				char* srcIp,
				char* dstMac,
				char* dstIp,
				int socket,
				struct sockaddr_ll device,
				int PACKET_TYPE);

//#################################################################################################################################
// Následující funkce jsou převzaty z veřejného zdroje - http://www.pdbuchan.com/rawsock/rawsock.html

/**
 * Funkce pro převod IP adresy z long na IPv4.
 * @param ip - vstupní počet bitů
 * @return - ip adresa
 */
char * myNtoa(unsigned long ip);

/**
 * Funkce pro výpočet checksumu u IPv6 paketů.
 * @param addr - adresa
 * @param len - délka
 * @return - spočítaný checksum
 */
uint16_t checksum (uint16_t *addr, int len);

/**
 * Funkce pro výpočet checksumu u paketu ICMPv6
 * @param iphdr - ip hlavička
 * @param icmp6hdr - icmp hlavička
 * @param payload 
 * @param payloadlen
 * @return - checksum
 */
uint16_t icmp6_checksum (struct ip6_hdr iphdr, struct icmp6_hdr icmp6hdr, uint8_t *payload, int payloadlen);

uint16_t icmp6_checksum2 (struct ip6_hdr iphdr, struct icmp6_hdr icmp6hdr, ICMPV6_OPT *payload, int payloadlen);

/**
 * Funkce pro alokování paměti pro u_char proměnné.
 * @param len - velikost proměnné
 * @return - ukazatel do paměti
 */
uint8_t * allocate_ustrmem (int len);

// ###############################################################################################################################

#endif /* PDS_HEADER_H */

