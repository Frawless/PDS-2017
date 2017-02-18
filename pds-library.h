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

#ifndef PDS_HEADER_H
#define PDS_HEADER_H

#ifdef __cplusplus
extern "C" {
#endif

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
#include <arpa/inet.h>
#include <netdb.h> 
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include <netinet/ip6.h>
#include <netinet/if_ether.h>
#include <pcap.h>
	
#define ERR_VICMAC1 100
#define ERR_VICMAC2 101
#define ERR_VICIP1 102
#define ERR_VICIP2 103
#define ERR_TIME 104
#define ERR_PROT 105
#define ERR_COUNT 106
#define ERR_DEF 150
#define ERR_OK	0
	
/**
 * Funkce pro otevření požadovaného interfacu
 * @param interface jmeno interface
 * @param secondPar
 **/ 
pcap_t* openInterface(char* interface, const char* secondPar);

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

void parsePacket(u_char *, struct pcap_pkthdr *, u_char *packetptr);

#ifdef __cplusplus
}
#endif

#endif /* PDS_HEADER_H */

