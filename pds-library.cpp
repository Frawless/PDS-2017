/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "pds-library.h"
#include <pcap.h>
#include <arpa/inet.h>

#include <iostream>
#include <fstream>
#include <sstream>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()

#include <netdb.h>            // struct addrinfo
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_RAW, INET_ADDRSTRLEN
#include <netinet/ip.h>       // IP_MAXPACKET (which is 65535)
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <net/if.h>           // struct ifreq
#include <linux/if_ether.h>   // ETH_P_ARP = 0x0806
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>

#include <errno.h>            // errno, perror()

#define ETH_ADDR_LEN 6
#define IP_ADDR_LEN 4

#define TARGET_MAC 00
#define PTYPE 0x8000


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

#define MAXBYTES2CAPTURE 2048 


using namespace std;

/**
 * Funkce pro otevření požadovaného interfacu
 * @param interface jmeno interface
 * @param secondPar
 **/ 
pcap_t* openInterface(char* interface, const char* secondPar)
{
	pcap_t* packetDesc;  					//packetDescriptor
  
    char errBuf[PCAP_ERRBUF_SIZE];
    
    uint32_t  srcip, netmask;
    struct bpf_program  bpf;


	//otevření zadaného interface
	/** 
	  * pcap_open_live - vestavěná funkce pro poslech na daném interface
	  * @param interface 
      * @param BUFSIZ  - maximální velikost packetu
      * @param promiskuitní mód (1 = true, 0 = false)
      * @param packet read timeout
	  * @param odložný prostor pro chybové zprávy
	  **/
	if((packetDesc = pcap_open_live(interface, BUFSIZ, 1, -1, errBuf)) == NULL)
	{
		cerr<<"Nepovedlo se připojit na interface ->"<<endl;
		cerr<< "pcap_open_live() failed: " << errBuf << endl;
		return NULL;
	}

	//získání Ip adresy a masky
	if(pcap_lookupnet(interface, &srcip, &netmask, errBuf) < 0)
	{
		cerr<<"Nenalezena IP..."<<endl;
		cerr<< "pcap_lookupnet failed: " << errBuf << endl;
		return NULL;
	}

	//konverze paketu
	if(pcap_compile(packetDesc, &bpf, (char*)secondPar, 0, netmask))
	{
		cerr<<"Nepovedlo se konvertovat paket"<<endl;
 		cerr<<"pcap_compile() failed: " <<pcap_geterr(packetDesc)<<endl;
		return NULL;
	} 

	//nastavení filtru
	if(pcap_setfilter(packetDesc, &bpf) < 0)
	{
		cerr<<"Nelze nastavit filter"<<endl;
		cerr<<"pcap_setfilter() failed: " <<pcap_geterr(packetDesc)<<endl;
		return NULL;
	}

	cerr<<"Func: openInterface exit(succes)"<<endl;
	return packetDesc;
}

/**
 * Funkce pro odchytávání ARP paketů
 * @param descriptor paket deskriptor
 **/ 
void ARPSniffer(pcap_t* descriptor, pcap_handler func)
{
	//funkce pro chytání packetů - dokud není program ukončen
	if(pcap_loop(descriptor, 0, func, NULL) < 0)
	{
		cerr << "pcap_loop() failed: " << pcap_geterr(descriptor)<<endl;
		return;
	}
	cerr<<"Func: capturePacket exit(succes)"<<endl;
}


/**
 * Funkce pro získání MAC adresy uživaného rozhranní.
 * @param interface - název rozhranní
 * @return src_mac - mac adresa
 */
u_char* getMAC(char* interface)
{
	struct ifreq ifr;
	int sd;
	uint8_t *src_mac = (uint8_t *) malloc (ETH_ADDR_LEN * sizeof (uint8_t));
	// Aloakce paměti
	memset (src_mac, 0, ETH_ADDR_LEN * sizeof (uint8_t));
	
	// Vytvoření socketu.
	if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror ("Socket() chyba při získání socketu pro ioctl()!");
		exit(EXIT_FAILURE);
	}
	// Získání MAC adresy.
	memset (&ifr, 0, sizeof (ifr));
	snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
	if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
		perror ("ioctl() chyba při získávání MAC adreasy! ");
		exit(EXIT_FAILURE);
	}
	close (sd);
	
	// Kopírování MAC adresy.
	memcpy (src_mac, ifr.ifr_hwaddr.sa_data, ETH_ADDR_LEN * sizeof (uint8_t));
	cerr<<"MAC adresa užívaného rozhranní:";
	for(int i = 0; i < 5; i++)
		fprintf (stderr,"%02x:", src_mac[i]);
	fprintf (stderr,"%02x\n", src_mac[5]);
	return (u_char*)src_mac;
}

u_char* getIP(char* interface)
{
//	u_char senderIP = (u_char *) malloc (IP_ADDR_LEN * sizeof (u_char));
//	u_char netmask = (u_char *) malloc (IP_ADDR_LEN * sizeof (u_char));
//	memset (senderIP, 0, IP_ADDR_LEN * sizeof (u_char));
//	memset (netmask, 0, IP_ADDR_LEN * sizeof (u_char));
	
	uint32_t senderIP, netmask;
	
//	senderIP = (u_char *) malloc (IP_ADDR_LEN * sizeof (u_char));
//	memset (senderIP, 0, IP_ADDR_LEN * sizeof (u_char));	
	
	in_addr src_ip, src_netmask;
	in_addr test;
	
	char errBuf[PCAP_ERRBUF_SIZE];
	
	// Získání zdrojové IP
	if(pcap_lookupnet(interface, &senderIP, &netmask, errBuf) < 0)
	{
		cerr<<"Nenalezena IP..."<<endl;
		cerr<< "pcap_lookupnet failed: " << errBuf << endl;
		return NULL;
	}
	
	src_ip.s_addr = senderIP;
	src_netmask.s_addr = netmask;
	
	cerr<<inet_ntoa(src_ip)<<endl;
	cerr<<inet_ntoa(src_netmask)<<endl;
	
	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	/* I want to get an IPv4 IP address */
	ifr.ifr_addr.sa_family = AF_INET;

	/* I want IP address attached to "eth0" */
	strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);

	ioctl(fd, SIOCGIFADDR, &ifr);

	close(fd);

	/* display result */
	printf("%s\n", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
	
//	
	char* localAddrString = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);

	u_char finalAddr[4];
	
	inet_pton(AF_INET,localAddrString,&finalAddr);
	
	printIP(finalAddr); // FUnguje, zkrášlit, možná spojit do jedné funkce s MAC a vracet strukturu asi? Info o rozhranní, asi bude nejjednodušší
	
//	printIP((u_char*)ratata);

	
	return (u_char*)senderIP;
}

/**
 * Funkce pro vypsání MAC adresy
 * @param mac
 */
void printMAC(u_char * mac)
{
	cerr<<"MAC adresa užívaného rozhranní:";
	for(int i = 0; i < 5; i++)
		fprintf (stderr,"%02x:", mac[i]);
	fprintf (stderr,"%02x\n", mac[5]);
}

/**
 * Funkce pro vypsání IP adresy
 * @param mac
 */
void printIP(u_char * ip)
{
	cerr<<"IP adresa užívaného rozhranní:";
	for(int i = 0; i < 3; i++)
		fprintf (stderr,"%d.", ip[i]);
	fprintf (stderr,"%d\n", ip[3]);
}

/**
 * Funkce vytvoří ARP paket.
 * @param ripHdr ukazatel na strukturu Authentication
 * @param ptr ukazatel na pcket
 * @param datalen hodnota zbývajícího místa v packetuů 
 **/
u_char * arHdrFill(ARP_HEADER* arpHeader,
				 u_char* ptr,
				 ssize_t &datalen,
				 size_t sizeofARP,
				char* interface)
{  	
	
	//vytvoření místa v pamětu a namapování packetu na strukturu
	memset(ptr,0, sizeofARP);
	arpHeader = (ARP_HEADER*)ptr;
	datalen += sizeofARP;
			
	arpHeader->htype = htons(1);
	arpHeader->ptype = PTYPE;
	arpHeader->oper = htons(ARP_REQUEST);
	
	
//	arpHeader->sha = senderMAC;
//	arpHeader->spa = inet_ntoa(ip_addr);
//	inet_ntop(AF_INET, &(ip_addr.s_addr), &arpHeader->spa, INET_ADDRSTRLEN);
//	arpHeader->tha = targetIP;
//	for(int i=0; i<IP_ADDR_LEN;i++)
//		arpHeader->tpa[i] = TARGET_MAC;
//	arpHeader->tpa = TARGET_MAC;
	
//	inet_pton(AF_INET, inet_ntoa(ip_addr.s_addr), &arpHeader->spa);
	
	
	return ptr + sizeofARP;
}

void parsePacket(u_char *, struct pcap_pkthdr *, u_char *packetptr)
{
	int i=0; 
	char errbuf[PCAP_ERRBUF_SIZE];    /* Error buffer                           */ 
	struct pcap_pkthdr pkthdr;        /* Packet information (timestamp,size...) */ 
	ARP_HEADER *arpheader = NULL;       /* Pointer to the ARP header              */ 
	memset(errbuf,0,PCAP_ERRBUF_SIZE); 
	cerr<<"Výpis paketu: ARP"<<endl;
	//cerr<<packetptr<<endl;
	
	arpheader = (struct arphdr_def *)(packetptr+14); /* Point to the ARP header */ 

	printf("\n\nReceived Packet Size: %d bytes\n", pkthdr.len); 
	printf("Hardware type: %s\n", (ntohs(arpheader->htype) == 1) ? "Ethernet" : "Unknown"); 
	printf("Protocol type: %s\n", (ntohs(arpheader->ptype) == 0x0800) ? "IPv4" : "Unknown"); 
	printf("Operation: %s\n", (ntohs(arpheader->oper) == ARP_REQUEST)? "ARP Request" : "ARP Reply"); 

   /* If is Ethernet and IPv4, print packet contents */ 
	if (ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800){ 
	  printf("Sender MAC: "); 

	  for(i=0; i<6;i++)
		  printf("%02X:", arpheader->sha[i]); 

	  printf("\nSender IP: "); 

//	  cerr<<inet_ntoa(arpheader->spa)<<endl;
	  for(i=0; i<4;i++)
		  printf("%d.", arpheader->spa[i]); 

	  printf("\nTarget MAC: "); 

	  for(i=0; i<6;i++)
		  printf("%02X:", arpheader->tha[i]); 

	  printf("\nTarget IP: "); 

	  for(i=0; i<4; i++)
		  printf("%d.", arpheader->tpa[i]); 

	  printf("\n"); 

	} 	
	
	
}


// Zatím netřeba
// Allocate memory for an array of unsigned chars.
uint8_t * allocate_ustrmem (int len)
{
  uint8_t *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (uint8_t));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
    exit (EXIT_FAILURE);
  }
}