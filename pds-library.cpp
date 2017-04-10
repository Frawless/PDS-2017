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


ofstream outputFile;


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


void openFile(char* file)
{
	outputFile.open(file,ios::out | ios::trunc);
}


/**
 * Funkce pro odchytávání ARP paketů
 * @param descriptor paket deskriptor
 **/ 
void ARPSniffer(pcap_t* descriptor, pcap_handler func)
{
	cerr<<"Odchytávání odpovědí..."<<endl;
	
	outputFile<<"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
	outputFile<<"<devices>\n";
	
	// Nastavení směru
//	pcap_setdirection(descriptor,PCAP_D_IN);
//	spcap_set_timeout(descriptor,10);
	
	//funkce pro chytání packetů - dokud není program ukončen
	if(pcap_dispatch(descriptor, -1, func, NULL) < 0)
	{
		cerr << "pcap_loop() failed: " << pcap_geterr(descriptor)<<endl;
		return;
	}
	
	outputFile<<"</devices>\n";
	outputFile.close();
	
	cerr<<"Func: capturePacket exit(succes)"<<endl;
	cerr<<"Celkem paketů: "<<h<<endl;
}

/**
 * 
 * @param intInfo
 * @param interface
 */
void getInterfaceInfo(INTERFACE_INFO* intInfo, char * interface)
{
	struct ifreq ifr;				// Struktura pro získání mac adresy
	int sd;							// Socket
	uint32_t senderIP, netmask;		// Proměnné pro masku a síť
	in_addr src_ip, src_netmask;	// Struktury pro masku a síť
	char errBuf[PCAP_ERRBUF_SIZE];
	
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
				tmpAddrPtr=&((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
//				char addressBuffer[INET6_ADDRSTRLEN];
//				inet_ntop(AF_INET6, tmpAddrPtr, addressBuffer, INET6_ADDRSTRLEN);
//				printf("%s IP Address %s\n", ifa->ifa_name, addressBuffer);
				if(ipCount == 0)
					inet_ntop(AF_INET6, tmpAddrPtr, intInfo->interfaceAddv6a, INET6_ADDRSTRLEN);
				else if (ipCOunt == 1)
					inet_ntop(AF_INET6, tmpAddrPtr, intInfo->interfaceAddv6b, INET6_ADDRSTRLEN);
				else
					inet_ntop(AF_INET6, tmpAddrPtr, intInfo->interfaceAddv6c, INET6_ADDRSTRLEN);
			} 			
		}
    }
    if (ifAddrStruct!=NULL) 
		freeifaddrs(ifAddrStruct);	
}

/**
 * 
 * @param intInfo
 * @param arpHdr
 * @param targetAddress
 * @param ptr
 * @param datalen
 * @param sizeofARP
 * @return 
 */
u_char* createARPv4(INTERFACE_INFO* intInfo,
				ARP_HEADER* arpHdr,
				char* tarAdd,
				u_char* ptr,
				ssize_t &datalen,
				size_t sizeofARP)
{
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
	
	memcpy(&arpHdr->tpa, tarAdd, ETH_ADDR_LEN * sizeof (u_char));
	
	
	return ptr + sizeofARP;	
}




/**
 * 
 * @param intInfo
 * @param datalen
 * @param packetPtr
 */
void sendARPv4(INTERFACE_INFO* intInfo, ssize_t datalen, u_char *packetPtr, pcap_t* descriptor)
{
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
	
	cerr<<"Test na hodnotu:";
	printIP(intInfo->interfaceAdd);
	
	// TODO - vyřešit to const char* aby tam byla pravá adresa sítě, pak vše pojede!
	inet_pton(AF_INET,createAddress(intInfo->interfaceAdd).c_str(),&src_address.sin_addr);
	
	inet_pton(AF_INET,createAddress(intInfo->networkAddress).c_str(),&dst_address.sin_addr);
	
	dst_ip = ntohl(dst_address.sin_addr.s_addr);
	

	cerr<<"Target: "<<createAddress(intInfo->interfaceAdd)<<endl;
//	printIP(intInfo->networkAddress);
//	cerr<<intInfo->interfaceAdd<<endl;
	
	
	// Vytvoření socketu.
	if ((sockfd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror ("Socket() chyba při získání socketu pro ioctl()!");
		exit(EXIT_FAILURE);
	}
	
	std::string target = "10.0.0.31";
	
//	inet_pton(AF_INET,(const char*)intInfo->,&src_address.sin_addr);
	
	pid_t pid = fork();
	
	if(pid < 0)
	{
		cerr<<"Fork() Error!"<<endl;
		exit(EXIT_FAILURE);
	}
	else if (pid == 0)
	{
		cerr<<"CHILD"<<endl;
		ARPSniffer(descriptor, (pcap_handler)parsePacket);
		exit(EXIT_SUCCESS);
	}
	else
	{
		usleep(1000000);
		cerr<<"PARRENT"<<endl;
		cerr<<intInfo->hosts<<endl;
		int i;
		for(i = 1; i <= intInfo->hosts; i++)
		{
			dst_ip = ntohl(dst_address.sin_addr.s_addr);

			inet_pton(AF_INET, my_ntoa(dst_ip+1),&dst_address.sin_addr);
			//bind socketu
			if(bind(sockfd, (struct sockaddr *)&src_address, sizeof(src_address)) < 0)
			{
				cerr <<"Bind() error"<< endl;
				exit(EXIT_FAILURE);
			}


	//		cerr<<"IP cíle: "<<inet_ntoa(dst_address.sin_addr)<<" -> Hodnota i: "<<i<<endl;

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
		cerr<<"Pakety odeslány."<<endl;
		usleep(60000000);
	}

	

//	cerr<<"Počet paketů: "<<x<<endl;
	
	
	close(sockfd);
}

/**
 * 
 * @param input
 * @return 
 */
std::string createAddress(u_char * input)
{
//	cerr<<"Createa adress IP: ";
	
	char tmp[3];
	std::string output;
	
	for(int i =0; i < 3; i++){
//		output += input[i];
		sprintf(&tmp[0], "%d", input[i]);
		output += tmp;
		output += ".";
	}
////	output  += input[3];
	sprintf(&tmp[0], "%d", input[3]);
	output += tmp;

//	cerr<<"Output: "<<output<<endl;
	
	return output;
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
 * 
 * @param 
 * @param 
 * @param packetptr
 */
void parsePacket(u_char *, struct pcap_pkthdr *, u_char *packetptr)
{
	int i=0; 
	char errbuf[PCAP_ERRBUF_SIZE];    /* Error buffer                           */ 
	struct pcap_pkthdr pkthdr;        /* Packet information (timestamp,size...) */ 
	ARP_HEADER *arpheader = NULL;       /* Pointer to the ARP header              */ 
	memset(errbuf,0,PCAP_ERRBUF_SIZE); 
	//cerr<<packetptr<<endl;
	h++;
	arpheader = (struct arphdr_def *)(packetptr+14); /* Point to the ARP header */ 
//	printf("Operation: %s\n", (ntohs(arpheader->oper) == ARP_REQUEST)? "ARP Request" : "ARP Reply");
	if(ntohs(arpheader->oper) == ARP_REPLY)
	{
		char tmp[4];
		// Výpis MAC
		outputFile<<"\t<host mac=\"";
		for(i=0; i<5;i++){
			sprintf(tmp,"%02X", arpheader->sha[i]);
			outputFile << tmp;
			if(i % 2 != 0)
				outputFile<<".";
		}
		sprintf(tmp,"%02X", arpheader->sha[5]);
		outputFile << tmp<<"\">\n";
		// Výpis IP adres
		outputFile<<"\t\t<ipv4>";
		for(i=0; i<3; i++){
			sprintf(tmp,"%d.", arpheader->spa[i]);
			outputFile << tmp;
			
		}
		sprintf(tmp,"%d", arpheader->spa[3]);
		outputFile << tmp <<"</ipv4>\n\t</host>\n";
		
		
		
//		cerr<<"Paket číslo: "<<h<<endl;
//		cerr<<"#############################################"<<endl;
//		printf("Received Packet Size: %d bytes\n", pkthdr.len); 
//		printf("Hardware type: %s\n", (ntohs(arpheader->htype) == 1) ? "Ethernet" : "Unknown"); 
//		printf("Protocol type: %s\n", (ntohs(arpheader->ptype) == 0x0800) ? "IPv4" : "Unknown"); 
//		printf("Operation: %s\n", (ntohs(arpheader->oper) == ARP_REQUEST)? "ARP Request" : "ARP Reply"); 
//
//	   /* If is Ethernet and IPv4, print packet contents */ 
//		if (ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800){ 
//		  printf("Sender MAC: "); 
//
//		  for(i=0; i<6;i++)
//			  printf("%02X:", arpheader->sha[i]); 
//
//		  printf("\nSender IP: "); 
//
//	//	  cerr<<inet_ntoa(arpheader->spa)<<endl;
//		  for(i=0; i<4;i++)
//			  printf("%d.", arpheader->spa[i]); 
//
//		  printf("\nTarget MAC: "); 
//
//		  for(i=0; i<6;i++)
//			  printf("%02X:", arpheader->tha[i]); 
//
//		  printf("\nTarget IP: "); 
//
//		  for(i=0; i<4; i++)
//			  printf("%d.", arpheader->tpa[i]); 
//
//		  printf("\n"); 
//
//		} 		
	}
	
}


void test(struct pcap_pkthdr *pkthdr,const u_char *packetptr)
{
	int i=0; 
	char errbuf[PCAP_ERRBUF_SIZE];    /* Error buffer                           */ 
	ARP_HEADER *arpheader = NULL;       /* Pointer to the ARP header              */ 
	memset(errbuf,0,PCAP_ERRBUF_SIZE); 
	cerr<<"Výpis paketu: ARP"<<endl;
	//cerr<<packetptr<<endl;
	
	u_char *ptr = (u_char *)packetptr;
	cerr<<"nasrat"<<endl;
	cerr<<ptr<<endl;
	arpheader = (struct arphdr_def *)(ptr+14); /* Point to the ARP header */ 

//	printf("\n\nReceived Packet Size: %d bytes\n", pkthdr.len); 
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


/* Convert the given ip address in native byte order to a printable string */
char *
my_ntoa(unsigned long ip) {
	struct in_addr addr;
	addr.s_addr = htonl(ip);
	return inet_ntoa(addr);
}

