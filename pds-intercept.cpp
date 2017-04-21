/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   pds-intercept.c
 * Author: xstejs24
 *
 * Created on 15. února 2017, 23:36
 */

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <map>

#include "pds-library.h"
#include "tree.h"

#include <net/if.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */

using namespace std;    // Or using std::string
typedef std::string NetError;

//pcap socket deskriptor
pcap_t* packetDesc;
int sockfd;

struct cmp_str
{
   bool operator()(char const *a, char const *b) const
   {
      return strcmp(a, b) < 0;
   }
};


std::map<char*,char*> macMap;

//struktura pro jméno interface
typedef struct{
	int ErrParam;
	int optindNumber;
	char interface[255];
	char fileName[255];
} PARAMS;

/**
 * Funkce ověří parametry z příkazové řádky
 * @param argc počet argumentů
 * @param argv pole argumentů
 * @param argInt struktura s názvem interface pro spuštění
 **/
PARAMS getParams (int argc, char *argv[], PARAMS params)
{
	int c;
	//ověření správnosti a počtu argumentů
	//FUNKČNÍ POUZE PRO JEDEN INTERFACE (-i vLan1 vLan0  nejde!!!)
	while((c = getopt(argc,argv, "i:f:")) != -1 && argc == 5)
	{
		//parametr i + interface_name
		switch(c)
		{
			case 'i':
				strcpy(params.interface, optarg);
				params.ErrParam++;
				break;
			case 'f':
				strcpy(params.fileName, optarg);
				params.ErrParam++;
				break;
			default:
				params.ErrParam = -1;
				cerr<<"getParams() - Bad Argument Format!\nUsage: pds-scanner -i interface -f output_file"<<endl;
				break;
		}
	}

	params.optindNumber = optind;
	
	if(params.ErrParam != 0)
		cerr<<"getParams() - Bad Argument Format!\nUsage: pds-scanner -i interface -f output_file"<<endl;

	//kontrolní výpis pro jméno interface
	//cerr<<params.interface<<endl;
	
	// vrací se struktura se zpracovanými parametry
	return params;
}

/*
 * Funkce pro ověření číselnosti parametrů.
 * @param argument argument
 */
int parseNumber (char *argument)
{
    char *ptr;
    long arg = strtol(argument, &ptr,10);                   
    if (*ptr != '\0')
		return -1;
    return (int)arg;
}

/*
 * Funkce pro vypsání chybové hlášky pro jednotlivé chyby.
 * @param error Číslo chyby
 */
void printError(int error)
{
	switch(error)
	{
		case ERR_VICMAC1:
			cerr<<"parseParams(): [--victim1mac] Nesprávný formát MAC adresy"<<endl;
			break;
		case ERR_VICMAC2:
			cerr<<"parseParams(): [--victim2mac] Nesprávný formát MAC adresy"<<endl;
			break;
		case ERR_VICIP1:
			cerr<<"parseParams(): [--victim1ip] Nesprávný formát IP adresy (IPv4/IPv6)"<<endl;
			break;
		case ERR_VICIP2:
			cerr<<"parseParams(): [--victim2ip] Nesprávný formát IP adresy (IPv4/IPv6)"<<endl;
			break;
		case ERR_TIME:
			cerr<<"parseParams(): [-t] Nesprávný formát čísla"<<endl;
			break;
		case ERR_PROT:
			cerr<<"parseParams(): [-p] Pouze arp/ndp"<<endl;
			break;
		case ERR_DEF:
			cerr<<"parseParams(): Jiná chyba"<<endl;
			break;
		case ERR_COUNT:
			cerr<<"parseParams(): Nesprávný počet argumentů"<<endl;
		default:
			//return true;
			break;
	}
	// Vypsání použití a ukončení programu
	cerr<<"Použití: pds-spoof -i interface -t sec -p protocol --victim1ip ipaddress --victim1mac macaddress --victim2ip ipaddress --victim2mac macaddress"<<endl;
	exit(EXIT_FAILURE);
}


/**
 * Funkce pro ukončení snifferu
 * @param signo
 **/
void terminate(int signo)
{
    //zavření spojení
	close(sockfd);
    pcap_close(packetDesc); 
	macMap.clear();
	/*
     * Cleanup function for the XML library.
     */
    xmlCleanupParser();
    /*
     * this is to debug memory for regression tests
     */
    xmlMemoryDump();	
	cerr<<"Signo number: "<<signo<<endl;
	cerr<<"Func: terminate exit(0)"<<endl;	
    exit(EXIT_SUCCESS);
}


static void
createMap(xmlNode * a_node, std::map<char*,char*> &macMap)
{
    xmlNode *cur_node = NULL;
	std::map<char*,char*>::iterator it;
	xmlChar *uriM, *uriG;
    for (cur_node = a_node; cur_node; cur_node = cur_node->next) {
        if (cur_node->type == XML_ELEMENT_NODE) {
//            printf("node type: Element, name: %s Value: %s\n", cur_node->name,xmlNodeGetContent(cur_node));
			if ((!xmlStrcmp(cur_node->name, (const xmlChar *)"host"))) {
				uriM = xmlGetProp(cur_node, (const xmlChar *)"mac");
				uriG = xmlGetProp(cur_node, (const xmlChar *)"group");
				if(uriG != NULL){
					it = macMap.find((char*)uriM);
					if (it == macMap.end()){
						macMap[(char*)uriM] = (char*)uriG;
						macMap[(char*)uriG] = (char*)uriM;
					}
				}					
			}
        }
		createMap(cur_node->children,macMap);
    }
}


void parseMap(std::map<char*,char*> &macMap){
	std::map<char*,char*>::iterator tmpIt, it;
	std::map<char*,char*> tmpMap;
	
	for (it=macMap.begin(); it!=macMap.end(); ++it){
		for(tmpIt=macMap.begin(); tmpIt!=macMap.end(); ++tmpIt){
			if(strcmp(tmpIt->second,it->first) == 0){
				if(strcmp(tmpIt->first,it->second) != 0){
					tmpMap[it->second] = tmpIt->first;
				}

			}
		}
	}
	macMap = tmpMap;
	tmpMap.clear();
}

/**
 * exampleFunc:
 * @filename: a filename or an URL
 *
 * Parse and validate the resource and free the resulting tree
 */
static void
parseTree(const char *filename, std::map<char*,char*> &macMap) {
    xmlParserCtxtPtr ctxt; /* the parser context */
    xmlDocPtr doc; /* the resulting document tree */
	xmlNode *root_element = NULL;

    /* create a parser context */
    ctxt = xmlNewParserCtxt();
    if (ctxt == NULL) {
        fprintf(stderr, "Failed to allocate parser context\n");
	return;
    }
    /* parse the file, activating the DTD validation option */
    doc = xmlCtxtReadFile(ctxt, filename, NULL, 0);
    /* check if parsing suceeded */
    if (doc == NULL) {
        fprintf(stderr, "Failed to parse %s\n", filename);
    } else {
	/* check if validation suceeded */
        if (ctxt->valid == 0)
	    fprintf(stderr, "Failed to validate %s\n", filename);
		
		/*Get the root element node */
		root_element = xmlDocGetRootElement(doc);
		
		createMap(root_element, macMap);
		parseMap(macMap);
		
		/* free up the resulting document */
		xmlFreeDoc(doc);
    }
    /* free up the parser context */
    xmlFreeParserCtxt(ctxt);
}


void resendPackets(std::map<char*,char*> macMap,INTERFACE_INFO* intInfo)
{
	int status, bytes;
	uint8_t *ether_frame;
	u_char tmpMac[ETH_ADDR_LEN];
	std::map<char*,char*>::iterator it;

	struct sockaddr_ll device;
		
	memset (&device, 0, sizeof (device));
	if ((device.sll_ifindex = if_nametoindex (intInfo->interface)) == 0) {
		perror ("if_nametoindex() failed to obtain interface index ");
		exit (EXIT_FAILURE);
	}
	
	device.sll_family = AF_PACKET;
	memcpy (device.sll_addr, intInfo->interfaceMac, 6 * sizeof (uint8_t));
	device.sll_halen = 6;	
	
	// Submit request for a raw socket descriptor.
	if ((sockfd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
		perror ("socket() failed ");
		exit (EXIT_FAILURE);
	}
	
	// Allocate memory for various arrays.
	ether_frame = allocate_ustrmem (IP_MAXPACKET);
	while(1)
	{
		if ((status = recv (sockfd, ether_frame, IP_MAXPACKET, 0)) < 0) {
//			if (errno == EINTR) {
//				memset (ether_frame, 0, IP_MAXPACKET * sizeof (uint8_t));
//				continue;  // Something weird happened, but let's try again.
//			} else {
			perror ("recv() failed:");
			exit (EXIT_FAILURE);
//			}	
		}
		
//		cerr<<"Odchyceno: "<<status<<endl;
		
		memcpy (tmpMac, ether_frame + ETH_ADDR_LEN, ETH_ADDR_LEN * sizeof (uint8_t));
		
		cerr<<"Odchycen packet od: ";
		printMAC(tmpMac);
		cerr<<endl;
//		cerr<<"Velikost: "<<status<<endl;
//		
		cerr<<"Hledám: "<<(char*)macToString(tmpMac).c_str()<<endl;
		
		cerr<<"Výpis mapy po:"<<endl;
		for (std::map<char*,char*>::iterator it=macMap.begin(); it!=macMap.end(); ++it){
			cerr<<"Key: "<<it->first<<" Value: "<<it->second<<endl;
			cerr<<"test: "<<(char*)macToString(tmpMac).c_str()<<endl;
			if(strcmp(it->first,(char*)macToString(tmpMac).c_str()) == 0){
				createMacAdressFromXML(tmpMac,(const xmlChar*)it->second);
				cerr<<"Přeposílám na: ";
				printMAC(tmpMac);
				cerr<<endl;
				memcpy (ether_frame, tmpMac, ETH_ADDR_LEN * sizeof (uint8_t));
		//		memcpy (ethFrame + ETH_ADDR_LEN, srcMac, ETH_ADDR_LEN * sizeof (uint8_t));
	
				// Send ethernet frame to socket.
				if ((bytes = sendto (sockfd, ether_frame, status, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
					perror ("sendto() failed");
					exit (EXIT_FAILURE);
				}
				break;
			}
			
		}			
	}
}

/*
 * 
 */
int main(int argc, char** argv) {

	PARAMS params = {-2,-1,"",""};
	params = getParams(argc,argv,params);
	
	if(params.ErrParam != 0){
		return (EXIT_FAILURE);
	}
	
	INTERFACE_INFO* intInfo = (INTERFACE_INFO*)calloc(18, sizeof(INTERFACE_INFO));			// Struktura pro potřebné adresy
	// Získání informací o rozhraní pro scan
	getInterfaceInfo(intInfo,params.interface);	
	
	
	std::map<char*,char*>::iterator it;
	
	//návázání spojení s daným interface
	packetDesc = openInterface(params.interface, "",0);	
	
	//ukončení aplikace
	signal(SIGINT, terminate);
	signal(SIGTERM, terminate);
	signal(SIGQUIT, terminate);	
	
    /*
     * this initialize the library and check potential ABI mismatches
     * between the version it was compiled for and the actual shared
     * library used.
     */
//    LIBXML_TEST_VERSION

    parseTree(params.fileName,macMap);

	
	
	cerr<<"Výpis mapy po:"<<endl;
	for (std::map<char*,char*>::iterator it=macMap.begin(); it!=macMap.end(); ++it){
		cerr<<"Key: "<<it->first<<" Value: "<<it->second<<endl;
	}	
	
	resendPackets(macMap, intInfo);
	
	

//	
	// Odchytávání packetů a jejich přeposílání
//	packetSniffer(packetDesc, (pcap_handler)reSendPacket);
	
	return (EXIT_SUCCESS);
}


