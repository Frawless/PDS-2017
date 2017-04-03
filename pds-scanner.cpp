/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   pds-scanner.c
 * Author: xstejs24
 *
 * Created on 15. února 2017, 23:35
 */

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <pcap.h>

#include "pds-library.h"

using namespace std;    // Or using std::string
typedef std::string NetError;

//pcap socket deskriptor
pcap_t* packetDesc;

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

/**
 * Funkce pro ukončení snifferu
 * @param signo
 **/
void terminate(int signo)
{
    struct pcap_stat stats;
    if (pcap_stats(packetDesc, &stats) >= 0)
    {
		cerr<<"Packets received: "<<stats.ps_recv<<endl;
		cerr<<"Packets droped: "<<stats.ps_drop<<endl;
    }
    //zavření spojení
    pcap_close(packetDesc);
	cerr<<"Signo number: "<<signo<<endl;
	cerr<<"Func: terminate exit(0)"<<endl;	
    exit(0);
}

/*
 * 
 */
int main(int argc, char** argv) {

	PARAMS params = {-2,-1,"",""};
	params = getParams(argc,argv,params);
	
	uint32_t maskp;          /* subnet mask               */
    uint32_t netp;           /* ip                        */
	char errbuf[PCAP_ERRBUF_SIZE];
	
	pcap_lookupnet("wlo1",&netp,&maskp,errbuf);
	
	in_addr ip_addr;
	ip_addr.s_addr = maskp;
	
	cerr<<inet_ntoa(ip_addr)<<endl;
	
//	printTest();
	printMAC(getMAC(params.interface));
	printIP(getIP(params.interface));
	
	if(params.ErrParam != ERR_OK){
		return (EXIT_FAILURE);
	}
	
	//filtr pro ARP a NDP
	char bpfstr[255] = "((udp) and ((dst port 520) or (dst port 521)))";	
	
	//návázání spojení s daným interface
	packetDesc = openInterface(params.interface, "arp");
	
	ARPSniffer(packetDesc, (pcap_handler)parsePacket);
	
	//ukončení aplikace
	signal(SIGINT, terminate);
	signal(SIGTERM, terminate);
	signal(SIGQUIT, terminate);
	
	return (EXIT_SUCCESS);
}

