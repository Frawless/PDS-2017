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
	
	INTERFACE_INFO* intInfo = (INTERFACE_INFO*)calloc(18, sizeof(INTERFACE_INFO));			// Struktura pro potřebné adresy
	// Získání informací o rozhraní pro scan
	getInterfaceInfo(intInfo,params.interface);
	
	printMAC(intInfo->interfaceMac);
	printIP(intInfo->interfaceAdd);
	printIP(intInfo->networkAddress);
	printIP(intInfo->networkMask);
	cerr<<"Počet hostů: "<<intInfo->hosts<<endl;

	// Vyhodnocení chybového stavu
	if(params.ErrParam != ERR_OK){
		return (EXIT_FAILURE);
	}
	
	//filtr pro ARP a ICMPv6 (scan)
	//návázání spojení s daným interface
	packetDesc = openInterface(params.interface, "(arp) or (icmp6)");
	// Otevřený výstupního souboru
	openFile(params.fileName);

	
	//ukončení aplikace
	signal(SIGINT, terminate);
	signal(SIGTERM, terminate);
	signal(SIGQUIT, terminate);
	
	// Skenování sítě
	scanNetwork(intInfo, packetDesc);
	
	free(intInfo);
	
	return (EXIT_SUCCESS);
}

