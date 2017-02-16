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
#include "pds-header.h"
#include <iostream>
#include <fstream>
#include <sstream>

using namespace std;    // Or using std::string
typedef std::string NetError;

//pcap socket deskriptor
//pcap_t* packetDesc;

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

/**
 * Funkce ověří parametry z příkazové řádky
 * @param argc počet argumentů
 * @param argv pole argumentů
 * @param argInt struktura s názvem interface pro spuštění
 **/
PARAMS getParams (int argc, char *argv[], PARAMS params)
{
	int c;
	
    const char* const short_opts = "i:t:p:a:b:c:d:";
    const option long_opts[] = {
            {"victim1ip", 1, nullptr, 'a'},
            {"victim1mac", 0, nullptr, 'b'},
            {"victim2ip", 1, nullptr, 'c'},
            {"victim2mac", 1, nullptr, 'd'},
            {"help", 0, nullptr, 'h'},
            {nullptr, 0, nullptr, 0}
    };	

	//ověření správnosti a počtu argumentů
	//./pds-spoof -i interface -t sec -p protocol -victim1ip ipaddress -victim1mac macaddress -victim2ip ipaddress -victim2mac macaddress
	while((c = getopt_long(argc,argv,short_opts, long_opts, nullptr)) != -1 && argc == 15)
	{
		//parametr i + interface_name
		switch(c)
		{
			case 'i':
				strcpy(params.interface, optarg);
				params.ErrParam++;
				break;
			case 't':
				strcpy(params.time, optarg);
				params.ErrParam++;
				break;
			case 'p':
				strcpy(params.protocol, optarg);
				params.ErrParam++;
				break;
			case 'a':
				strcpy(params.victim1ip, optarg);
				//ověření, zda je zadaná IP syntakticky správně
				if(!inet_pton(AF_INET,tokenIP.c_str(), &ripResponse.IPaddress)){
					ripResponse.retCode = ErrIP_r;
					cerr<<"Bad \"victim1ip\" format"<<endl;
				}
				else
					params.ErrParam++;
				break;
			case 'b':
				strcpy(params.victim1mac, optarg);
				params.ErrParam++;
				break;	
			case 'c':
				strcpy(params.victim2ip, optarg);
				params.ErrParam++;
				break;	
			case 'd':
				strcpy(params.victim2mac, optarg);
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
	//cerr<<argInt.interface<<endl;
	
	// vrací se struktura se zpracovanými parametry
	return params;
}

/*
 * 
 */
int main(int argc, char** argv) {

	PARAMS params = {-7,-1,"",""};
	params = getParams(argc,argv,params);
	
	if(params.ErrParam != 0){
		return (EXIT_FAILURE);
	}
	
	return (EXIT_SUCCESS);
}


