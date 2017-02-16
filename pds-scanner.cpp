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
	//cerr<<argInt.interface<<endl;
	
	// vrací se struktura se zpracovanými parametry
	return params;
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
	
	return (EXIT_SUCCESS);
}

