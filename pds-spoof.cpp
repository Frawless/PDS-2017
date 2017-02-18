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

#include "pds-library.h"

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
       else if (*mac == ':' || *mac == '-') {
			if (i == 0 || i / 2 - 1 != s)
				break;
          ++s;
       }
       else {
           s = -1;
       }
       ++mac;
    }
    return (i == 12 && (s == 5 || s == 0));
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
    const char* const short_opts = "i:t:p:a:b:c:d:";
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
	while((c = getopt_long(argc,argv,short_opts, long_opts, &option_index)) != -1)
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
				if(!inet_pton(AF_INET,tokenIP.c_str(), &params.victim1ip) && !inet_pton(AF_INET6, tokenIP.c_str(), &params.victim1ip))
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
				if(!inet_pton(AF_INET,tokenIP.c_str(), &params.victim1ip) && !inet_pton(AF_INET6, tokenIP.c_str(), &params.victim1ip))
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

/*
 * 
 */
int main(int argc, char** argv) {

	PARAMS params = {ERR_OK,-1,0,"","","","","",""};
	params = getParams(argc,argv,params);
	
	if(params.ErrParam != 0){
		return (EXIT_FAILURE);
	}
	
	return (EXIT_SUCCESS);
}

