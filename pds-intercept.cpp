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
    pcap_close(packetDesc);
	cerr<<"Signo number: "<<signo<<endl;
	cerr<<"Func: terminate exit(0)"<<endl;	
    exit(EXIT_SUCCESS);
}


void
parseStory (xmlDocPtr doc, xmlNodePtr cur) {

	xmlChar *key;
	cur = cur->xmlChildrenNode;
	while (cur != NULL) {
	   if ((!xmlStrcmp(cur->name, (const xmlChar *)"keyword"))) {
		    key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
		    printf("keyword: %s\n", key);
		    xmlFree(key);
 	   }
	cur = cur->next;
	}
    return;
}


/**
 * print_element_names:
 * @a_node: the initial xml node to consider.
 *
 * Prints the names of the all the xml elements
 * that are siblings or children of a given xml node.
 */

xmlChar* getGroup(xmlNode * a_node, string mac){
    xmlNode *cur_node = NULL;
	xmlChar *uriM, *uriG, *output = NULL;
	
    for (cur_node = a_node; cur_node; cur_node = cur_node->next) {
        if (cur_node->type == XML_ELEMENT_NODE) {
//            printf("node type: Element, name: %s Value: %s\n", cur_node->name,xmlNodeGetContent(cur_node));
//			printf("Element: %s\n",cur_node->name);
			if ((!xmlStrcmp(cur_node->name, (const xmlChar *)"host"))) {
				uriM = xmlGetProp(cur_node, (const xmlChar *)"mac");
				uriG = xmlGetProp(cur_node, (const xmlChar *)"group");
				if(uriG != NULL){
					if(!(xmlStrcmp((const xmlChar*)mac.c_str(), uriM))){
//						printf("GROUP_search: %s\n",uriG);
						return uriG;
					}					
				}			
			}
        }
		output = getGroup(cur_node->children, mac);
//		printf("output: %s\n",output);
		if(output != NULL)
			return output;
    }
	return NULL;
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
//		cerr<<"it "<<it->first<<" : "<<it->second<<endl;
		for(tmpIt=macMap.begin(); tmpIt!=macMap.end(); ++tmpIt){
//			cerr<<"tmp "<<tmpIt->first<<" : "<<tmpIt->second<<endl;
//			cerr<<"dvojice: "<<tmpIt->first<<"#"<<" : "<<it->second<<"#"<<endl;
//			cerr<<"dvojice"<<endl;
//			cerr<<it->first<<"#"<<endl;
//			cerr<<tmpIt->second<<"#"<<endl;
			if(strcmp(tmpIt->second,it->first) == 0){
				if(strcmp(tmpIt->first,it->second) != 0){
//					cerr<<"it "<<it->first<<" : "<<it->second<<endl;
//					cerr<<"tmp "<<tmpIt->first<<" : "<<tmpIt->second<<endl;	
					tmpMap[it->second] = tmpIt->first;
				}

			}
		}
	}

	macMap = tmpMap;
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


// Projdu strom, pokud narazím na někoho, kdo má group tak ho přidám a hledám druhého, výsledkem bude ten vector struktur nebo mapa, pak jen přeposílání

/*
 * 
 */
int main(int argc, char** argv) {

	PARAMS params = {-2,-1,"",""};
	params = getParams(argc,argv,params);
	
	if(params.ErrParam != 0){
		return (EXIT_FAILURE);
	}
	
	std::map<char*,char*> macMap;
	std::map<char*,char*>::iterator it;
	
	//návázání spojení s daným interface
//	packetDesc = openInterface(params.interface, "",0);	
	
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
	
    /*
     * Cleanup function for the XML library.
     */
    xmlCleanupParser();
    /*
     * this is to debug memory for regression tests
     */
    xmlMemoryDump();	
//	
	// Odchytávání packetů a jejich přeposílání
//	packetSniffer(packetDesc, (pcap_handler)reSendPacket);
	
	return (EXIT_SUCCESS);
}


