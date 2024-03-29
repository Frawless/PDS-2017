/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

// Zdroj - https://www.tutorialspoint.com/data_structures_algorithms/tree_data_structure.htm
// http://www.xmlsoft.org/examples/tree2.c
#include "tree.h"
#include <cstring>
using namespace std;

/**
 * Funkce pro inicializaci stromu.
 * @param root ukaaztel strom
 */
void treeInit(T_NODE_PTR* root)
{
	*root = NULL;
}

/**
 * Funkce pro vkládání nalezených IPv4 adres do stromu. Díky funkci stromu je eliminována možnost duplictních výskytů adres.
 * @param root - ukazatel nastrom
 * @param macAddr - vkládající MAC
 * @param ipv4 - vkládající IPv4
 */
void insert(T_NODE_PTR* root,u_char* macAddr, u_char* ipv4) {
	T_NODE_PTR tempNode = (T_NODE_PTR)malloc(sizeof(struct T_NODE));

	// Pokud uzel prázdný vkládám
	if(*root == NULL) {
		*root = tempNode;
		(*root)->leftChild = NULL;
		(*root)->rightChild = NULL;
		memcpy((*root)->macAddr,macAddr,ETH_ALEN*(sizeof(u_char)));
		memcpy((*root)->ipv4, ipv4,IP_ADDR_LEN*(sizeof(u_char)));
		memset((*root)->ip6a,'#',INET6_ADDRSTRLEN);
		memset((*root)->ip6b,'#',INET6_ADDRSTRLEN);
		memset((*root)->ip6c,'#',INET6_ADDRSTRLEN);
//		return;
	}
	else{
		// Porovnání hodnot v paměti
		int n = memcmp((*root)->macAddr, macAddr,ETH_ADDR_LEN);
		
		// Hodnoty se rovnají - aktualizace hodnoty ve stromu
		if(n == 0){
			memcpy((*root)->ipv4, ipv4,IP_ADDR_LEN*(sizeof(u_char)));
		}
		// Vkládám do levého stromu
		else if(n > 0) {
			insert((&(*root)->leftChild),macAddr,ipv4);
		}

		// Vkládám do pravého stromu
		else if (n < 0){
			insert((&(*root)->rightChild),macAddr,ipv4);
		}
   }
}

/**
 * Funkce pro vkládání nalezených IPv6 adres do stromu. Díky funkci stromu je eliminována možnost duplictních výskytů adres.
 * @param root - ukazatel nastrom
 * @param macAddr - vkládající MAC
 * @param ipv6 - vkládající IPv6
 */
void insert(T_NODE_PTR* root,u_char* macAddr, char* ipv6) {
	T_NODE_PTR tempNode = (T_NODE_PTR)malloc(sizeof(struct T_NODE));
   
	//if tree is empty, create root node
	if(*root == NULL) {
		*root = tempNode;
		(*root)->leftChild = NULL;
		(*root)->rightChild = NULL;		
		memset((*root)->ipv4,'#',IP_ADDR_LEN);
		memcpy((*root)->macAddr,macAddr,ETH_ALEN*(sizeof(u_char)));
		memcpy((*root)->ip6a, ipv6, INET6_ADDRSTRLEN*(sizeof(u_char)));;
		memset((*root)->ip6b,'#',INET6_ADDRSTRLEN);
		memset((*root)->ip6c,'#',INET6_ADDRSTRLEN);
	}
	else{
		// Porovnání hodnot v paměti
		int n = memcmp((*root)->macAddr, macAddr,ETH_ADDR_LEN);
		
		// Hodnoty se rovnají - aktualizace hodnoty ve stromu
		if(n == 0){
			// Možnost vložit více adres IPv6, následuje test prázdnosti a případné vložení
			if((*root)->ip6a[0] == '#'){
				memcpy((*root)->ip6a, ipv6, INET6_ADDRSTRLEN*(sizeof(u_char)));
				return;
			}
			else if((*root)->ip6b[0] == '#' && (memcmp((*root)->ip6a, ipv6,ETH_ADDR_LEN) != 0)){
				memcpy((*root)->ip6b, ipv6, INET6_ADDRSTRLEN*(sizeof(u_char)));
				return;
			}
			else if((*root)->ip6c[0] == '#' && (memcmp((*root)->ip6a, ipv6,ETH_ADDR_LEN) != 0) && (memcmp((*root)->ip6b, ipv6,ETH_ADDR_LEN) != 0)){
				memcpy((*root)->ip6c, ipv6, INET6_ADDRSTRLEN*(sizeof(u_char)));
				return;
			};
		}
		// Vkládám do levého stromu
		else if(n > 0) {
			insert((&(*root)->leftChild),macAddr,ipv6);
		}

		// Vkládám do pravého stromu
		else if (n < 0){
			insert((&(*root)->rightChild),macAddr,ipv6);
		}         
   }
}

/**
 * Funkce pro vypsání stromu do souboru v požadovaném XML formátu. Adresy jsu vypsány pouze pokud jsou uloženy ve stromu.
 * @param root - ukazatel nastrom
 * @param outputFile - výstupní soubor
 */
void printTree(T_NODE_PTR root, std::ofstream& outputFile)
{
	int i;
	if(root == NULL){
//		std::cerr<<"Nenalezeny žádné adresy!"<<std::endl;
		return;
	}
	else{
		char tmp[5];
		// Výpis MAC
		outputFile<<"\t<host mac=\"";
		for(i=0; i<5;i++){
			sprintf(tmp,"%02x", root->macAddr[i]);
			outputFile << tmp;

			if(i % 2 != 0)
				outputFile<<".";
		}
		sprintf(tmp,"%02x", root->macAddr[5]);
		outputFile << tmp<<"\">\n";
		// Výpis IPv4
		if(root->ipv4[0] != '#')
		{
			// Výpis IP adres
			outputFile<<"\t\t<ipv4>";
			for(i=0; i<3; i++){
				sprintf(tmp,"%d.", root->ipv4[i]);
				outputFile << tmp;

			}
			sprintf(tmp,"%d", root->ipv4[3]);
			outputFile << tmp <<"</ipv4>\n";	
		}
		// Výpisy uložených IPv6
		if(root->ip6a[0] != '#')
		{
			outputFile << "\t\t<ipv6>";
			outputFile << root->ip6a;
			outputFile << "</ipv6>\n";
		}
		if(root->ip6b[0] != '#')
		{
			outputFile << "\t\t<ipv6>";
			outputFile << root->ip6b;
			outputFile << "</ipv6>\n";
		}
		if(root->ip6c[0] != '#')
		{
			outputFile << "\t\t<ipv6>";
			outputFile << root->ip6c;
			outputFile << "</ipv6>\n";
		}		
		
		outputFile << "\t</host>\n";
		
		// Zpracování levého a pravého potomka
		printTree(root->leftChild, outputFile);
		printTree(root->rightChild, outputFile);
	}
}

/**
 * Funkce pro smazání stromu z paměti.
 * @param root - ukazatel na strom
 */
void dispose (T_NODE_PTR *root) {

    if(*root == NULL)    
        return ;
    else
    {
        if((*root)->leftChild != NULL) // Pokud mohu jít doleva
        {
            dispose(&(*root)->leftChild);
        }
        
        if((*root)->rightChild != NULL) // Pokud mohu jít doleva
        {
            dispose(&(*root)->rightChild);
        }
        if(((*root)->leftChild == NULL) && ((*root)->leftChild == NULL))
        {
            free(*root);
        }
        *root = NULL;
    }
    return ;
}

