/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

// Zdroj - https://www.tutorialspoint.com/data_structures_algorithms/tree_data_structure.htm

#include "tree.h"


void treeInit(T_NODE_PTR* root)
{
	*root = NULL;
}


void insert(T_NODE_PTR* root,u_char* macAddr, u_char* ipv4) {
	printf("Insert IPv4\n");
	T_NODE_PTR *tmp;
	T_NODE_PTR current;
	T_NODE_PTR parent;

	u_char *tmpMac = macAddr;

	T_NODE_PTR tempNode = (T_NODE_PTR)malloc(sizeof(struct T_NODE));
	*tmp = NULL;

	//if tree is empty, create root node
	if(*root == NULL) {
		printf("Vložena IPv4-root\n");
		*root = tempNode;
		(*root)->leftChild = NULL;
		(*root)->rightChild = NULL;
		memcpy((*root)->macAddr,macAddr,ETH_ALEN*(sizeof(u_char)));
		memcpy((*root)->ipv4, ipv4,IP_ADDR_LEN*(sizeof(u_char)));
//		return;
	}
	else if((tmp = search((&(*root)), tmpMac)) != NULL){
		if((*tmp) != NULL)
		{
			printf("Našel jsem\n");
//			printf("Test MAC:");
//			printMAC((*tmp)->macAddr);
//			printf("\n");
		}
		else
			printf("Nenašel jsem\n");

//		memcpy((*tmp)->ipv4, ipv4,IP_ADDR_LEN*(sizeof(u_char)));
		return;
	}
	else{
		//go to left of the tree
		if((*root)->leftChild == NULL) {
			insert((&(*root)->leftChild),macAddr,ipv4);
		}

		//go to right of the tree
		else {
			insert((&(*root)->rightChild),macAddr,ipv4);
		}
   }
}

void insert(T_NODE_PTR* root,u_char* macAddr, char* ipv6) {
	printf("Insert IPv6\n");
	T_NODE_PTR *tmp;
	T_NODE_PTR current;
	T_NODE_PTR parent;

	u_char *tmpMac = macAddr;
//	char *tmpIpv6 = ipv6;

	T_NODE_PTR tempNode = (T_NODE_PTR)malloc(sizeof(struct T_NODE));
   
	//if tree is empty, create root node
	if(*root == NULL) {
		printf("Vložena IPv6-root\n");
		*root = tempNode;
		(*root)->leftChild = NULL;
		(*root)->rightChild = NULL;		
		memcpy((*root)->macAddr,macAddr,ETH_ALEN*(sizeof(u_char)));
		if((*root)->ip6a == NULL)
			memcpy((*root)->ip6a, ipv6, INET6_ADDRSTRLEN*(sizeof(u_char)));
		else if((*root)->ip6b == NULL && (*root)->ip6a != ipv6)
			memcpy((*root)->ip6b, ipv6, INET6_ADDRSTRLEN*(sizeof(u_char)));
		else if((*root)->ip6a != ipv6 && (*root)->ip6b != ipv6)
			memcpy((*root)->ip6c, ipv6, INET6_ADDRSTRLEN*(sizeof(u_char)));
//		return;
	}
	else if((tmp = search((&(*root)), tmpMac)) != NULL){
//		if((*tmp)->ip6a == NULL)
//			memcpy((*tmp)->ip6a, ipv6, INET6_ADDRSTRLEN*(sizeof(u_char)));
//		else if((*tmp)->ip6b == NULL && (*tmp)->ip6a != ipv6)
//			memcpy((*tmp)->ip6b, ipv6, INET6_ADDRSTRLEN*(sizeof(u_char)));
//		else if((*tmp)->ip6a != ipv6 && (*tmp)->ip6b != ipv6)
//			memcpy((*tmp)->ip6c, ipv6, INET6_ADDRSTRLEN*(sizeof(u_char)));
		return;
	}
	else{
		//go to left of the tree
		if((*root)->leftChild == NULL) {
			insert((&(*root)->leftChild),macAddr,ipv6);
		}

		//go to right of the tree
		else {
			insert((&(*root)->rightChild),macAddr,ipv6);
		}           
   }
}

//na search to spadne někde asi
T_NODE_PTR* search(T_NODE_PTR *root, u_char* macAddr) {
//   struct T_NODE_PTR current = root;
   T_NODE_PTR *tmp;
//   T_NODE_PTR *current = (*root);
   printf("Visiting elements of MAC: ");
   printMAC(macAddr);
   printf("\n");
   
   u_char *tmpMac = macAddr;
//   memcpy(tmpMac, macAddr, IP_ADDR_LEN * (sizeof(u_char)));

	if((*root) != NULL)
	{
		if((*root)->macAddr != NULL){
			if((*root)->macAddr != macAddr)
			{
				 if((tmp = search((&(*root)->leftChild), tmpMac)) != NULL)
					 return (&(*tmp));
				 else
					 return search((&(*root)->rightChild), tmpMac);	   
			}

		}
		else
			return (&(*root));	   
	}
 
}


void printTree(T_NODE_PTR root, std::ofstream& outputFile)
{
	int i;
	if(root == NULL){
		std::cerr<<"Nenalezeny žádné adresy!"<<std::endl;
		return;
	}
	else{
//		char *tmpMac = (char*)malloc(16*sizeof(char));
//		char *tmpip = (char*)malloc(IP_ADDR_LEN*sizeof(char));
//		char tmpMac[16];
		char tmpMac[4];
		// Výpis MAC
		outputFile<<"\t<host mac=\"";
		for(i=0; i<5;i++){
			sprintf(tmpMac,"%02X", root->macAddr[i]);
			outputFile << tmpMac;

			if(i % 2 != 0)
				outputFile<<".";
		}
		sprintf(tmpMac,"%02X", root->macAddr[5]);
		outputFile << tmpMac<<"\">\n";
		// IPv4
		if(root->ipv4 != NULL)
		{
			// Výpis IP adres
			outputFile<<"\t\t<ipv4>";
			for(i=0; i<3; i++){
				sprintf(tmpMac,"%d.", root->ipv4[i]);
				outputFile << tmpMac;

			}
			sprintf(tmpMac,"%d", root->ipv4[3]);
			outputFile << tmpMac <<"</ipv4>\n";	
		}
		if(root->ip6a != NULL)
		{
			outputFile << "\t\t<ipv6>";
			outputFile << root->ip6a;
			outputFile << "</ipv6>\n";
		}
		if(root->ip6b != NULL)
		{
			outputFile << "\t\t<ipv6>";
			outputFile << root->ip6a;
			outputFile << "</ipv6>\n";
		}
		if(root->ip6c != NULL)
		{
			outputFile << "\t\t<ipv6>";
			outputFile << root->ip6a;
			outputFile << "</ipv6>\n";
		}		
		
		outputFile << "\t</host>\n";
		
		printTree(root->leftChild, outputFile);
		printTree(root->rightChild, outputFile);
	}
	
//	free(root);
	
}


void dispose (T_NODE_PTR *root) {
/*   ----------
** Zruší celý binární vyhledávací strom a korektně uvolní paměť.
**
** Po zrušení se bude BVS nacházet ve stejném stavu, jako se nacházel po
** inicializaci. Tuto funkci implementujte rekurzivně bez deklarování pomocné
** funkce.
**/

    if(*root == NULL)    
        return ;
    else
    {
        if((*root)->leftChild != NULL) //pokud mohu jit doleva
        {
            dispose(&(*root)->leftChild);
        }
        
        if((*root)->rightChild != NULL) //pokud mohu jit doleva
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